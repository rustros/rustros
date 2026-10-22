//! virtio-blk driver: synchronous, one request at a time.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::now_ms;
use crate::pci::PciDev;
use crate::virtio::{D_NEXT, D_WRITE, Queue, Virtio};

const F_SIZE_MAX: u64 = 1 << 1;
const F_SEG_MAX: u64 = 1 << 2;
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
/// The most one request carries (less if the device says so).
const MAX_REQUEST: usize = 64 * 1024;

pub struct VirtioBlk {
    _dev: Virtio,
    q: Queue,
    pub sectors: u64,
    pub read_only: bool,
    /// the most bytes one request may carry (the device's size_max)
    max_len: usize,
    /// the device has a write cache: writes are followed by a flush
    flush: bool,
    /// errors reported so far (only the first few are printed)
    errors: u32,
    /// page-aligned bounce buffer of `max_len` bytes: every transfer goes
    /// through it (hardware devices may want aligned buffers)
    bounce: *mut u8,
    /// A request timed out; the device may still DMA into old buffers, so
    /// never touch it again.
    dead: bool,
    /// Request header and status byte live here (not on the stack) so a late
    /// DMA from a timed-out request cannot corrupt anything.
    req: Box<Req>,
}

#[repr(C)]
struct Req {
    hdr: ReqHdr,
    status: u8,
}

pub fn is_blk(d: &PciDev) -> bool {
    d.vendor == 0x1AF4 && (d.device == 0x1001 || d.device == 0x1042)
}

#[repr(C)]
struct ReqHdr {
    ty: u32,
    _reserved: u32,
    sector: u64,
}

impl VirtioBlk {
    pub fn new(pci: &PciDev) -> Option<VirtioBlk> {
        let mut dev = Virtio::probe(pci)?;
        let feat = dev.begin(F_RO | F_SIZE_MAX | F_SEG_MAX | F_FLUSH)?;
        let q = dev.queue(0, 16)?;
        let sectors = dev.config32(0) as u64 | (dev.config32(4) as u64) << 32;
        // one data descriptor per request: it must fit the device's segment size
        let size_max = if feat & F_SIZE_MAX != 0 { dev.config32(8) as usize } else { 0 };
        let max_len = if size_max >= 512 { (size_max.min(MAX_REQUEST)) & !511 } else { MAX_REQUEST };
        let flush = feat & F_FLUSH != 0;
        // Safety: a non-zero size and a valid alignment.
        let bounce = unsafe { alloc::alloc::alloc_zeroed(core::alloc::Layout::from_size_align(max_len, 4096).ok()?) };
        if bounce.is_null() {
            return None;
        }
        dev.finish();
        crate::kprintln!(
            "disk: virtio-blk {} MiB{}, requests up to {} KiB{}",
            sectors / 2048,
            if feat & F_RO != 0 { " read-only" } else { "" },
            max_len / 1024,
            if flush { ", write cache flushed" } else { "" }
        );
        Some(VirtioBlk {
            _dev: dev,
            q,
            sectors,
            read_only: feat & F_RO != 0,
            max_len,
            flush,
            errors: 0,
            bounce,
            dead: false,
            req: Box::new(Req { hdr: ReqHdr { ty: 0, _reserved: 0, sector: 0 }, status: 0 }),
        })
    }

    /// A read or write in requests the device takes, then (writes) a flush.
    fn io(&mut self, sector: u64, buf: *mut u8, len: usize, write: bool) -> bool {
        if self.dead || len == 0 || len % 512 != 0 || sector + (len / 512) as u64 > self.sectors || (write && self.read_only) {
            return false;
        }
        let mut done = 0;
        while done < len {
            let n = (len - done).min(self.max_len);
            let ty = if write { T_OUT } else { T_IN };
            // Safety: `buf` has `len` bytes, the bounce buffer `max_len` >= n.
            unsafe {
                if write {
                    core::ptr::copy_nonoverlapping(buf.add(done), self.bounce, n);
                }
                if !self.request(ty, sector + (done / 512) as u64, self.bounce, n) {
                    return false;
                }
                if !write {
                    core::ptr::copy_nonoverlapping(self.bounce, buf.add(done), n);
                }
            }
            done += n;
        }
        !(write && self.flush) || self.request(T_FLUSH, 0, core::ptr::null_mut(), 0)
    }

    /// One request (`len` 0: no data, a flush).
    fn request(&mut self, ty: u32, sector: u64, buf: *mut u8, len: usize) -> bool {
        self.req.hdr = ReqHdr { ty, _reserved: 0, sector };
        self.req.status = 0xFF;
        let hdr = &raw const self.req.hdr as u64;
        let status = &raw mut self.req.status;
        // All memory is identity-mapped, so the device can DMA straight
        // from/to these addresses.
        if len == 0 {
            self.q.set_desc(0, hdr, 16, D_NEXT, 2);
        } else {
            self.q.set_desc(0, hdr, 16, D_NEXT, 1);
            self.q.set_desc(1, buf as u64, len as u32, D_NEXT | if ty == T_IN { D_WRITE } else { 0 }, 2);
        }
        self.q.set_desc(2, status as u64, 1, D_WRITE, 0);
        self.q.push(0);
        self.q.notify();
        let start = now_ms();
        loop {
            if self.q.pop().is_some() {
                break;
            }
            if now_ms() - start > 5000 {
                crate::kprintln!("disk: request {} at sector {} ({} bytes) timed out, disk given up", ty, sector, len);
                self.dead = true;
                return false;
            }
            core::hint::spin_loop();
        }
        let st = unsafe { core::ptr::read_volatile(status) };
        if st != 0 {
            self.errors += 1;
            if self.errors <= 5 {
                crate::kprintln!("disk: request {} at sector {} ({} bytes) failed: status {}", ty, sector, len, st);
            }
        }
        st == 0
    }

}

/// A request is in flight (the watchdog must not write the disk then).
static BUSY: AtomicBool = AtomicBool::new(false);

pub fn busy() -> bool {
    BUSY.load(Ordering::Relaxed)
}

impl devices::BlockDevice for VirtioBlk {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        BUSY.store(true, Ordering::Relaxed);
        let ok = self.io(sector, buf.as_mut_ptr(), buf.len(), false);
        BUSY.store(false, Ordering::Relaxed);
        ok
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> bool {
        BUSY.store(true, Ordering::Relaxed);
        let ok = self.io(sector, buf.as_ptr() as *mut u8, buf.len(), true);
        BUSY.store(false, Ordering::Relaxed);
        ok
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
}
