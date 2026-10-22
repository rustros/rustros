//! virtio-blk driver: synchronous, one request at a time.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::now_ms;
use crate::pci::PciDev;
use crate::virtio::{D_NEXT, D_WRITE, Queue, Virtio};

const F_RO: u64 = 1 << 5;

pub struct VirtioBlk {
    _dev: Virtio,
    q: Queue,
    pub sectors: u64,
    pub read_only: bool,
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
        let feat = dev.begin(F_RO)?;
        let q = dev.queue(0, 16)?;
        let sectors = dev.config32(0) as u64 | (dev.config32(4) as u64) << 32;
        dev.finish();
        Some(VirtioBlk { _dev: dev, q, sectors, read_only: feat & F_RO != 0, dead: false, req: Box::new(Req { hdr: ReqHdr { ty: 0, _reserved: 0, sector: 0 }, status: 0 }) })
    }

    fn rw(&mut self, sector: u64, buf: *mut u8, len: usize, write: bool) -> bool {
        if self.dead || len == 0 || len % 512 != 0 || sector + (len / 512) as u64 > self.sectors || (write && self.read_only) {
            return false;
        }
        self.req.hdr = ReqHdr { ty: write as u32, _reserved: 0, sector };
        self.req.status = 0xFF;
        let hdr = &raw const self.req.hdr as u64;
        let status = &raw mut self.req.status;
        // All memory is identity-mapped, so the device can DMA straight
        // from/to these addresses.
        self.q.set_desc(0, hdr, 16, D_NEXT, 1);
        self.q.set_desc(1, buf as u64, len as u32, D_NEXT | if write { 0 } else { D_WRITE }, 2);
        self.q.set_desc(2, status as u64, 1, D_WRITE, 0);
        self.q.push(0);
        self.q.notify();
        let start = now_ms();
        loop {
            if self.q.pop().is_some() {
                break;
            }
            if now_ms() - start > 5000 {
                self.dead = true;
                return false;
            }
            core::hint::spin_loop();
        }
        unsafe { core::ptr::read_volatile(status) == 0 }
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
        let ok = self.rw(sector, buf.as_mut_ptr(), buf.len(), false);
        BUSY.store(false, Ordering::Relaxed);
        ok
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> bool {
        BUSY.store(true, Ordering::Relaxed);
        let ok = self.rw(sector, buf.as_ptr() as *mut u8, buf.len(), true);
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
