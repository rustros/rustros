//! virtio-pci transport (modern 1.0 MMIO, with legacy I/O-port fallback) and
//! split virtqueues, and the drivers on them that live in boot modules
//! (`blk`). Shared by the kernel (virtio-net) and the boot module.
#![no_std]

extern crate alloc;

pub mod blk;
pub mod pci;

use alloc::alloc::{Layout, alloc_zeroed};
use alloc::format;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use pci::{Config, PciDev, inb, inl, inw, outb, outl, outw};
pub use rustros_api::module::Hw;

pub const F_VERSION_1: u64 = 1 << 32;
/// The device sits behind the platform's DMA translation (none here: we
/// hand it physical addresses, which is what it then expects). Hardware
/// virtio devices (cloud hosts' offload cards) insist on it.
const F_ACCESS_PLATFORM: u64 = 1 << 33;
/// Memory ordering as for real hardware: our fences already are.
const F_ORDER_PLATFORM: u64 = 1 << 35;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;

enum Transport {
    Modern { common: usize, notify: usize, notify_mul: u32, device: usize, isr: usize },
    Legacy { io: Lio },
}

/// Where a legacy device's registers are: I/O ports, or a memory BAR (as on
/// some cloud hosts).
#[derive(Clone, Copy)]
enum Lio {
    Port(u16),
    Mem(usize),
}

impl Lio {
    unsafe fn r8(self, off: u16) -> u8 {
        unsafe {
            match self {
                Lio::Port(p) => inb(p + off),
                Lio::Mem(a) => rd::<u8>(a + off as usize),
            }
        }
    }
    unsafe fn r16(self, off: u16) -> u16 {
        unsafe {
            match self {
                Lio::Port(p) => inw(p + off),
                Lio::Mem(a) => rd::<u16>(a + off as usize),
            }
        }
    }
    unsafe fn r32(self, off: u16) -> u32 {
        unsafe {
            match self {
                Lio::Port(p) => inl(p + off),
                Lio::Mem(a) => rd::<u32>(a + off as usize),
            }
        }
    }
    unsafe fn w8(self, off: u16, v: u8) {
        unsafe {
            match self {
                Lio::Port(p) => outb(p + off, v),
                Lio::Mem(a) => wr::<u8>(a + off as usize, v),
            }
        }
    }
    unsafe fn w16(self, off: u16, v: u16) {
        unsafe {
            match self {
                Lio::Port(p) => outw(p + off, v),
                Lio::Mem(a) => wr::<u16>(a + off as usize, v),
            }
        }
    }
    unsafe fn w32(self, off: u16, v: u32) {
        unsafe {
            match self {
                Lio::Port(p) => outl(p + off, v),
                Lio::Mem(a) => wr::<u32>(a + off as usize, v),
            }
        }
    }
}

pub struct Virtio {
    pub hw: &'static dyn Hw,
    t: Transport,
    /// the legacy registers of a transitional device, to fall back to
    legacy_io: Option<Lio>,
    /// "00:05.0", for messages
    at: alloc::string::String,
    /// queues interrupt by MSI-X (table entry 0)
    msix: bool,
    /// the device did not take an MSI-X vector for a queue
    msix_refused: core::cell::Cell<bool>,
}

unsafe fn rd<T>(a: usize) -> T {
    unsafe { read_volatile(a as *const T) }
}
unsafe fn wr<T>(a: usize, v: T) {
    unsafe { write_volatile(a as *mut T, v) }
}

// modern common configuration offsets
const C_DFSEL: usize = 0;
const C_DF: usize = 4;
const C_GFSEL: usize = 8;
const C_GF: usize = 12;
const C_MSIX_CONFIG: usize = 16;
const C_STATUS: usize = 20;
const C_QSEL: usize = 22;
const C_QSIZE: usize = 24;
const C_QMSIX: usize = 26;
const C_QENABLE: usize = 28;
const C_QNOTIFY: usize = 30;
const C_QDESC: usize = 32;
const C_QDRIVER: usize = 40;
const C_QDEVICE: usize = 48;

// legacy register offsets
const L_HF: u16 = 0;
const L_GF: u16 = 4;
const L_QPFN: u16 = 8;
const L_QSIZE: u16 = 12;
const L_QSEL: u16 = 14;
const L_QNOTIFY: u16 = 16;
const L_STATUS: u16 = 18;
/// with MSI-X on: the vectors for configuration changes and the selected
/// queue come here, and the device's configuration moves 4 bytes on
const L_CVEC: u16 = 20;
const L_QVEC: u16 = 22;
const L_CONFIG: u16 = 20;

impl Virtio {
    pub fn probe(hw: &'static dyn Hw, pci: &PciDev) -> Option<Virtio> {
        pci.enable();
        let at = alloc::format!("{:02x}:{:02x}.{}", pci.bus, pci.dev, pci.func);
        let (mut common, mut notify, mut device, mut mul, mut isr) = (None, None, None, 0, None);
        for cap in pci.caps() {
            if pci.read8(cap) != 0x09 {
                continue;
            }
            let ty = pci.read8(cap + 3);
            let bar = pci.read8(cap + 4);
            let off = pci.read32(cap + 8) as u64;
            let len = pci.read32(cap + 12) as u64;
            if bar > 5 {
                continue;
            }
            let (base, io) = pci.bar(bar);
            if !(1..=4).contains(&ty) {
                continue;
            }
            if io || base == 0 || !hw.map_device(base + off, len) {
                hw.log(&format!("virtio {}: capability {} in BAR{} at {:#x}+{:#x} not usable", at, ty, bar, base, off));
                continue;
            }
            let a = (base + off) as usize;
            match ty {
                1 => common = Some(a),
                2 => {
                    notify = Some(a);
                    mul = pci.read32(cap + 16);
                }
                3 => isr = Some(a),
                4 => device = Some(a),
                _ => {}
            }
        }
        let (io, is_io) = pci.bar(0);
        let modern = common.is_some() && notify.is_some() && device.is_some();
        let legacy_io = if is_io && io != 0 {
            Some(Lio::Port(io as u16))
        } else if !modern && io != 0 && hw.map_device(io, 4096) {
            // a legacy device with its registers in memory
            Some(Lio::Mem(io as usize))
        } else {
            None
        };
        if legacy_io.is_some() && !modern {
            // the legacy layout moves the device's config when MSI-X is on: keep it off
            if let Some(c) = pci.caps().find(|&c| pci.read8(c) == 0x11) {
                let ctl = pci.read8(c + 3);
                if ctl & 0x80 != 0 {
                    pci.write8(c + 3, ctl & !0x80);
                }
            }
        }
        let t = match (common, notify, device) {
            (Some(common), Some(notify), Some(device)) => Transport::Modern { common, notify, notify_mul: mul, device, isr: isr.unwrap_or(0) },
            _ => match legacy_io {
                Some(io) => Transport::Legacy { io },
                None => {
                    hw.log(&format!("virtio {}: neither modern registers nor legacy ones (BAR0 {:#x})", at, io));
                    return None;
                }
            },
        };
        Some(Virtio { hw, t, legacy_io, at, msix: false, msix_refused: core::cell::Cell::new(false) })
    }

    /// The ISR status register (reading it acknowledges the interrupt).
    pub fn isr(&self) -> Option<Isr> {
        match self.t {
            Transport::Modern { isr: 0, .. } => None,
            Transport::Modern { isr, .. } => Some(Isr::Mmio(isr)),
            Transport::Legacy { io: Lio::Port(p) } => Some(Isr::Port(p + 19)),
            Transport::Legacy { io: Lio::Mem(a) } => Some(Isr::Mmio(a + 19)),
        }
    }

    /// Interrupt by MSI-X on `vector` of the CPU with local APIC `apic`
    /// (before `begin`): true if the device has MSI-X. Whether the device
    /// took it shows once the queues are set up (`msix_ok`).
    pub fn enable_msix(&mut self, pci: &PciDev, apic: u8, vector: u8) -> bool {
        let Some(cap) = pci.caps().find(|&c| pci.read8(c) == 0x11) else { return false };
        let ctl = pci.read16(cap + 2);
        let table = pci.read32(cap + 4);
        let (base, io) = pci.bar((table & 7) as u8);
        let entries = (ctl & 0x7FF) as u64 + 1;
        let at = base + (table & !7) as u64;
        if io || base == 0 || !self.hw.map_device(at, 16 * entries) {
            return false;
        }
        unsafe {
            // every entry masked but the first, which all queues use
            for e in 0..entries as usize {
                wr::<u32>(at as usize + 16 * e + 12, 1);
            }
            let e = at as usize;
            wr::<u32>(e, 0xFEE0_0000 | (apic as u32) << 12);
            wr::<u32>(e + 4, 0);
            wr::<u32>(e + 8, vector as u32); // fixed delivery, edge
            wr::<u32>(e + 12, 0);
        }
        pci.write16(cap + 2, (ctl | 0x8000) & !0x4000);
        self.msix = true;
        true
    }

    /// The queues interrupt by MSI-X.
    pub fn msix_ok(&self) -> bool {
        self.msix && !self.msix_refused.get()
    }

    /// Where a legacy device's own configuration starts.
    fn l_config(&self) -> u16 {
        if self.msix { L_CONFIG + 4 } else { L_CONFIG }
    }

    pub fn is_modern(&self) -> bool {
        matches!(self.t, Transport::Modern { .. })
    }

    fn set_status(&self, s: u8) {
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => wr::<u8>(common + C_STATUS, s),
                Transport::Legacy { io } => io.w8(L_STATUS, s),
            }
        }
    }
    fn status(&self) -> u8 {
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => rd::<u8>(common + C_STATUS),
                Transport::Legacy { io } => io.r8(L_STATUS),
            }
        }
    }

    /// Reset and negotiate features. Returns the accepted feature set. A
    /// transitional device that refuses the modern way is driven the
    /// legacy way.
    pub fn begin(&mut self, wanted: u64) -> Option<u64> {
        match self.negotiate(wanted) {
            Some(f) => Some(f),
            None if self.is_modern() && self.legacy_io.is_some() => {
                self.hw.log(&format!("virtio {}: trying the legacy interface", self.at));
                self.set_status(0);
                self.t = Transport::Legacy { io: self.legacy_io? };
                self.negotiate(wanted)
            }
            None => None,
        }
    }

    fn negotiate(&self, wanted: u64) -> Option<u64> {
        self.set_status(0);
        while self.status() != 0 {}
        self.set_status(S_ACK);
        self.set_status(S_ACK | S_DRIVER);
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => {
                    wr::<u32>(common + C_DFSEL, 0);
                    let lo = rd::<u32>(common + C_DF) as u64;
                    wr::<u32>(common + C_DFSEL, 1);
                    let hi = rd::<u32>(common + C_DF) as u64;
                    let offered = lo | hi << 32;
                    let f = offered & (wanted | F_VERSION_1 | F_ACCESS_PLATFORM | F_ORDER_PLATFORM);
                    if f & F_VERSION_1 == 0 {
                        self.hw.log(&format!("virtio {}: no VERSION_1 (offers {:#x})", self.at, offered));
                        return None;
                    }
                    wr::<u32>(common + C_GFSEL, 0);
                    wr::<u32>(common + C_GF, f as u32);
                    wr::<u32>(common + C_GFSEL, 1);
                    wr::<u32>(common + C_GF, (f >> 32) as u32);
                    self.set_status(S_ACK | S_DRIVER | S_FEATURES_OK);
                    if self.status() & S_FEATURES_OK == 0 {
                        self.hw.log(&format!("virtio {}: features {:#x} refused (offers {:#x})", self.at, f, offered));
                        return None;
                    }
                    Some(f)
                }
                Transport::Legacy { io } => {
                    let f = io.r32(L_HF) as u64 & wanted & 0xFFFF_FFFF;
                    io.w32(L_GF, f as u32);
                    Some(f)
                }
            }
        }
    }

    pub fn finish(&self) {
        let s = self.status();
        self.set_status(s | S_DRIVER_OK);
    }

    /// Everything the device offers (not just what was negotiated).
    pub fn offered(&self) -> u64 {
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => {
                    wr::<u32>(common + C_DFSEL, 0);
                    let lo = rd::<u32>(common + C_DF) as u64;
                    wr::<u32>(common + C_DFSEL, 1);
                    lo | (rd::<u32>(common + C_DF) as u64) << 32
                }
                Transport::Legacy { io } => io.r32(L_HF) as u64,
            }
        }
    }

    pub fn config16(&self, off: usize) -> u16 {
        self.config8(off) as u16 | (self.config8(off + 1) as u16) << 8
    }

    pub fn config8(&self, off: usize) -> u8 {
        unsafe {
            match self.t {
                Transport::Modern { device, .. } => rd::<u8>(device + off),
                Transport::Legacy { io } => io.r8(self.l_config() + off as u16),
            }
        }
    }

    pub fn config32(&self, off: usize) -> u32 {
        unsafe {
            match self.t {
                Transport::Modern { device, .. } => rd::<u32>(device + off),
                Transport::Legacy { io } => io.r32(self.l_config() + off as u16),
            }
        }
    }

    /// Set up virtqueue `idx` with at most `max` entries.
    pub fn queue(&self, idx: u16, max: u16) -> Option<Queue> {
        unsafe {
            let size = match self.t {
                Transport::Modern { common, .. } => {
                    wr::<u16>(common + C_QSEL, idx);
                    rd::<u16>(common + C_QSIZE)
                }
                Transport::Legacy { io } => {
                    io.w16(L_QSEL, idx);
                    io.r16(L_QSIZE)
                }
            };
            if size == 0 {
                self.hw.log(&format!("virtio {}: no queue {}", self.at, idx));
                return None;
            }
            // modern devices let us shrink the queue; legacy ones don't
            let size = if self.is_modern() { size.min(max) } else { size };
            let n = size as usize;
            let used_off = (16 * n + 6 + 2 * n + 4095) & !4095;
            let total = used_off + ((6 + 8 * n + 4095) & !4095);
            let mem = alloc_zeroed(Layout::from_size_align(total, 4096).ok()?) as usize;
            if mem == 0 {
                return None;
            }
            let (desc, avail, used) = (mem, mem + 16 * n, mem + used_off);
            let notify = match self.t {
                Transport::Modern { common, notify, notify_mul, .. } => {
                    wr::<u16>(common + C_QSIZE, size);
                    if self.msix {
                        wr::<u16>(common + C_MSIX_CONFIG, 0xFFFF);
                        wr::<u16>(common + C_QMSIX, 0);
                        if rd::<u16>(common + C_QMSIX) != 0 {
                            self.msix_refused.set(true);
                        }
                    } else {
                        wr::<u16>(common + C_QMSIX, 0xFFFF);
                    }
                    wr::<u64>(common + C_QDESC, desc as u64);
                    wr::<u64>(common + C_QDRIVER, avail as u64);
                    wr::<u64>(common + C_QDEVICE, used as u64);
                    let off = rd::<u16>(common + C_QNOTIFY) as usize;
                    wr::<u16>(common + C_QENABLE, 1);
                    Notify::Mmio(notify + off * notify_mul as usize)
                }
                Transport::Legacy { io } => {
                    if self.msix {
                        io.w16(L_CVEC, 0xFFFF);
                        io.w16(L_QVEC, 0);
                        if io.r16(L_QVEC) != 0 {
                            self.msix_refused.set(true);
                        }
                    }
                    io.w32(L_QPFN, (mem >> 12) as u32);
                    match io {
                        Lio::Port(p) => Notify::Port(p + L_QNOTIFY),
                        Lio::Mem(a) => Notify::Mmio(a + L_QNOTIFY as usize),
                    }
                }
            };
            wr::<u16>(avail, 1); // VIRTQ_AVAIL_F_NO_INTERRUPT
            Some(Queue { idx, size, desc, avail, used, notify, avail_idx: 0, last_used: 0 })
        }
    }
}

enum Notify {
    Mmio(usize),
    Port(u16),
}

pub const D_NEXT: u16 = 1;
pub const D_WRITE: u16 = 2;

/// A split virtqueue. Drivers manage descriptor ids themselves.
pub struct Queue {
    idx: u16,
    pub size: u16,
    desc: usize,
    avail: usize,
    used: usize,
    notify: Notify,
    avail_idx: u16,
    last_used: u16,
}

impl Queue {
    pub fn set_desc(&mut self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let d = self.desc + 16 * i as usize;
        unsafe {
            wr::<u64>(d, addr);
            wr::<u32>(d + 8, len);
            wr::<u16>(d + 12, flags);
            wr::<u16>(d + 14, next);
        }
    }

    pub fn push(&mut self, head: u16) {
        let slot = self.avail + 4 + 2 * (self.avail_idx % self.size) as usize;
        unsafe { wr::<u16>(slot, head) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        fence(Ordering::SeqCst);
        unsafe { wr::<u16>(self.avail + 2, self.avail_idx) };
    }

    /// Notify the device unless it said it does not need it (it is still
    /// processing the queue: VIRTQ_USED_F_NO_NOTIFY).
    pub fn kick(&self) {
        fence(Ordering::SeqCst);
        if unsafe { rd::<u16>(self.used) } & 1 == 0 {
            self.notify();
        }
    }

    /// Completed buffers not taken yet.
    pub fn used_count(&self) -> u16 {
        unsafe { rd::<u16>(self.used + 2).wrapping_sub(self.last_used) }
    }

    /// Completed buffers are waiting.
    pub fn has_used(&self) -> bool {
        unsafe { rd::<u16>(self.used + 2) != self.last_used }
    }

    /// Interrupt when the device completes buffers (VIRTQ_AVAIL_F_NO_INTERRUPT off).
    pub fn set_interrupts(&self, on: bool) {
        unsafe { wr::<u16>(self.avail, if on { 0 } else { 1 }) };
        fence(Ordering::SeqCst);
    }

    pub fn notify(&self) {
        fence(Ordering::SeqCst);
        unsafe {
            match self.notify {
                Notify::Mmio(a) => wr::<u16>(a, self.idx),
                Notify::Port(p) => outw(p, self.idx),
            }
        }
    }

    /// Next completed descriptor chain: (head id, bytes written by device).
    pub fn pop(&mut self) -> Option<(u16, u32)> {
        let used_idx = unsafe { rd::<u16>(self.used + 2) };
        if used_idx == self.last_used {
            return None;
        }
        fence(Ordering::SeqCst);
        let e = self.used + 4 + 8 * (self.last_used % self.size) as usize;
        self.last_used = self.last_used.wrapping_add(1);
        unsafe { Some((rd::<u32>(e) as u16, rd::<u32>(e + 4))) }
    }
}

#[derive(Clone, Copy)]
pub enum Isr {
    Mmio(usize),
    Port(u16),
}

impl Isr {
    /// Read the ISR status register: acknowledges a legacy interrupt.
    pub fn ack(self) {
        unsafe {
            match self {
                Isr::Mmio(a) => {
                    rd::<u8>(a);
                }
                Isr::Port(p) => {
                    inb(p);
                }
            }
        }
    }
}
