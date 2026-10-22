//! virtio-pci transport (modern 1.0 MMIO, with legacy I/O-port fallback) and
//! split virtqueues. Everything is polled; device interrupts stay off.

use alloc::alloc::{Layout, alloc_zeroed};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use crate::arch::{inb, inl, outb, outl};
use crate::pci::PciDev;

pub const F_VERSION_1: u64 = 1 << 32;

const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;

enum Transport {
    Modern { common: usize, notify: usize, notify_mul: u32, device: usize, isr: usize },
    Legacy { io: u16 },
}

pub struct Virtio {
    t: Transport,
}

unsafe fn rd<T>(a: usize) -> T {
    unsafe { read_volatile(a as *const T) }
}
unsafe fn wr<T>(a: usize, v: T) {
    unsafe { write_volatile(a as *mut T, v) }
}
unsafe fn outw(port: u16, v: u16) {
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) }
}
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe { core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

// modern common configuration offsets
const C_DFSEL: usize = 0;
const C_DF: usize = 4;
const C_GFSEL: usize = 8;
const C_GF: usize = 12;
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
const L_CONFIG: u16 = 20;

impl Virtio {
    pub fn probe(pci: &PciDev) -> Option<Virtio> {
        pci.enable();
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
            if io || base == 0 || !crate::mem::map_identity(base + off, len) {
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
        let t = match (common, notify, device) {
            (Some(common), Some(notify), Some(device)) => Transport::Modern { common, notify, notify_mul: mul, device, isr: isr.unwrap_or(0) },
            _ => {
                let (io, is_io) = pci.bar(0);
                if !is_io || io == 0 {
                    return None;
                }
                Transport::Legacy { io: io as u16 }
            }
        };
        Some(Virtio { t })
    }

    /// The ISR status register (reading it acknowledges the interrupt).
    pub fn isr(&self) -> Option<Isr> {
        match self.t {
            Transport::Modern { isr: 0, .. } => None,
            Transport::Modern { isr, .. } => Some(Isr::Mmio(isr)),
            Transport::Legacy { io } => Some(Isr::Port(io + 19)),
        }
    }

    pub fn is_modern(&self) -> bool {
        matches!(self.t, Transport::Modern { .. })
    }

    fn set_status(&self, s: u8) {
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => wr::<u8>(common + C_STATUS, s),
                Transport::Legacy { io } => outb(io + L_STATUS, s),
            }
        }
    }
    fn status(&self) -> u8 {
        unsafe {
            match self.t {
                Transport::Modern { common, .. } => rd::<u8>(common + C_STATUS),
                Transport::Legacy { io } => inb(io + L_STATUS),
            }
        }
    }

    /// Reset and negotiate features. Returns the accepted feature set.
    pub fn begin(&self, wanted: u64) -> Option<u64> {
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
                    let f = (lo | hi << 32) & (wanted | F_VERSION_1);
                    if f & F_VERSION_1 == 0 {
                        return None;
                    }
                    wr::<u32>(common + C_GFSEL, 0);
                    wr::<u32>(common + C_GF, f as u32);
                    wr::<u32>(common + C_GFSEL, 1);
                    wr::<u32>(common + C_GF, (f >> 32) as u32);
                    self.set_status(S_ACK | S_DRIVER | S_FEATURES_OK);
                    if self.status() & S_FEATURES_OK == 0 {
                        return None;
                    }
                    Some(f)
                }
                Transport::Legacy { io } => {
                    let f = inl(io + L_HF) as u64 & wanted & 0xFFFF_FFFF;
                    outl(io + L_GF, f as u32);
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
                Transport::Legacy { io } => inl(io + L_HF) as u64,
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
                Transport::Legacy { io } => inb(io + L_CONFIG + off as u16),
            }
        }
    }

    pub fn config32(&self, off: usize) -> u32 {
        unsafe {
            match self.t {
                Transport::Modern { device, .. } => rd::<u32>(device + off),
                Transport::Legacy { io } => inl(io + L_CONFIG + off as u16),
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
                    outw(io + L_QSEL, idx);
                    inw(io + L_QSIZE)
                }
            };
            if size == 0 {
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
                    wr::<u16>(common + C_QMSIX, 0xFFFF);
                    wr::<u64>(common + C_QDESC, desc as u64);
                    wr::<u64>(common + C_QDRIVER, avail as u64);
                    wr::<u64>(common + C_QDEVICE, used as u64);
                    let off = rd::<u16>(common + C_QNOTIFY) as usize;
                    wr::<u16>(common + C_QENABLE, 1);
                    Notify::Mmio(notify + off * notify_mul as usize)
                }
                Transport::Legacy { io } => {
                    outl(io + L_QPFN, (mem >> 12) as u32);
                    Notify::Port(io + L_QNOTIFY)
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

const MAX_ISRS: usize = 8;

/// Interrupt lines and the ISR registers of the virtio devices on them.
static ISRS: crate::Global<([(u8, Isr); MAX_ISRS], usize)> = crate::Global::new(([(0, Isr::Port(0)); MAX_ISRS], 0));

/// Route a device's legacy interrupt `line` through the PIC; false if the
/// line is unusable (then only the timer wakes the CPU).
pub fn register_irq(line: u8, isr: Isr) -> bool {
    if line == 0 || line == 2 || line >= 16 {
        return false;
    }
    // Safety: boot time, single core, before the line is unmasked.
    let r = unsafe { ISRS.get() };
    if r.1 == MAX_ISRS {
        return false;
    }
    r.0[r.1] = (line, isr);
    r.1 += 1;
    crate::arch::unmask_irq(line);
    true
}

/// Interrupt on `line`: acknowledge every device on it (level-triggered).
pub fn ack_irq(line: u8) {
    // Safety: written only before the lines were unmasked.
    let r = unsafe { ISRS.get() };
    for &(l, isr) in &r.0[..r.1] {
        if l == line {
            unsafe {
                match isr {
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
}
