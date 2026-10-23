//! PCI configuration space access (mechanism #1, ports 0xCF8/0xCFC).

pub use rustros_api::module::PciAddr as PciDev;

pub unsafe fn outb(port: u16, v: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}
pub unsafe fn outw(port: u16, v: u16) {
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe { core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}
pub unsafe fn outl(port: u16, v: u32) {
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

fn addr(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    0x8000_0000 | (bus as u32) << 16 | (dev as u32) << 11 | (func as u32) << 8 | (off as u32 & 0xFC)
}

/// Configuration space of a PCI function.
pub trait Config {
    fn read32(&self, off: u8) -> u32;
    fn write32(&self, off: u8, v: u32);
    fn read16(&self, off: u8) -> u16;
    fn write16(&self, off: u8, v: u16);
    fn write8(&self, off: u8, v: u8);
    fn read8(&self, off: u8) -> u8;
    fn enable(&self);
    fn enable_intx(&self);
    fn bar(&self, n: u8) -> (u64, bool);
    fn caps(&self) -> impl Iterator<Item = u8> + '_;
}

impl Config for PciDev {
    fn read32(&self, off: u8) -> u32 {
        unsafe {
            outl(0xCF8, addr(self.bus, self.dev, self.func, off));
            inl(0xCFC)
        }
    }
    fn write32(&self, off: u8, v: u32) {
        unsafe {
            outl(0xCF8, addr(self.bus, self.dev, self.func, off));
            outl(0xCFC, v);
        }
    }
    // Some devices (QEMU's i6300esb) only act on config writes of the exact
    // register width, so these must not be emulated with 32-bit writes.
    fn read16(&self, off: u8) -> u16 {
        (self.read32(off & !3) >> ((off & 2) * 8)) as u16
    }

    fn write16(&self, off: u8, v: u16) {
        unsafe {
            outl(0xCF8, addr(self.bus, self.dev, self.func, off));
            core::arch::asm!("out dx, ax", in("dx") 0xCFC + (off & 2) as u16, in("ax") v, options(nomem, nostack, preserves_flags));
        }
    }
    fn write8(&self, off: u8, v: u8) {
        unsafe {
            outl(0xCF8, addr(self.bus, self.dev, self.func, off));
            outb(0xCFC + (off & 3) as u16, v);
        }
    }
    fn read8(&self, off: u8) -> u8 {
        (self.read32(off) >> ((off & 3) * 8)) as u8
    }

    /// Enable I/O, memory and bus mastering; disable legacy INTx.
    fn enable(&self) {
        let cmd = self.read32(0x04);
        self.write32(0x04, (cmd & 0xFFFF) | 0x07 | 0x400);
    }

    /// Let the device raise its legacy interrupt (`enable` turns it off).
    fn enable_intx(&self) {
        let cmd = self.read32(0x04);
        self.write32(0x04, cmd & 0xFFFF & !0x400);
    }

    /// Returns (address, is_io) of BAR `n`, combining 64-bit BARs.
    fn bar(&self, n: u8) -> (u64, bool) {
        let off = 0x10 + n * 4;
        let lo = self.read32(off);
        if lo & 1 != 0 {
            return ((lo & !3) as u64, true);
        }
        let mut a = (lo & !0xF) as u64;
        if (lo >> 1) & 3 == 2 {
            a |= (self.read32(off + 4) as u64) << 32;
        }
        (a, false)
    }

    /// Iterate the capability list: yields config-space offsets.
    fn caps(&self) -> impl Iterator<Item = u8> + '_ {
        let has = self.read32(0x04) & (1 << 20) != 0;
        let mut p = if has { self.read8(0x34) & 0xFC } else { 0 };
        let mut guard = 0;
        core::iter::from_fn(move || {
            if p == 0 || guard > 48 {
                return None;
            }
            guard += 1;
            let cur = p;
            p = self.read8(cur + 1) & 0xFC;
            Some(cur)
        })
    }
}

/// Enumerate all functions on all buses.
pub fn scan(mut f: impl FnMut(PciDev)) {
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let d = PciDev { bus, dev, func, vendor: 0, device: 0 };
                let id = d.read32(0);
                if id & 0xFFFF == 0xFFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                f(PciDev { vendor: id as u16, device: (id >> 16) as u16, ..d });
                if func == 0 && d.read8(0x0E) & 0x80 == 0 {
                    break; // not multi-function
                }
            }
        }
    }
}
