//! Intel 6300ESB watchdog (QEMU/KVM `-device i6300esb`). It resets the machine
//! even when the kernel is wedged with interrupts off, which the software
//! watchdog in the timer interrupt cannot catch.

use core::ptr::write_volatile;

use crate::arch::now_ms;
use virtio::pci::{self, Config, PciDev};

/// Total time without a pet before the reset (longer than the software
/// watchdog, which should normally fire first).
pub const TIMEOUT_S: u32 = 60;

const CONFIG: u8 = 0x60;
const LOCK: u8 = 0x68;
const TIMER1: usize = 0x00;
const TIMER2: usize = 0x04;
const RELOAD: usize = 0x0C;

pub struct Esb {
    base: usize,
    last_pet: u64,
}

impl Esb {
    pub fn probe() -> Option<Esb> {
        let mut found = None;
        pci::scan(|d| {
            if d.vendor == 0x8086 && d.device == 0x25AB && found.is_none() {
                found = Some(d);
            }
        });
        let d: PciDev = found?;
        d.enable();
        let (bar, io) = d.bar(0);
        if io || bar == 0 || !crate::mem::map_device(bar, 0x1000) {
            return None;
        }
        let mut w = Esb { base: bar as usize, last_pet: 0 };
        // no stage-1 interrupt, reboot on stage-2 expiry, ~1 kHz clock
        d.write16(CONFIG, 0x0003);
        d.write8(LOCK, 0x00); // stop while we program it
        w.unlock();
        w.w16(RELOAD, 1 << 9); // clear a pending timeout flag
        // each stage counts (TIMEOUT_S << 9) ticks at 1 kHz: TIMEOUT_S in total
        let val = TIMEOUT_S << 9;
        w.unlock();
        w.w32(TIMER1, val);
        w.unlock();
        w.w32(TIMER2, val);
        w.reload();
        d.write8(LOCK, 0x02); // enable (not locked, so a new kernel can reprogram it)
        w.last_pet = now_ms();
        Some(w)
    }

    fn w16(&self, off: usize, v: u16) {
        unsafe { write_volatile((self.base + off) as *mut u16, v) }
    }
    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }
    fn unlock(&self) {
        self.w16(RELOAD, 0x80);
        self.w16(RELOAD, 0x86);
    }
    fn reload(&self) {
        self.unlock();
        self.w16(RELOAD, 1 << 8);
    }

    /// Restart the countdown (rate-limited to once a second).
    pub fn pet(&mut self) {
        let now = now_ms();
        if now - self.last_pet >= 1000 {
            self.reload();
            self.last_pet = now;
        }
    }
}
