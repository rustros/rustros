//! What the kernel gives device drivers (boot modules): PCI functions to
//! probe, and `Hw`. A disk a driver drives is wrapped to tell the watchdog
//! when a request is in flight and to pin a crash in it on the driver.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use devices::BlockDevice;
use rustros_api::module::{Device, Driver, Hw, IrqAck, PciAddr};

use crate::modules::set_current_native;

struct KernelHw;

impl Hw for KernelHw {
    fn map_device(&self, phys: u64, len: u64) -> bool {
        crate::mem::map_device(phys, len)
    }
    fn now_ms(&self) -> u64 {
        crate::arch::now_ms()
    }
    fn tsc_per_ms(&self) -> u64 {
        crate::arch::tsc_per_ms()
    }
    fn log(&self, line: &str) {
        crate::kprintln!("{}", line);
    }
    fn msi(&self) -> Option<(u8, u8)> {
        crate::arch::lapic_init().map(|apic| (apic, crate::arch::MSI_VECTOR))
    }
    fn route_irq(&self, line: u8, ack: IrqAck) -> bool {
        if line == 0 || line == 2 || line >= 16 {
            return false;
        }
        // Safety: boot time, single core, before the line is unmasked.
        let r = unsafe { ISRS.get() };
        // a device taken again by a new driver (hot replacement): known already
        if r.0[..r.1].iter().any(|&(l, a)| l == line && a == ack) {
            return true;
        }
        if r.1 == MAX_ISRS {
            return false;
        }
        r.0[r.1] = (line, ack);
        r.1 += 1;
        crate::arch::unmask_irq(line);
        true
    }
}

const MAX_ISRS: usize = 8;

/// Interrupt lines and the status registers of the devices on them.
static ISRS: crate::Global<([(u8, IrqAck); MAX_ISRS], usize)> = crate::Global::new(([(0, IrqAck::Port(0)); MAX_ISRS], 0));

/// Interrupt on `line`: acknowledge every device on it (level-triggered).
pub fn ack_irq(line: u8) {
    // Safety: written only before the lines were unmasked.
    let r = unsafe { ISRS.get() };
    for &(l, ack) in &r.0[..r.1] {
        if l == line {
            // Safety: a device register its driver handed over.
            unsafe {
                match ack {
                    IrqAck::Mmio(a) => {
                        core::ptr::read_volatile(a as *const u8);
                    }
                    IrqAck::Port(p) => {
                        crate::arch::inb(p);
                    }
                }
            }
        }
    }
}

pub static HW: &dyn Hw = &KernelHw;

/// A request is in flight (the watchdog must not write the disk then).
static BUSY: AtomicBool = AtomicBool::new(false);

pub fn busy() -> bool {
    BUSY.load(Ordering::Relaxed)
}

/// A disk and the driver driving it.
pub struct Disk {
    pub dev: Box<dyn BlockDevice>,
    pub driver: &'static str,
}

impl Disk {
    fn call<T>(&mut self, f: impl FnOnce(&mut dyn BlockDevice) -> T) -> T {
        BUSY.store(true, Ordering::Relaxed);
        let before = set_current_native(Some(self.driver));
        let r = f(&mut *self.dev);
        set_current_native(before);
        BUSY.store(false, Ordering::Relaxed);
        r
    }
}

impl BlockDevice for Disk {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.call(|d| d.read(lba, buf))
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        self.call(|d| d.write(lba, buf))
    }
    fn sectors(&self) -> u64 {
        self.dev.sectors()
    }
    fn read_only(&self) -> bool {
        self.dev.read_only()
    }
}

/// Offer `dev` to the drivers in turn: the first that takes it drives it
/// (its name comes along).
pub fn probe(drivers: &mut [Box<dyn Driver>], dev: PciAddr, options: &str) -> Option<(Device, &'static str)> {
    for d in drivers {
        let name = d.name();
        let before = set_current_native(Some(name));
        let got = d.probe(HW, dev, options);
        set_current_native(before);
        if let Some(dev) = got {
            return Some((dev, name));
        }
    }
    None
}
