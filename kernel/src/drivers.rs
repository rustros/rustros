//! What the kernel gives device drivers (boot modules): PCI functions to
//! probe, and `Hw`. A disk a driver drives is wrapped to tell the watchdog
//! when a request is in flight and to pin a crash in it on the driver.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use devices::BlockDevice;
use rustros_api::module::{Hw, PciAddr};

use crate::modules::set_current_native;

struct KernelHw;

impl Hw for KernelHw {
    fn map_device(&self, phys: u64, len: u64) -> bool {
        crate::mem::map_device(phys, len)
    }
    fn now_ms(&self) -> u64 {
        crate::arch::now_ms()
    }
    fn log(&self, line: &str) {
        crate::kprintln!("{}", line);
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

/// Offer `dev` to the drivers in turn: the first that takes it drives it.
pub fn probe(drivers: &mut [Box<dyn rustros_api::module::Driver>], dev: PciAddr, disks: &mut alloc::vec::Vec<Disk>) {
    for d in drivers {
        let name = d.name();
        let before = set_current_native(Some(name));
        let got = d.probe(HW, dev);
        set_current_native(before);
        match got {
            Some(rustros_api::module::Device::Block(b)) => return disks.push(Disk { dev: b, driver: name }),
            None => {}
        }
    }
}
