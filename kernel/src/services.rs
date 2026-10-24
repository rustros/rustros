//! The services: device drivers, storage, the network stack and the module
//! manager. The boot modules' binary provides them at boot; an installed
//! module exporting one replaces it while the system runs (hot replacement,
//! see `rustros_api::module::Export`). Replacements happen between two
//! main-loop passes (`modules::apply`), when no call is in flight.
//!
//! The boot image's network stack is a bootstrap without a state handover:
//! an installed one replaces it at boot, before any app has run (only its
//! configuration is taken over); installed ones hand everything over to the
//! next. The boot image's storage, module manager and drivers are kept when
//! replaced, and come back when the module that replaced them is removed;
//! its stack comes back at the next boot.

use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use devices::NetDevice;
use rustros_api::module::{Device, Disk, Driver, Export, ModManager, NetStack, PciAddr, Storage};
use rustros_api::{ModuleInfo, ModuleKind};

use crate::sys::Kernel;
use crate::{drivers, kprintln, loader};

/// Where a service's code is: the installed module it came from, shared by
/// all it exports (None: the boot modules' binary, kept for good). Dropped
/// after the service itself.
pub struct Provider {
    /// the installed module's name (`BOOT`: the boot image's)
    pub name: &'static str,
    pub version: &'static str,
    _code: Option<Rc<loader::Module>>,
}

pub const BOOT: &str = "boot";
const BUSY: &str = "a kernel image is being written to the disk: install it again afterwards";

impl Provider {
    pub fn boot() -> Provider {
        Provider { name: BOOT, version: rustros_api::BUILD, _code: None }
    }
}

/// A device and who drives it, so a new driver can take it again.
pub struct Dev {
    pub pci: PciAddr,
    /// the driver's name (a boot module's: a replacement has the same name)
    pub driver: &'static str,
}

/// The boot image's services while installed ones replace them.
#[derive(Default)]
pub struct Parked {
    storage: Option<Box<dyn Storage>>,
    manager: Option<Box<dyn ModManager>>,
    drivers: Vec<Box<dyn Driver>>,
}

/// A service export, taken out of its module.
enum New {
    Driver(Box<dyn Driver>),
    Storage(Box<dyn Storage>),
    Stack(Box<dyn NetStack>),
    Manager(Box<dyn ModManager>),
}

impl New {
    fn version(&self) -> &'static str {
        match self {
            New::Driver(d) => d.version(),
            New::Storage(s) => s.version(),
            New::Stack(s) => s.version(),
            New::Manager(m) => m.version(),
        }
    }
}

fn flatten(e: Export, out: &mut Vec<New>) -> Result<(), &'static str> {
    match e {
        Export::Driver(d) => out.push(New::Driver(d)),
        Export::Storage(s) => out.push(New::Storage(s)),
        Export::NetStack(n) => out.push(New::Stack(n)),
        Export::Manager(m) => out.push(New::Manager(m)),
        Export::Many(v) => v.into_iter().try_for_each(|e| flatten(e, out))?,
        _ => return Err("a module with services exports nothing else"),
    }
    Ok(())
}

/// Whether module `m` exports services.
pub fn is_service(m: &loader::Module) -> bool {
    fn any(e: &Export) -> bool {
        match e {
            Export::Driver(_) | Export::Storage(_) | Export::NetStack(_) | Export::Manager(_) => true,
            Export::Many(v) => v.iter().any(any),
            _ => false,
        }
    }
    m.export.as_ref().is_some_and(any)
}

fn providers(k: &Kernel) -> impl Iterator<Item = &Provider> {
    [&k.stack_by, &k.boot_by, &k.manager_by].into_iter().chain(k.drivers.iter().map(|d| &d.1))
}

/// Whether installed module `name` provides a service now.
pub fn provides(k: &Kernel, name: &str) -> bool {
    providers(k).any(|p| p.name == name)
}

/// `a` is an older release than `b` (calendar versions, "2026.10.23.3";
/// anything else is never older).
fn older(a: &str, b: &str) -> bool {
    let num = |v: &str| -> Option<[u32; 4]> {
        let mut out = [0; 4];
        for (i, p) in v.split('.').enumerate() {
            *out.get_mut(i)? = p.parse().ok()?;
        }
        Some(out)
    };
    matches!((num(a), num(b)), (Some(x), Some(y)) if x < y)
}

/// Put what installed module `name` exports in service. Err: why not; the
/// services that ran stay.
pub fn start(k: &mut Kernel, name: &'static str, mut m: loader::Module) -> Result<(), String> {
    let mut news = Vec::new();
    flatten(m.export.take().ok_or("nothing exported")?, &mut news)?;
    // after a kernel update the boot image's services may be newer than
    // those installed for the kernel before
    if let Some(n) = news.iter().find(|n| older(n.version(), rustros_api::BUILD)) {
        return Err(format!("{} is older than the boot image ({}): mod rm {}", n.version(), rustros_api::BUILD, name));
    }
    let code = Rc::new(m);
    for n in news {
        let by = Provider { name, version: n.version(), _code: Some(code.clone()) };
        install(k, n, by)?;
    }
    Ok(())
}

/// Installed module `name` is removed: the boot image's services it
/// replaced come back.
pub fn revert(k: &mut Kernel, name: &str) -> Result<(), String> {
    const GONE: &str = "the boot image's version is gone";
    if k.boot_by.name == name {
        let s = k.parked.storage.take().ok_or(GONE)?;
        install(k, New::Storage(s), Provider::boot())?;
    }
    if k.manager_by.name == name {
        let m = k.parked.manager.take().ok_or(GONE)?;
        install(k, New::Manager(m), Provider::boot())?;
    }
    while let Some(i) = k.drivers.iter().position(|d| d.1.name == name) {
        let dn = k.drivers[i].0.name();
        let p = k.parked.drivers.iter().position(|d| d.name() == dn).ok_or(GONE)?;
        let d = k.parked.drivers.swap_remove(p);
        install(k, New::Driver(d), Provider::boot())?;
    }
    if k.stack_by.name == name {
        kprintln!("services: the boot image's network stack comes back at the next boot");
    }
    Ok(())
}

/// Replace one service, handing its state over.
fn install(k: &mut Kernel, n: New, by: Provider) -> Result<(), String> {
    let (name, version) = (by.name, by.version);
    let what = match n {
        New::Stack(mut new) => {
            new.set_owner_names(k.names.clone());
            if k.booting {
                // nothing holds state in it yet but its configuration (the
                // boot image's stack has no state handover)
                new.set_nics(k.nics.iter().map(|n| n.mac()).collect());
                new.set_config(&k.stack.config())?;
            } else {
                let v = new.state_version().min(k.stack.state_version());
                let state = k.stack.save_state(v).filter(|_| v > 0).ok_or("no state handover from the running stack: it takes over at the next boot")?;
                new.load_state(&state)?;
            }
            k.stack = new;
            k.stack_by = by;
            k.sync_ifmap();
            "network stack"
        }
        New::Manager(mut new) => {
            let old = k.manager.as_ref().ok_or("no module manager")?;
            let v = new.state_version().min(old.state_version());
            new.load_state(&old.save_state(v).ok_or("no state handover")?)?;
            let old = k.manager.replace(new);
            if k.manager_by.name == BOOT {
                k.parked.manager = old;
            }
            k.manager_by = by;
            "module manager"
        }
        New::Storage(mut new) => {
            let old = k.boot.as_mut().ok_or("no storage")?;
            if old.busy() {
                return Err(String::from(BUSY));
            }
            let v = new.state_version().min(old.state_version());
            let mut disks = Vec::new();
            let state = old.hand_over(v, &mut disks).ok_or("no state handover")?;
            let now = crate::arch::rdtsc();
            if let Err(e) = new.open(drivers::HW, &k.cmdline, &mut disks, now, Some(&state)) {
                // the old one goes on with it
                if let Err(e) = old.open(drivers::HW, &k.cmdline, &mut disks, now, Some(&state)) {
                    kprintln!("services: storage lost: {}", e);
                }
                return Err(e);
            }
            let old = k.boot.replace(new);
            if k.boot_by.name == BOOT {
                k.parked.storage = old;
            }
            k.boot_by = by;
            crate::set_crash_sink(k);
            "storage"
        }
        New::Driver(new) => {
            replace_driver(k, new, by)?;
            "driver"
        }
    };
    kprintln!("services: {} replaced by {} {}", what, name, version);
    Ok(())
}

/// A stand-in for a NIC that no driver takes any more.
struct Gone([u8; 6]);

impl NetDevice for Gone {
    fn mac(&self) -> [u8; 6] {
        self.0
    }
    fn send(&mut self, _: &[u8]) -> bool {
        false
    }
    fn recv(&mut self, _: &mut [u8]) -> Option<usize> {
        None
    }
    fn kind(&self) -> &'static str {
        "no driver"
    }
}

/// Drivers hand nothing over: the devices of the one replaced are reset and
/// taken again by the new one (the link drops for a moment); one it does not
/// take, the old driver takes back.
fn replace_driver(k: &mut Kernel, new: Box<dyn Driver>, by: Provider) -> Result<(), String> {
    let Some(old) = k.drivers.iter().position(|d| d.0.name() == new.name()) else {
        // for devices nobody drives yet: they are offered at the next boot
        k.drivers.push((new, by));
        return Ok(());
    };
    let name = k.drivers[old].0.name();
    let disk = k.disk_dev.as_ref().filter(|d| d.driver == name).map(|d| d.pci);
    if disk.is_some() && k.boot.as_ref().is_some_and(|b| b.busy()) {
        return Err(String::from(BUSY));
    }
    k.drivers.push((new, by));
    let new = k.drivers.len() - 1;
    for n in 0..k.nics.len() {
        if k.nic_dev[n].driver != name {
            continue;
        }
        // the old device goes first (it is reset), then the new driver takes it
        let mac = k.nics[n].mac();
        k.nics[n] = Box::new(Gone(mac));
        let (pci, options) = (k.nic_dev[n].pci, k.nic_options);
        match take(k, new, pci, options).or_else(|| take(k, old, pci, options)) {
            Some(Device::Net(d)) => k.nics[n] = d,
            _ => kprintln!("services: nic{}: no driver takes it", n),
        }
    }
    // the boot disk: the storage service lets go of it, the new driver takes
    // it, the storage service goes on with it
    if let (Some(pci), Some(b)) = (disk, k.boot.as_mut()) {
        let mut held = Vec::new();
        let state = b.hand_over(b.state_version(), &mut held).ok_or("no state handover")?;
        drop(held);
        let mut held: Vec<Box<dyn Disk>> = Vec::new();
        if let Some(Device::Block(dev)) = take(k, new, pci, "").or_else(|| take(k, old, pci, "")) {
            held.push(Box::new(drivers::Disk { dev, driver: k.drivers[new].1.name }));
        }
        let b = k.boot.as_mut().unwrap();
        if let Err(e) = b.open(drivers::HW, &k.cmdline, &mut held, crate::arch::rdtsc(), Some(&state)) {
            kprintln!("services: storage lost: {}", e);
            k.boot = None;
            crate::set_crash_sink(k);
        }
    }
    // the old driver goes last, after its devices
    let (d, p) = k.drivers.swap_remove(old);
    if p.name == BOOT {
        k.parked.drivers.push(d);
    }
    Ok(())
}

/// Offer `pci` to driver `i` (a crash in it is pinned on its module).
fn take(k: &mut Kernel, i: usize, pci: PciAddr, options: &str) -> Option<Device> {
    let (d, by) = &mut k.drivers[i];
    let before = crate::modules::set_current_native(Some(by.name));
    let r = d.probe(drivers::HW, pci, options);
    crate::modules::set_current_native(before);
    r
}

/// The installed modules that provide services, for `module_list`.
pub fn running(k: &Kernel) -> Vec<ModuleInfo> {
    let mut out: Vec<ModuleInfo> = Vec::new();
    for by in providers(k) {
        if by.name != BOOT && !out.iter().any(|m| m.name == by.name) {
            out.push(ModuleInfo {
                name: String::from(by.name),
                native_bytes: None,
                wasm_bytes: None,
                preferred: ModuleKind::Native,
                running: Some(ModuleKind::Native),
                state: String::from("service"),
                restarts: 0,
                native_off: None,
                params: Vec::new(),
                version: String::from(by.version),
            });
        }
    }
    out
}
