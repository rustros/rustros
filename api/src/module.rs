//! Loadable native modules and application runtimes.
//!
//! A native module is a position-independent ELF built for
//! `x86_64-unknown-none` (see `modules/`). The kernel copies it into memory,
//! applies its relative relocations and calls `rustros_module_init`:
//!
//! ```text
//! extern "C" fn rustros_module_init(host: *const HostTable, out: *mut Option<Export>) -> u64
//! ```
//!
//! Only plain C values cross until both sides have checked that their
//! `API_FINGERPRINT`s match; after that they talk through Rust trait objects
//! (`Box<dyn Module>`, `&mut dyn Sys`), with no copying or marshalling. Native
//! modules are trusted code: they run in the kernel's address space.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sys::{KvError, Module};

pub const ENTRY: &str = "rustros_module_init";

/// What the kernel gives a module. The module routes its heap through these
/// so that boxes may be freed on either side.
#[repr(C)]
pub struct HostTable {
    pub fingerprint: u64,
    pub alloc: extern "C" fn(size: usize, align: usize) -> *mut u8,
    pub dealloc: extern "C" fn(ptr: *mut u8, size: usize, align: usize),
    pub realloc: extern "C" fn(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8,
    /// Fatal error in the module (its panic handler): record and reboot.
    pub crash: extern "C" fn(msg: *const u8, len: usize) -> !,
}

/// What a module provides.
pub enum Export {
    Module(Box<dyn Module>),
    /// Runs applications in another format (the WebAssembly runtime).
    Runtime(Box<dyn Runtime>),
    /// Several things from one binary (sharing its code): the boot modules.
    Many(Vec<Export>),
    /// A device driver ("virtio-blk"): the kernel offers it the PCI functions.
    Driver(Box<dyn Driver>),
    /// A file system driver ("ext4", "xfs", ...): the kernel mounts the
    /// files partition with the one that recognises it.
    Filesystem(Box<dyn Filesystem>),
}

/// A file system driver, a module of its own. The kernel lends it the files
/// partition's sectors; apps reach the mounted file system through `Kv`'s
/// file calls (each in its own directory). Paths are from its root.
pub trait Filesystem {
    /// The file system's name: "ext4", "xfs", ...
    fn name(&self) -> &'static str;
    /// The release this driver is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    /// Whether `disk` holds this file system.
    fn probe(&mut self, disk: &mut dyn Disk) -> bool;
    /// Make an empty one on `disk` (the kernel asks only for a blank partition).
    fn format(&mut self, disk: &mut dyn Disk, uuid: [u8; 16], now: u32) -> Result<(), String>;
    /// Mount it (a line for the log).
    fn mount(&mut self, disk: &mut dyn Disk, now: u32) -> Result<String, String>;
    /// (total, used) bytes of the mounted file system.
    fn usage(&self) -> (u64, u64);
    /// Create or replace a whole file (the directories above it are made).
    fn put(&mut self, disk: &mut dyn Disk, path: &str, data: &[u8], now: u32) -> Result<(), KvError>;
    /// Bytes of a file from `offset`: how many (0 at its end).
    fn read(&mut self, disk: &mut dyn Disk, path: &str, offset: u64, buf: &mut [u8]) -> Option<usize>;
    /// (size, modification time, directory)
    fn stat(&mut self, disk: &mut dyn Disk, path: &str) -> Option<(u64, u64, bool)>;
    /// A directory's entries: (name, size, directory).
    fn list(&mut self, disk: &mut dyn Disk, path: &str) -> Option<Vec<(String, u64, bool)>>;
    /// Remove a file or an empty directory; false if there was none.
    fn remove(&mut self, disk: &mut dyn Disk, path: &str, now: u32) -> bool;
    /// Everything to the disk, the file system marked clean (a planned restart).
    fn close(&mut self, disk: &mut dyn Disk);
}

/// A disk addressed in 512-byte sectors: one a driver drives, or sectors
/// the kernel lends a module (LBAs count from their start).
pub trait Disk {
    /// `buf.len()` bytes (a multiple of 512) from sector `lba`.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
    /// Durable when it returns true.
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool;
    fn sectors(&self) -> u64;
    fn read_only(&self) -> bool {
        false
    }
}

/// A PCI function the kernel found.
#[derive(Clone, Copy)]
pub struct PciAddr {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
}

/// What a driver needs from the kernel besides the device itself (port I/O
/// and identity-mapped memory it has: it runs in the kernel).
pub trait Hw: Sync {
    /// Map a device's registers (uncached); false if they cannot be.
    fn map_device(&self, phys: u64, len: u64) -> bool;
    fn now_ms(&self) -> u64;
    /// A line for the console.
    fn log(&self, line: &str);
}

/// A device driver. Drivers come with the kernel (boot modules) and are
/// offered the PCI functions at boot, before anything uses a disk.
pub trait Driver {
    fn name(&self) -> &'static str;
    /// Drive `dev` if it is this driver's kind of device.
    fn probe(&mut self, hw: &'static dyn Hw, dev: PciAddr) -> Option<Device>;
}

/// A device a driver drives.
pub enum Device {
    Block(Box<dyn Disk>),
}

/// An application runtime: turns application images of its format into apps.
pub trait Runtime {
    /// Short name of the format ("wasm").
    fn format(&self) -> &'static str;
    /// Whether `image` is in this runtime's format (magic number check).
    fn accepts(&self, image: &[u8]) -> bool;
    /// Full check of an image before it is stored.
    fn validate(&self, image: &[u8]) -> Result<(), String>;
    /// A new app instance called `name` running `image`.
    fn instantiate(&mut self, name: &'static str, image: &[u8]) -> Result<Box<dyn Module>, String>;
}
