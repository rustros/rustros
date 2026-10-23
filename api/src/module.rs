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

use crate::sys::{KvError, Module, StorageInfo};

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
    /// The boot disk's services (a boot module's).
    Storage(Box<dyn Storage>),
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

impl<T: Disk + ?Sized> Disk for Box<T> {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        (**self).read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        (**self).write(lba, buf)
    }
    fn sectors(&self) -> u64 {
        (**self).sectors()
    }
    fn read_only(&self) -> bool {
        (**self).read_only()
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
    /// base class (1 mass storage, 2 network, ...)
    pub class: u8,
}

/// Where a device's interrupt status register is: reading it acknowledges
/// a legacy interrupt.
#[derive(Clone, Copy)]
pub enum IrqAck {
    Mmio(usize),
    Port(u16),
}

/// What a driver needs from the kernel besides the device itself (port I/O
/// and identity-mapped memory it has: it runs in the kernel).
pub trait Hw: Sync {
    /// Map a device's registers (uncached); false if they cannot be.
    fn map_device(&self, phys: u64, len: u64) -> bool;
    fn now_ms(&self) -> u64;
    /// TSC ticks per millisecond (short waits by `rdtsc`).
    fn tsc_per_ms(&self) -> u64;
    /// A line for the console.
    fn log(&self, line: &str);
    /// (local APIC id, vector) for message-signalled interrupts that wake
    /// the CPU, if it has an APIC.
    fn msi(&self) -> Option<(u8, u8)>;
    /// Wake the CPU on legacy interrupt `line`, acknowledged by reading
    /// `ack`; false if the line is unusable.
    fn route_irq(&self, line: u8, ack: IrqAck) -> bool;
}

/// A device driver. Drivers come with the kernel (boot modules) and are
/// offered the PCI functions at boot: disks first (before the storage
/// service opens), NICs after it (their settings may be in grubenv).
pub trait Driver {
    fn name(&self) -> &'static str;
    /// Drive `dev` if it is this driver's kind of device. `options`: settings
    /// as on the command line ("offload=off").
    fn probe(&mut self, hw: &'static dyn Hw, dev: PciAddr, options: &str) -> Option<Device>;
}

/// The boot disk's services: grubenv and the kernel slots, the system
/// key-value store, the console log kept on disk, the files partition. A
/// boot module provides it; the kernel calls it for the system calls.
pub trait Storage {
    /// Take the boot disk among `disks` (the one with the slots the command
    /// line names) and open what is on it (progress to `hw.log`).
    fn open(&mut self, hw: &'static dyn Hw, cmdline: &str, disks: Vec<Box<dyn Disk>>, seed: u64) -> Result<(), String>;

    /// The slot running ('a' or 'b'), and whether this is its trial boot.
    fn slot(&self) -> (char, bool);
    /// How big a kernel image a slot takes.
    fn slot_bytes(&self) -> u64;
    /// grubenv
    fn env(&self, key: &str) -> Option<&str>;
    fn env_vars(&self) -> Vec<(String, String)>;
    /// Set several (an empty value removes one) in one write.
    fn env_set(&mut self, vars: &[(&str, &str)]) -> bool;
    /// A new kernel into the other slot: begin, write the image in pieces,
    /// commit (the next boot tries it); `confirm` keeps the slot on trial.
    fn update_begin(&mut self) -> bool;
    fn update_write(&mut self, data: &[u8]) -> bool;
    fn update_commit(&mut self) -> bool;
    fn confirm(&mut self) -> bool;

    /// The system key-value store (full keys, with the app's prefix).
    fn kv_get(&self, key: &str) -> Option<&[u8]>;
    fn kv_keys(&self, prefix: &str) -> Vec<String>;
    fn kv_put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError>;
    fn kv_delete(&mut self, key: &str) -> Result<bool, KvError>;
    fn kv_info(&self) -> Option<StorageInfo>;

    /// Console output for this boot's log on disk.
    fn log_write(&mut self, text: &[u8]);
    /// This boot's number in the log.
    fn log_seq(&self) -> Option<u64>;
    /// Boots with a log: (boot number, bytes).
    fn log_list(&mut self) -> Vec<(u64, u64)>;
    fn log_read(&mut self, seq: u64) -> Option<Vec<u8>>;

    /// Call `f` with the files partition (false: there is none).
    fn files(&mut self, f: &mut dyn FnMut(&mut dyn Disk)) -> bool;
    /// Sectors of the ESP (only there) and of the boot area below 64 MiB.
    fn esp_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>>;
    fn esp_write(&mut self, lba: u64, data: &[u8]) -> bool;
    fn boot_area_read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
    /// Write sectors of the boot area that no partition holds.
    fn boot_area_write(&mut self, lba: u64, data: &[u8]) -> bool;
    /// Make `[first, last]` (free, in the boot area, starting with a FAT
    /// boot sector) the EFI partition: the GPT entry is all that changes.
    fn esp_move(&mut self, first: u64, last: u64) -> Result<(), String>;
}

/// A device a driver drives.
pub enum Device {
    Block(Box<dyn Disk>),
    Net(Box<dyn NetDevice>),
}

// ---------------------------------------------------------------- network devices

use crate::{HEADROOM, Offload};

/// A packet buffer: HEADROOM, then up to 2048 bytes of frame.
pub const BUF_SIZE: usize = HEADROOM + 2048;
/// Packet buffers are handed between the kernel and the drivers instead of
/// copying what is in them. Most are BUF_SIZE; one holding a big segment
/// (offloads) is as big as that, and only lives while it is in flight.
pub type Buf = alloc::boxed::Box<[u8]>;

pub fn new_buf() -> Buf {
    alloc::vec![0u8; BUF_SIZE].into_boxed_slice()
}

/// A buffer for a frame of `len` bytes (HEADROOM in front).
pub fn buf_for(len: usize) -> Buf {
    alloc::vec![0u8; (HEADROOM + len).max(BUF_SIZE)].into_boxed_slice()
}

/// Counters of a NIC, kept by its driver (all traffic, forwarded too).
#[derive(Clone, Copy, Default, Debug)]
pub struct DevStats {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    /// frames not sent: the TX ring stayed full
    pub tx_full: u64,
    /// times the TX ring was full and the driver waited for room
    pub tx_wait: u64,
    /// times the RX ring was found completely full (the host drops then)
    pub rx_full: u64,
    /// unicast frames for other MACs, dropped on arrival
    pub rx_foreign: u64,
}

/// An Ethernet interface.
pub trait NetDevice {
    fn stats(&self) -> DevStats {
        DevStats::default()
    }
    fn mac(&self) -> [u8; 6];
    /// Transmit one frame (without FCS). False if the device is busy.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// Copy the next received frame into `buf`; returns its length.
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize>;
    /// Short description for the boot log.
    fn kind(&self) -> &'static str;
    /// Zero-copy receive: the next frame ends up in `buf` (at HEADROOM;
    /// its length and pending offloads are returned) and the driver keeps
    /// the buffer that was there.
    fn recv_swap(&mut self, buf: &mut Buf) -> Option<(usize, Offload)> {
        self.recv(&mut buf[HEADROOM..]).map(|n| (n, Offload::default()))
    }
    /// Zero-copy send of `buf[start..start + len]`: the driver keeps the
    /// buffer until the device is done with it and leaves a spare one in
    /// `buf`. False if the device is busy (`buf` is then unchanged).
    /// `offload` only if `tx_offloads()`.
    fn send_swap(&mut self, buf: &mut Buf, start: usize, len: usize, _offload: Offload) -> bool {
        self.send(&buf[start..start + len])
    }
    /// The device completes partial checksums and cuts big TCP segments.
    fn tx_offloads(&self) -> bool {
        false
    }
    /// Tell the device about frames sent and buffers returned since the last
    /// flush (`send`/`recv` batch their notifications, which are expensive
    /// under a hypervisor). Call after each batch.
    fn flush(&mut self) {}
    /// A received frame is waiting.
    fn rx_pending(&self) -> bool {
        false
    }
    /// Interrupt on received frames (before sleeping) or not (while polling).
    fn rx_interrupts(&mut self, _on: bool) {}
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
