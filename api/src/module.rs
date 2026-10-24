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
    /// `at` is an address inside the module, so the crash is pinned on it.
    pub crash: extern "C" fn(msg: *const u8, len: usize, at: usize) -> !,
}

/// What a module provides.
///
/// The services (`Driver`, `Storage`, `NetStack`, `Manager`) come with the
/// kernel in the boot modules' binary, and each can be replaced while the
/// system runs by an installed module exporting the same kind of service
/// (hot replacement). Between two main-loop passes no call is in flight; the
/// kernel then moves the old version's state to the new one: the old one
/// writes it in a format both read (each says the newest it reads,
/// `state_version`; every version reads all older formats), the new one
/// takes it over. If that fails the old one stays, with its state intact.
/// Drivers hand nothing over: their devices are reset and the new driver
/// takes them again (the link drops for a moment).
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
    /// The system's network stack (a boot module's).
    NetStack(Box<dyn NetStack>),
    /// The installed modules' bookkeeping (a boot module's).
    Manager(Box<dyn ModManager>),
    /// The system calls of user-mode processes (the Linux compatibility
    /// layer, an installed module).
    Syscalls(Box<dyn Syscalls>),
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
#[derive(Clone, Copy, PartialEq, Eq)]
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
/// service opens), NICs after it (their settings may be in grubenv). A
/// driver of the same name replacing it while the system runs is offered
/// the same devices again, after they were reset.
pub trait Driver {
    fn name(&self) -> &'static str;
    /// The release this version is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    /// Drive `dev` if it is this driver's kind of device. `options`: settings
    /// as on the command line ("offload=off").
    fn probe(&mut self, hw: &'static dyn Hw, dev: PciAddr, options: &str) -> Option<Device>;
}

/// The boot disk's services: grubenv and the kernel slots, the system
/// key-value store, the console log kept on disk, the files partition. A
/// boot module provides it; the kernel calls it for the system calls.
pub trait Storage {
    /// The release this version is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    /// Take the boot disk out of `disks` (the one with the slots the command
    /// line names) and open what is on it (progress to `hw.log`). `state`:
    /// carry on from another version's (hot replacement) instead of
    /// starting this boot's log. On failure `disks` is left as it was.
    fn open(&mut self, hw: &'static dyn Hw, cmdline: &str, disks: &mut Vec<Box<dyn Disk>>, seed: u64, state: Option<&[u8]>) -> Result<(), String>;
    /// The newest state format this version reads (0: none).
    fn state_version(&self) -> u32;
    /// Something that must not be cut short is going on (a kernel image
    /// being written to a slot): a replacement waits for it.
    fn busy(&self) -> bool;
    /// Let go of the boot disk for a replacement: it goes into `disks`, the
    /// state (format `version`) is returned. None (this version cannot
    /// write that format): nothing changed.
    fn hand_over(&mut self, version: u32, disks: &mut Vec<Box<dyn Disk>>) -> Option<Vec<u8>>;

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

// ---------------------------------------------------------------- network stack

use crate::socket::{Epoll, EpollEvent, SockAddr, SockResult, Socket};
use crate::sys::{ConnInfo, Ip, NetConf, NetInfo};

/// What the network stack needs from the kernel.
pub trait Link {
    fn now_ms(&self) -> u64;
    /// Transmit one Ethernet frame (without FCS) on interface `nic`. False
    /// if it cannot be queued.
    fn send(&mut self, nic: usize, frame: &[u8]) -> bool;
    /// Not cryptographically strong; fine for ISNs and port numbers.
    fn random(&mut self) -> u64;
    /// Socket `sock` of `owner` changed: `events` (EPOLL* bits) say what
    /// just happened (an edge: new data is EPOLLIN again, even on a socket
    /// that was readable). Called at the moment of the change, from inside
    /// the stack: the kernel only records it (it must not call back into
    /// the stack) and wakes the waiters afterwards.
    fn notify(&mut self, owner: usize, sock: Socket, events: u32);
}

/// The system's network stack (Ethernet, ARP, IPv4, ICMP, UDP, TCP) and the
/// sockets the applications have in it, by owner (the application's id).
/// The kernel feeds it the frames for us and sends what it sends; a boot
/// module provides it.
pub trait NetStack {
    /// The release this version is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    /// One received frame (plain: no offloads pending) from interface `nic`.
    fn input(&mut self, link: &mut dyn Link, nic: usize, frame: &[u8]);
    /// Timers, retransmissions, packets to ourselves. Returns a line for the
    /// log when packets to ourselves used the whole budget (a storm).
    fn poll(&mut self, link: &mut dyn Link) -> Option<String>;

    /// The NICs' MACs: interface `i < macs.len()` is NIC `i`, VLAN
    /// interfaces follow.
    fn set_nics(&mut self, macs: Vec<[u8; 6]>);
    /// The configuration in effect: the interfaces in order (what each is:
    /// `phys`, `vlan`) and the static routes.
    fn config(&self) -> NetConf;
    /// Put a whole configuration in effect (it lists the NICs, and the VLAN
    /// interfaces to have): interfaces that stay keep their ARP cache
    /// unless their addresses change.
    fn set_config(&mut self, conf: &NetConf) -> Result<(), String>;
    /// The configuration being edited (not in effect).
    fn candidate(&self) -> Option<NetConf>;
    fn set_candidate(&mut self, conf: Option<NetConf>);
    /// The candidate into effect; unless confirmed within `seconds` (0: no
    /// limit) it is reverted (`tick`). The revert point is what ran before
    /// the first apply.
    fn apply(&mut self, now: u64, seconds: u32) -> Result<(), String>;
    /// Back to the revert point; Ok(false) if nothing was applied.
    fn revert(&mut self) -> Result<bool, String>;
    /// Stop the revert timer; false if none ran.
    fn confirm(&mut self) -> bool;
    /// Revert if applied, and drop the candidate.
    fn discard(&mut self);
    /// Seconds before an applied candidate is reverted.
    fn pending(&self, now: u64) -> Option<u64>;
    /// Whether what runs differs from the revert point.
    fn applied(&self) -> bool;
    /// Revert an applied candidate whose time is up; a line for the log.
    fn tick(&mut self, now: u64) -> Option<String>;
    /// The configuration to boot with for `nics` NICs, from the kernel
    /// command line and grubenv (`env`), and the lines for the boot log.
    fn boot_config(&self, nics: usize, cmdline: &str, env: &dyn Fn(&str) -> Option<String>) -> (NetConf, Vec<String>);
    /// The grubenv variables that make what runs the boot configuration
    /// (`net save`; it ends the apply/revert round).
    fn save(&mut self) -> Vec<(String, String)>;
    /// Application names by owner (connection listings).
    fn set_owner_names(&mut self, names: Vec<&'static str>);
    /// Drop everything `owner` holds (it was stopped or crashed).
    fn release_owner(&mut self, owner: usize, link: &mut dyn Link);

    fn nic_info(&self, nic: usize) -> Option<NetInfo>;
    /// (address, MAC, age in ms)
    fn arp_table(&self, now: u64) -> Vec<(Ip, [u8; 6], u64)>;
    fn connections(&self) -> Vec<ConnInfo>;

    /// (interface, next hop) towards `dst`, for a packet from `src` (0: any).
    fn route_from(&self, src: Ip, dst: Ip) -> Option<(usize, Ip)>;
    /// MAC of `ip` on interface `nic`; None (asking ARP) if not known yet.
    fn neighbor(&mut self, link: &mut dyn Link, nic: usize, ip: Ip) -> Option<[u8; 6]>;
    /// Route and send a finished IPv4 packet (its source left alone).
    fn send_packet(&mut self, link: &mut dyn Link, packet: &[u8]) -> bool;

    /// The newest state format this version reads (0: none).
    fn state_version(&self) -> u32;
    /// Everything (configuration, interfaces with their ARP caches, sockets
    /// with their TCP connections, buffers and timers, epoll instances) in
    /// format `version`; None if this version cannot write it.
    fn save_state(&self, version: u32) -> Option<Vec<u8>>;
    /// Take over another version's state, before any other call.
    fn load_state(&mut self, state: &[u8]) -> Result<(), String>;

    // Sockets with Linux semantics (crate::socket), by owner. Every change
    // of a socket's readiness is reported through `Link::notify`.
    fn socket(&mut self, owner: usize, domain: i32, ty: i32, protocol: i32) -> SockResult<Socket>;
    fn bind(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()>;
    fn listen(&mut self, owner: usize, link: &mut dyn Link, s: Socket, backlog: i32) -> SockResult<()>;
    fn accept(&mut self, owner: usize, link: &mut dyn Link, s: Socket, flags: i32) -> SockResult<(Socket, SockAddr)>;
    fn connect(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()>;
    fn sendto(&mut self, owner: usize, link: &mut dyn Link, s: Socket, data: &[u8], flags: i32, to: Option<&SockAddr>) -> SockResult<usize>;
    fn recvfrom(&mut self, owner: usize, link: &mut dyn Link, s: Socket, buf: &mut [u8], flags: i32) -> SockResult<(usize, Option<SockAddr>)>;
    fn shutdown(&mut self, owner: usize, link: &mut dyn Link, s: Socket, how: i32) -> SockResult<()>;
    fn close(&mut self, owner: usize, link: &mut dyn Link, s: Socket) -> SockResult<()>;
    fn getsockname(&self, owner: usize, s: Socket) -> SockResult<SockAddr>;
    fn getpeername(&self, owner: usize, s: Socket) -> SockResult<SockAddr>;
    fn setsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &[u8]) -> SockResult<()>;
    fn getsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &mut [u8]) -> SockResult<usize>;
    fn ioctl(&mut self, owner: usize, s: Socket, request: u32, arg: u64) -> SockResult<u64>;
    /// Readiness now (EPOLL* bits) and the event counter.
    fn sock_poll(&self, owner: usize, s: Socket) -> SockResult<(u32, u64)>;
    /// Epoll instances over the owner's sockets: the stack puts a socket on
    /// their ready lists at the moment it changes.
    fn epoll_create(&mut self, owner: usize) -> SockResult<Epoll>;
    fn epoll_ctl(&mut self, owner: usize, ep: Epoll, op: i32, s: Socket, events: u32, data: u64) -> SockResult<()>;
    fn epoll_wait(&mut self, owner: usize, ep: Epoll, out: &mut [EpollEvent]) -> SockResult<usize>;
    fn epoll_close(&mut self, owner: usize, ep: Epoll) -> SockResult<()>;
}

// ---------------------------------------------------------------- module manager

use crate::sys::{ModuleInfo, ModuleKind};

/// The WebAssembly runtime is the native module installed under this name.
pub const RUNTIME: &str = "wasm";
/// Module roles (`ModHost::role`).
pub const ROLE_SERVICE: &str = "service";
pub const ROLE_FS: &str = "fs";

/// What the module manager asks the kernel to do with a module.
pub enum ModOp {
    /// (Re)start it in its preferred available form (`ModManager::choose`).
    Start(String),
    Stop(String),
}

/// What the module manager gets from the kernel.
pub trait ModHost {
    /// The boot disk's services (the store the modules are kept in).
    fn store(&mut self) -> Option<&mut dyn Storage>;
    fn cmdline(&self) -> &str;
    /// A line for the console and the boot log.
    fn log(&mut self, line: &str);
    /// What `image` is, if the system can run it: a native module, or a
    /// format the runtime takes (checked by it).
    fn check(&self, image: &[u8]) -> Result<ModuleKind, String>;
    /// What a native module is besides an app (it is loaded to see):
    /// `ROLE_SERVICE` (it replaces services: started before anything else)
    /// or `ROLE_FS` (a file system driver: started next).
    fn role(&self, image: &[u8]) -> Option<&'static str>;
    fn has_runtime(&self) -> bool;
    fn is_builtin(&self, name: &str) -> bool;
    fn is_running(&self, name: &str) -> bool;
}

/// The installed modules: how they are stored, which form runs, what starts
/// at boot. The kernel runs them (loading, the app table, crash attribution)
/// and applies the operations queued here between main loop passes.
pub trait ModManager {
    /// The release this version is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    fn install(&mut self, host: &mut dyn ModHost, name: &str, image: &[u8]) -> Result<ModuleKind, String>;
    /// Both forms (`kind` None) or one.
    fn remove(&mut self, host: &mut dyn ModHost, name: &str, kind: Option<ModuleKind>) -> bool;
    fn switch(&mut self, host: &mut dyn ModHost, name: &str, kind: ModuleKind) -> Result<(), String>;
    /// The installed modules, with what `running` (the kernel's) says of
    /// those that run.
    fn list(&self, host: &mut dyn ModHost, running: Vec<ModuleInfo>) -> Vec<ModuleInfo>;
    /// A module's settings (`cfg <module> <key> <value>`).
    fn config(&self, host: &mut dyn ModHost, name: &str) -> Vec<(String, String)>;
    fn config_set(&mut self, host: &mut dyn ModHost, name: &str, key: &str, value: Option<&str>) -> Result<(), String>;
    /// At boot (not in safe mode): queue every installed module.
    fn boot(&mut self, host: &mut dyn ModHost);
    /// The next queued operation.
    fn next_op(&mut self) -> Option<ModOp>;
    /// The form to run `name` in, and its image (`RUNTIME`: native only).
    fn choose(&mut self, host: &mut dyn ModHost, name: &str) -> Option<(ModuleKind, Vec<u8>)>;
    /// `name` turned out to be a file system driver (it starts first from now on).
    fn is_filesystem(&mut self, host: &mut dyn ModHost, name: &str);
    /// The runtime changed: `stopped` (its instances) and every installed
    /// module not running get another chance.
    fn runtime_changed(&mut self, host: &mut dyn ModHost, stopped: Vec<String>);
    /// The newest state format this version reads (0: none).
    fn state_version(&self) -> u32;
    /// The queued operations, in format `version`.
    fn save_state(&self, version: u32) -> Option<Vec<u8>>;
    fn load_state(&mut self, state: &[u8]) -> Result<(), String>;
}

// ---------------------------------------------------------------- user-mode processes

/// What a system call returns to the kernel.
pub enum Sysret {
    /// The value for the caller's rax (a negative errno for an error).
    Value(i64),
    /// The caller has to wait for something to happen to it (a child
    /// ended): the kernel makes the same call again then.
    Wait,
    /// The caller ended (`ProcHost::exit`).
    Exit,
}

/// What a system call implementation gets from the kernel: the calling
/// process and the kernel's mechanisms (the process table, address spaces,
/// the console). Addresses are the caller's.
pub trait ProcHost {
    fn pid(&self) -> u32;
    fn ppid(&self) -> u32;
    /// Copy from / to the caller's memory; false on a bad address.
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool;
    fn write(&mut self, addr: u64, data: &[u8]) -> bool;
    /// Output for the console (fd 1 and 2 until there are files).
    fn console(&mut self, data: &[u8]);
    /// The caller ends with `status` (as wait reports it).
    fn exit(&mut self, status: i32);
    /// A copy of the caller (its memory shared copy-on-write); the child's
    /// pid. The child returns from the call with 0.
    fn fork(&mut self) -> Result<u32, i32>;
    /// A child that ended (`pid` -1: any), reaped: (pid, status). Ok(None):
    /// none yet; Err(errno): no such child.
    fn wait(&mut self, pid: i32) -> Result<Option<(u32, i32)>, i32>;
    /// Anonymous memory (zero-filled on first touch): `len` bytes with
    /// `prot` (PROT_READ 1, PROT_WRITE 2, PROT_EXEC 4) at `addr` (0: the
    /// kernel picks; `fixed`: exactly there, replacing what was); where.
    fn map(&mut self, addr: u64, len: u64, prot: u32, fixed: bool) -> Result<u64, i32>;
    fn unmap(&mut self, addr: u64, len: u64) -> Result<(), i32>;
    /// Move the end of the heap (0: ask); where it is now.
    fn brk(&mut self, addr: u64) -> u64;
    /// The thread pointer (FS base).
    fn set_fs(&mut self, base: u64);
    /// Monotonic and wall-clock time, in ns.
    fn now_ns(&self) -> u64;
    fn unix_ns(&self) -> u64;
}

/// The system calls of user-mode processes. The kernel only takes the
/// `syscall` and hands it here (number and arguments as on Linux x86-64);
/// what the calls do is this module's. Process state lives in the kernel,
/// so the module can be replaced while processes run.
pub trait Syscalls {
    /// The release this version is from (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
    fn syscall(&mut self, host: &mut dyn ProcHost, nr: u64, args: [u64; 6]) -> Sysret;
}
