//! The interface between RustROS and its applications.
//!
//! Several applications run side by side. The system owns the network stack
//! and hands out non-blocking sockets; there are no threads, so every call
//! returns immediately (`Err(NetError::WouldBlock)` when there is nothing to do)
//! and applications are polled state machines.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::frame::{Frame, Offload};

/// IPv4 address in host byte order.
pub type Ip = u32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketAddr {
    pub ip: Ip,
    pub port: u16,
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = self.ip.to_be_bytes();
        write!(f, "{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], self.port)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetError {
    /// Nothing to receive / no buffer space right now; try again later.
    WouldBlock,
    /// Port already bound or listened on.
    AddrInUse,
    /// Unknown handle, or one that belongs to another application.
    BadHandle,
    /// The connection is gone (reset, timed out or closed by us).
    Closed,
    /// Datagram larger than one Ethernet frame.
    TooLarge,
    /// No address configured or no route to the destination.
    NoRoute,
}

/// Socket handles: opaque values issued by the system. A forged value is
/// harmless; the system checks every handle against its owner.
macro_rules! handle {
    ($($name:ident),*) => {$(
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $name(u64);
        impl $name {
            pub fn to_raw(self) -> u64 {
                self.0
            }
            pub fn from_raw(raw: u64) -> Self {
                $name(raw)
            }
        }
    )*};
}
handle!(UdpSocket, TcpListener, TcpStream, RawSocket);

/// The two forms an installed application can take; the same code builds as
/// either.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModuleKind {
    /// Loadable native module: full speed, no isolation.
    Native,
    /// WebAssembly: isolated (a crash only restarts the app), slower.
    Wasm,
}

impl ModuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleKind::Native => "native",
            ModuleKind::Wasm => "wasm",
        }
    }
    pub fn parse(s: &str) -> Option<ModuleKind> {
        match s {
            "native" => Some(ModuleKind::Native),
            "wasm" => Some(ModuleKind::Wasm),
            _ => None,
        }
    }
}

/// A setting a module takes (`cfg <module> <key> <value>`), described for
/// user interfaces, which build their forms from these (see `Module::params`).
///
/// `key` is a pattern: `<x>` stands for a name the user picks, an instance
/// when more follows (`<i>.listen`) or an entry of a table when it ends the
/// key (`user.<name>`); `[<i>.]` is an optional instance prefix (without
/// it: the default instance). A placeholder at the end may contain dots.
///
/// `kind`: text, number, switch (on/off), secret (a password: never shown),
/// choice:a|b|c, address (a.b.c.d or an interface), network (a.b.c.d/n),
/// list (comma separated).
#[derive(Clone, Copy)]
pub struct Param {
    pub key: &'static str,
    pub kind: &'static str,
    /// What applies when it is not set ("" for nothing).
    pub default: &'static str,
    pub help: &'static str,
}

/// `Param`, owned (it outlives the module that described it).
#[derive(Clone, Debug, Default)]
pub struct ParamInfo {
    pub key: String,
    pub kind: String,
    pub default: String,
    pub help: String,
}

impl From<&Param> for ParamInfo {
    fn from(p: &Param) -> ParamInfo {
        ParamInfo { key: String::from(p.key), kind: String::from(p.kind), default: String::from(p.default), help: String::from(p.help) }
    }
}

/// An installed (not built-in) application.
pub struct ModuleInfo {
    pub name: String,
    /// Sizes of the stored images.
    pub native_bytes: Option<usize>,
    pub wasm_bytes: Option<usize>,
    /// The form to run when both are available.
    pub preferred: ModuleKind,
    /// The form running now.
    pub running: Option<ModuleKind>,
    pub state: String,
    pub restarts: u32,
    /// The native form crashed the system and is switched off (with why).
    pub native_off: Option<String>,
    /// The settings the running module takes (empty if it does not say).
    pub params: Vec<ParamInfo>,
    /// The release the running module was built for ("" if not running).
    pub version: String,
}

pub struct NetInfo {
    pub mac: [u8; 6],
    pub ip: Ip,
    pub mask: Ip,
    pub gw: Ip,
    pub mtu: usize,
    pub rx: u64,
    pub tx: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// One interface's settings: a NIC (`vlan` None), or a VLAN on one.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IfConf {
    pub phys: u8,
    pub vlan: Option<u16>,
    pub ip: Ip,
    pub mask: Ip,
    pub gw: Ip,
    pub mtu: u16,
    /// extra addresses, sorted
    pub extra: Vec<Ip>,
}

/// A static route: `net/mask` via `gw` (which must be on a connected
/// network), for packets from `src/src_mask` only (mask 0: from anywhere).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RouteConf {
    pub net: Ip,
    pub mask: Ip,
    pub gw: Ip,
    pub src: Ip,
    pub src_mask: Ip,
}

/// The whole network configuration: interfaces (the NICs in order, then
/// the VLANs) and static routes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NetConf {
    pub ifs: Vec<IfConf>,
    pub routes: Vec<RouteConf>,
}

impl IfConf {
    /// "nic0", "nic0.109"
    pub fn name(&self) -> String {
        match self.vlan {
            None => alloc::format!("nic{}", self.phys),
            Some(v) => alloc::format!("nic{}.{}", self.phys, v),
        }
    }
}

pub struct ConnInfo {
    pub local_port: u16,
    pub remote: SocketAddr,
    pub state: &'static str,
    pub owner: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KvError {
    /// No data partition (no boot disk found, or no space on it).
    NoStorage,
    /// Empty or too long key (max 255 bytes with the app prefix), or value over 1 MiB.
    TooLarge,
    /// The store is full.
    Full,
    /// Disk error.
    Io,
}

pub struct StorageInfo {
    /// Data partition size in bytes.
    pub partition_bytes: u64,
    /// Part of it used by the key-value store.
    pub store_bytes: u64,
    /// Live keys and values, all applications.
    pub live_bytes: u64,
    /// Log space used in the active half.
    pub log_bytes: u64,
}

pub struct UpdateInfo {
    /// Slot we are running from ('a' or 'b').
    pub slot: char,
    /// This boot is a trial of a freshly uploaded kernel; call
    /// [`Admin::confirm_boot`] or the kernel reboots back to the old slot.
    pub trial: bool,
    /// Maximum kernel image size in bytes.
    pub max_bytes: u64,
    /// Boots in a row (this one included) that did not run stable for two
    /// minutes; 1 is normal.
    pub unstable_boots: u32,
    /// Safe mode (the third unstable boot): installed modules were not
    /// started; fix them and reboot.
    pub safe_mode: bool,
}

/// Keys `Module::key` gets beyond ASCII (from PS/2 and serial cursor keys).
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_HOME: u8 = 0x84;
pub const KEY_END: u8 = 0x85;
pub const KEY_DELETE: u8 = 0x86;

/// Capabilities an application can be granted (see `Module::caps`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Caps(u32);

impl Caps {
    pub const NONE: Caps = Caps(0);
    /// Sockets and network status.
    pub const NET: Caps = Caps(1);
    /// Its own key-value namespace.
    pub const KV: Caps = Caps(2);
    /// Raw frames and the zero-copy packet path (`Module::on_frames`).
    pub const PACKET: Caps = Caps(4);
    /// Reboot, network configuration, kernel updates, module management.
    pub const ADMIN: Caps = Caps(8);
    /// Keyboard/serial input: the console's owner (the newest running module
    /// with this capability, else the built-in rescue console) gets the keys.
    pub const CONSOLE: Caps = Caps(16);

    pub fn contains(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn bits(self) -> u32 {
        self.0
    }
    pub fn from_bits(bits: u32) -> Caps {
        Caps(bits & 31)
    }
}

impl core::ops::BitOr for Caps {
    type Output = Caps;
    fn bitor(self, o: Caps) -> Caps {
        Caps(self.0 | o.0)
    }
}

impl core::ops::BitAnd for Caps {
    type Output = Caps;
    fn bitand(self, o: Caps) -> Caps {
        Caps(self.0 & o.0)
    }
}

/// What every interface offers: time, logging, (non-cryptographic) random.
pub trait Base {
    /// Milliseconds since boot.
    fn now_ms(&self) -> u64;
    /// Microseconds since boot (shapers and timers that need it finer).
    fn now_us(&self) -> u64 {
        self.now_ms() * 1000
    }
    /// Seconds since 1970 (UTC), from the machine's real-time clock; 0 if
    /// unknown.
    fn unix_time(&self) -> u64 {
        0
    }
    /// Print to the console (serial + screen).
    fn print(&mut self, s: &str);
    /// Not cryptographically strong; fine for nonces and port numbers.
    fn random(&mut self) -> u64;
}

/// What the system offers an application. The capability accessors return
/// `None` unless the app asked for (`Module::caps`) and was granted that
/// capability.
pub trait Sys: Base {
    /// Kernel command line (from grub.cfg).
    fn cmdline(&self) -> &str;
    /// The running kernel's release (see `BUILD`).
    fn kernel_version(&self) -> &str {
        ""
    }
    /// Capabilities granted to this app.
    fn caps(&self) -> Caps;
    /// Names of all running applications.
    fn modules(&self) -> Vec<&'static str>;
    /// `None` when the boot disk was not found or slots are not configured.
    fn update_info(&self) -> Option<UpdateInfo>;
    /// Reason of the last crash (panic or CPU exception) recorded on the boot disk.
    fn last_crash(&self) -> Option<String>;

    fn net(&mut self) -> Option<&mut dyn Net>;
    fn kv(&mut self) -> Option<&mut dyn Kv>;
    fn packet(&mut self) -> Option<&mut dyn Packet>;
    fn admin(&mut self) -> Option<&mut dyn Admin>;
}

/// Sockets on the system's network stack, shared by all apps; every handle
/// belongs to the app that created it. Calls never block: they return
/// `Err(NetError::WouldBlock)` when there is nothing to do.
pub trait Net: Base {
    fn net_info(&self) -> NetInfo;
    /// (ip, mac, age in ms)
    fn arp_table(&self) -> Vec<(Ip, [u8; 6], u64)>;
    fn tcp_connections(&self) -> Vec<ConnInfo>;

    /// Bind a UDP port; 0 picks a free ephemeral port.
    fn udp_bind(&mut self, port: u16) -> Result<UdpSocket, NetError>;
    fn udp_local_port(&self, s: UdpSocket) -> Result<u16, NetError>;
    fn udp_send_to(&mut self, s: UdpSocket, to: SocketAddr, data: &[u8]) -> Result<(), NetError>;
    fn udp_recv_from(&mut self, s: UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError>;
    fn udp_close(&mut self, s: UdpSocket);

    fn tcp_listen(&mut self, port: u16) -> Result<TcpListener, NetError>;
    fn tcp_unlisten(&mut self, l: TcpListener);
    fn tcp_accept(&mut self, l: TcpListener) -> Result<(TcpStream, SocketAddr), NetError>;
    /// Connect out from an ephemeral port. Returns at once; data written before
    /// the handshake completes is sent afterwards. A refused or timed-out
    /// connection shows up as `Err(Closed)` on later calls.
    fn tcp_connect(&mut self, to: SocketAddr) -> Result<TcpStream, NetError>;
    /// Connect from our address `src` (an interface's or an extra one), routed by it.
    fn tcp_connect_from(&mut self, src: Ip, to: SocketAddr) -> Result<TcpStream, NetError> {
        if src == 0 { self.tcp_connect(to) } else { Err(NetError::NoRoute) }
    }
    /// Our end of a connection: the address it was accepted on (or
    /// connected from) and the port.
    fn tcp_local_addr(&self, _s: TcpStream) -> Result<SocketAddr, NetError> {
        Err(NetError::BadHandle)
    }
    /// `Ok(false)` while the handshake is still in progress.
    fn tcp_is_connected(&self, s: TcpStream) -> Result<bool, NetError>;
    /// `Ok(0)` means the peer has closed its side and all data was read.
    fn tcp_read(&mut self, s: TcpStream, buf: &mut [u8]) -> Result<usize, NetError>;
    /// May accept fewer bytes than given.
    fn tcp_write(&mut self, s: TcpStream, data: &[u8]) -> Result<usize, NetError>;
    /// Graceful close (FIN after queued data). The handle is dead afterwards.
    fn tcp_close(&mut self, s: TcpStream);
    /// Close with RST.
    fn tcp_abort(&mut self, s: TcpStream);

    /// Raw IP of one protocol (e.g. ICMP for ping).
    fn raw_open(&mut self, proto: u8) -> Result<RawSocket, NetError>;
    /// (length, source address, TTL); `buf` receives the IP payload.
    fn raw_recv(&mut self, s: RawSocket, buf: &mut [u8]) -> Result<(usize, Ip, u8), NetError>;
    fn raw_send(&mut self, s: RawSocket, dst: Ip, payload: &[u8]) -> Result<(), NetError>;
    fn raw_close(&mut self, s: RawSocket);

    // More interfaces: NICs, then VLANs on them ("nic0.109"); each looks
    // like a NIC of its own (frames on the packet path arrive untagged with
    // `Frame::nic` set to the interface, and get their tag when sent).
    // `net_info` is interface 0, the primary (management) one.
    fn nic_count(&self) -> usize {
        1
    }
    fn nic_name(&self, nic: usize) -> String {
        alloc::format!("nic{nic}")
    }
    fn nic_info(&self, nic: usize) -> Option<NetInfo> {
        (nic == 0).then(|| self.net_info())
    }
    /// Extra addresses of a NIC (NAT egress addresses).
    fn extra_addrs(&self, _nic: usize) -> Vec<Ip> {
        Vec::new()
    }
}

/// Persistent key-value store. Keys are private to each application (the
/// system prefixes them with the app's name); writes are durable when the
/// call returns.
pub trait Kv: Base {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError>;
    /// Ok(false) if the key did not exist.
    fn delete(&mut self, key: &str) -> Result<bool, KvError>;
    /// This application's keys starting with `prefix`.
    fn keys(&self, prefix: &str) -> Vec<String>;
    fn storage_info(&self) -> Option<StorageInfo>;

    // Files (the files partition, 1 GiB to the end of the disk): what is
    // too big for the store, up to 64 MiB each — a site, packages. Names
    // are paths ("site/index.html"); each app sees only its own.
    fn file_put(&mut self, _name: &str, _data: &[u8]) -> Result<(), KvError> {
        Err(KvError::NoStorage)
    }
    /// Bytes from `offset` (0 at the end); None if there is no such file.
    fn file_read(&mut self, _name: &str, _offset: u64, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    /// (bytes, SHA-256)
    fn file_stat(&self, _name: &str) -> Option<(u64, [u8; 32])> {
        None
    }
    /// (name, bytes) under `prefix`.
    fn file_list(&self, _prefix: &str) -> Vec<(String, u64)> {
        Vec::new()
    }
    fn file_delete(&mut self, _name: &str) -> bool {
        false
    }
    /// (total, used) bytes of the files partition.
    fn files_usage(&self) -> Option<(u64, u64)> {
        None
    }
}

/// Raw Ethernet, for apps that forward packets (see `Module::on_frames`).
pub trait Packet: Base {
    fn mac(&self) -> [u8; 6];
    /// Send a frame built from scratch (forwarded frames use `Verdict::Transmit`).
    fn send_frame(&mut self, frame: &[u8]) -> bool;

    // For forwarding between NICs:
    fn nic_mac(&self, nic: usize) -> Option<[u8; 6]> {
        (nic == 0).then(|| self.mac())
    }
    fn send_frame_on(&mut self, nic: usize, frame: &[u8]) -> bool {
        nic == 0 && self.send_frame(frame)
    }
    /// `send_frame_on` for a frame with offloads pending (`Frame::offload`).
    fn send_frame_offload(&mut self, nic: usize, frame: &[u8], offload: Offload) -> bool {
        offload.is_none() && self.send_frame_on(nic, frame)
    }
    /// (NIC, next hop) towards `dst` by the system's routes.
    fn route(&self, _dst: Ip) -> Option<(usize, Ip)> {
        None
    }
    /// (NIC, next hop) for a packet from `src` to `dst`: source routes, and
    /// our own addresses leave through their interface (several WANs).
    fn route_from(&self, _src: Ip, dst: Ip) -> Option<(usize, Ip)> {
        self.route(dst)
    }
    /// MAC of neighbour `ip` on `nic`; None while unknown (the system asks
    /// ARP, try again later or use `send_packet`).
    fn neighbor(&mut self, _nic: usize, _ip: Ip) -> Option<[u8; 6]> {
        None
    }
    /// Route and send a finished IPv4 packet, queueing it until ARP
    /// resolves (the slow path: it is copied).
    fn send_packet(&mut self, _packet: &[u8]) -> bool {
        false
    }
    /// Put a frame back on the packet path as if it had just arrived on
    /// `nic`; only the modules after `after_order` see it (a shaper
    /// releasing what it held). False if the queue for that is full.
    fn inject(&mut self, _nic: usize, _frame: &[u8], _offload: Offload, _after_order: i32) -> bool {
        false
    }
    /// Settle a frame's offloads for an app that must see plain packets
    /// (a tunnel): a partial checksum is completed in place (true: carry on
    /// with it); a big segment is cut into packets that come back on the
    /// packet path after `after_order`, and the frame is consumed (false).
    fn resolve(&mut self, _frame: &mut Frame, _after_order: i32) -> bool {
        false
    }
}

/// Privileged operations.
pub trait Admin: Base {
    fn reboot(&mut self) -> !;
    /// ACPI power off (S5); reboots if the machine has no ACPI.
    fn poweroff(&mut self) -> !;
    /// Testing aid for the hardware watchdog: disables interrupts and spins
    /// forever. Only the i6300esb (if present) gets the machine back.
    fn debug_freeze(&mut self) -> !;
    fn clear_crash(&mut self) -> bool;

    fn net_config(&mut self, ip: Ip, mask: Ip, gw: Ip);
    /// Clamped to 576..=1500.
    fn net_set_mtu(&mut self, mtu: usize);

    // The whole network configuration in three stages: a candidate (edited
    // freely, neither in effect nor stored), the running one, and what is
    // stored for the next boot (`net_save`). `net_apply` puts the candidate
    // in effect and `net_revert` goes back, as often as you like; the
    // candidate stays until `net_discard` or `net_save`.
    /// Throughput (per NIC, now and peak), CPU use and ring overflows.
    fn perf_report(&self) -> String;
    /// Start the peaks over.
    fn perf_reset(&mut self);
    /// CPU use over the last second, in percent (from the time the main
    /// loop waits in `hlt`).
    fn cpu_pct(&self) -> u32 {
        0
    }
    /// Bytes each NIC received and sent since boot (all traffic, forwarded
    /// too), in NIC order.
    fn nic_bytes(&self) -> Vec<(u64, u64)> {
        Vec::new()
    }

    /// Console logs kept on disk: (boot number, bytes), oldest first.
    fn log_list(&mut self) -> Vec<(u64, u64)>;
    /// This boot's number in the log (None: no log kept).
    fn log_this_boot(&self) -> Option<u64>;
    /// The console log of a boot.
    fn log_read(&mut self, boot: u64) -> Option<Vec<u8>>;

    /// The running configuration: the NICs in order, then the VLANs.
    fn net_running(&self) -> NetConf;
    /// Put `conf` in effect now (it must list the machine's NICs).
    fn net_set_running(&mut self, conf: &NetConf) -> Result<(), String>;
    fn net_candidate(&self) -> Option<NetConf>;
    fn net_set_candidate(&mut self, conf: Option<NetConf>);
    /// The candidate goes into effect; unless confirmed within `seconds`
    /// (0: no limit) it is reverted (the candidate stays).
    fn net_apply(&mut self, seconds: u32) -> Result<(), String>;
    /// Back to the configuration from before the first apply; false if
    /// nothing was applied. The candidate stays.
    fn net_revert(&mut self) -> bool;
    /// Stop the revert timer (revert stays possible); false if none ran.
    fn net_confirm(&mut self) -> bool;
    /// Revert if applied, and drop the candidate.
    fn net_discard(&mut self);
    /// Seconds before an applied candidate is reverted.
    fn net_pending(&self) -> Option<u64>;
    /// A candidate is in effect (applied, not saved or discarded yet).
    fn net_applied(&self) -> bool;
    /// The network settings stored for the next boot (grubenv `net*`).
    fn boot_net(&self) -> Vec<(String, String)>;
    /// Change one stored network setting without touching the running
    /// network (empty value removes it); takes effect at the next boot.
    fn boot_net_set(&mut self, key: &str, value: &str) -> bool;

    /// Store the running configuration on the boot disk for the next boots;
    /// ends an apply/revert round (candidate and revert point are dropped).
    /// False if there is no boot disk.
    fn net_save(&mut self) -> bool;

    /// Raw sectors of the EFI system partition (bootloader, its
    /// configuration, the kernel slots): `sectors` from `lba`, which must lie
    /// inside it. For maintaining what GRUB reads; nothing else is reachable.
    fn esp_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>>;
    /// Write whole sectors inside the EFI system partition.
    fn esp_write(&mut self, lba: u64, data: &[u8]) -> bool;

    /// Start writing a new kernel image into the inactive slot.
    fn update_begin(&mut self) -> bool;
    /// Append image bytes.
    fn update_write(&mut self, data: &[u8]) -> bool;
    /// Flush the image and arrange for a single trial boot of it.
    fn update_commit(&mut self) -> bool;
    /// Make the running slot the default (ends a trial boot).
    fn confirm_boot(&mut self) -> bool;

    /// Store an application image (native module ELF or WebAssembly) under
    /// `name`, make that form the preferred one and (re)start the app.
    /// Changes take effect after the current main-loop pass.
    fn module_install(&mut self, name: &str, image: &[u8]) -> Result<ModuleKind, String>;
    /// Remove one form (the app keeps running in the other, if stored) or,
    /// with `None`, the whole app.
    fn module_remove(&mut self, name: &str, kind: Option<ModuleKind>) -> bool;
    /// Run the other stored form (also re-enables a native form that was
    /// switched off after a crash).
    fn module_switch(&mut self, name: &str, kind: ModuleKind) -> Result<(), String>;
    fn module_list(&self) -> Vec<ModuleInfo>;
    /// A module's settings: the keys under `cfg/` in its own store namespace
    /// (the module reads them with `Kv::get("cfg/<key>")`).
    fn module_config(&self, name: &str) -> Vec<(String, String)>;
    /// Set (or with None remove) one setting of a module.
    fn module_config_set(&mut self, name: &str, key: &str, value: Option<&str>) -> Result<(), String>;
}

/// An application. All methods except `name` have defaults, so an app only
/// implements what it needs.
pub trait Module {
    fn name(&self) -> &'static str;
    /// Capabilities this app needs; it gets at most these.
    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV
    }
    /// Place on the packet path (`on_frames`): lower first. Translators
    /// (NAT, tunnels) stay at 0; a plain router goes last.
    fn order(&self) -> i32 {
        0
    }
    /// Whether `on_frames` / `on_egress` take frames with offloads pending
    /// (`Frame::offload`): big TCP segments and partial checksums. Apps that
    /// do not get plain packets.
    fn offloads(&self) -> bool {
        false
    }
    fn start(&mut self, _sys: &mut dyn Sys) {}
    /// Called on every main-loop iteration (at least every millisecond).
    fn poll(&mut self, _sys: &mut dyn Sys) {}
    /// A byte from the keyboard or serial console (only for the module that
    /// owns the console; see `Caps::CONSOLE`).
    fn key(&mut self, _sys: &mut dyn Sys, _c: u8) {}
    /// A batch of received frames, before the system stack sees them (needs
    /// `Caps::PACKET`). Set `verdict` on the frames you handle; leave the rest
    /// at `Pass`. Frames already decided by an earlier app are not included.
    fn on_frames(&mut self, _sys: &mut dyn Sys, _frames: &mut [Frame]) {}
    /// Frames about to be sent (`verdict` Transmit, `nic` the interface,
    /// VLAN tag not added yet). A shaper takes those it queues (sets
    /// `Consumed`) and sends them later with `Packet::send_frame_on`.
    fn on_egress(&mut self, _sys: &mut dyn Sys, _frames: &mut [Frame]) {}

    // For apps that restart themselves (runtime instances):
    /// True once after the app dropped its state and started over; the
    /// system then releases the sockets it held.
    fn take_restart(&mut self) -> bool {
        false
    }
    /// One-line state for listings ("running", "stopped: ..., restart in 4 s").
    fn status(&self) -> String {
        String::from("running")
    }
    /// The settings this module takes, for user interfaces (`Param`).
    fn params(&self) -> &'static [Param] {
        &[]
    }
    fn restarts(&self) -> u32 {
        0
    }
    /// The release this module was built for (see `BUILD`).
    fn version(&self) -> &'static str {
        crate::BUILD
    }
}

struct W<'a>(&'a mut dyn Base);

impl Write for W<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.print(s);
        Ok(())
    }
}

pub fn print_fmt(out: &mut dyn Base, args: fmt::Arguments) {
    let _ = W(out).write_fmt(args);
}

/// `say!(sys, "fmt", args...)` prints to the console (works with any of the
/// interfaces: `Sys`, `Net`, `Kv`, ...).
#[macro_export]
macro_rules! say {
    ($sys:expr, $($arg:tt)*) => { $crate::sys::print_fmt($sys, format_args!($($arg)*)) };
}
