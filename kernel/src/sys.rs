//! The system side of the application interface: one `Ctx` per call, carrying
//! the calling application's id so sockets stay with their owner.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_util::wire::Ip;
use rustros_api::{NetConf, Admin, ModuleInfo, ModuleKind, Base, Caps, ConnInfo, Kv, KvError, Net, Packet, NetInfo, StorageInfo, Sys, UpdateInfo, Frame, Verdict};

use devices::NetDevice;

use rustros_api::module::{Disk, Export, Filesystem, Link, NetStack, Runtime, Storage};
use rustros_api::socket::{Epoll, EpollEvent, SockAddr, SockResult, Socket};

use crate::services::{self, Provider};
use crate::{arch, console, kprintln, modules};

/// Frames waiting to be put back on the packet path, at most.
const INJECT_MAX: usize = 4096;
/// Frames the stack sent, waiting for the egress hook, at most.
const STACK_TX_MAX: usize = 4096;
const NO_MANAGER: &str = "no module manager in this system";

/// A logical interface: a NIC, or a VLAN on one. The NICs come first, so
/// interface `i < nics.len()` is NIC `i`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfMap {
    pub phys: usize,
    pub vlan: Option<u16>,
}

pub fn if_name(m: &IfMap) -> String {
    match m.vlan {
        None => format!("nic{}", m.phys),
        Some(v) => format!("nic{}.{}", m.phys, v),
    }
}

/// Send a frame out of logical interface `i`, tagged if it is a VLAN.
pub fn if_send(nics: &mut [Box<dyn NetDevice>], ifmap: &[IfMap], i: usize, frame: &[u8]) -> bool {
    let Some(m) = ifmap.get(i) else { return false };
    let Some(n) = nics.get_mut(m.phys) else { return false };
    match m.vlan {
        None => n.send(frame),
        Some(v) if frame.len() >= 14 => {
            let mut f = Vec::with_capacity(frame.len() + 4);
            f.extend_from_slice(&frame[..12]);
            f.extend_from_slice(&[0x81, 0x00, (v >> 8) as u8, v as u8]);
            f.extend_from_slice(&frame[12..]);
            n.send(&f)
        }
        _ => false,
    }
}

/// Send a frame with offloads pending out of logical interface `i`: as it
/// is if the NIC finishes offloads, else as plain packets.
pub fn if_send_offload(nics: &mut [Box<dyn NetDevice>], ifmap: &[IfMap], i: usize, frame: &[u8], off: rustros_api::Offload) -> bool {
    if off.is_none() {
        return if_send(nics, ifmap, i, frame);
    }
    let Some(m) = ifmap.get(i) else { return false };
    let Some(n) = nics.get_mut(m.phys) else { return false };
    if frame.len() < 14 {
        return false;
    }
    // into a buffer of its own, with room for the device header (and a tag)
    let mut b = devices::buf_for(frame.len() + 4);
    let mut start = devices::HEADROOM;
    let mut len = frame.len();
    b[start..start + len].copy_from_slice(frame);
    if let Some(v) = m.vlan {
        start -= 4;
        b.copy_within(start + 4..start + 16, start);
        b[start + 12..start + 16].copy_from_slice(&[0x81, 0x00, (v >> 8) as u8, v as u8]);
        len += 4;
    }
    n.send_swap(&mut b, start, len, off)
}

pub struct Kernel {
    /// All NICs; 0 is the primary.
    pub nics: Vec<Box<dyn NetDevice>>,
    /// Logical interfaces (the stack's interfaces, `Frame::nic`).
    pub ifmap: Vec<IfMap>,
    pub boot: Option<Box<dyn Storage>>,
    pub cmdline: String,
    /// The network stack.
    pub stack: Box<dyn NetStack>,
    /// Where the services come from (the boot modules, or an installed
    /// module that replaced them; services.rs).
    pub stack_by: Provider,
    pub boot_by: Provider,
    pub manager_by: Provider,
    pub drivers: Vec<(Box<dyn rustros_api::module::Driver>, Provider)>,
    /// What each NIC is (its PCI function, its driver), and the boot disk.
    pub nic_dev: Vec<services::Dev>,
    pub disk_dev: Option<services::Dev>,
    /// The NIC drivers' options ("offload=off").
    pub nic_options: &'static str,
    /// The boot image's services while installed ones replace them.
    pub parked: services::Parked,
    /// Booting: no app has run yet, so nothing holds state in the network
    /// stack but its configuration.
    pub booting: bool,
    /// User-mode processes, and the module with their system calls.
    pub procs: crate::proc::Procs,
    pub syscalls: Option<(&'static str, crate::loader::Module)>,
    /// Module names by id ("" for a free slot).
    pub names: Vec<&'static str>,
    /// Capabilities granted, by app id.
    pub caps: Vec<Caps>,
    pub builtin_names: Vec<&'static str>,
    /// The WebAssembly runtime: a native module installed as "wasm".
    pub runtime_module: Option<crate::loader::Module>,
    /// file system drivers: (module name, module)
    pub filesystems: Vec<(&'static str, crate::loader::Module)>,
    /// the driver that has the files partition mounted
    pub files_fs: Option<usize>,
    /// The installed modules' bookkeeping.
    pub manager: Option<Box<dyn rustros_api::module::ModManager>>,
    pub app_status: Vec<modules::ModuleStatus>,
    /// Boots in a row that did not run stable (from grubenv via GRUB).
    pub unstable_boots: u32,
    pub safe_mode: bool,
    /// Throughput and CPU use.
    pub perf: crate::perf::Perf,
    /// Frames put back on the packet path: (interface, after which module
    /// order, frame).
    pub injected: alloc::collections::VecDeque<(u8, i32, Vec<u8>, rustros_api::Offload)>,
    /// Frames the system's stack sends: they pass the egress hook (shapers)
    /// before the NIC, like forwarded ones. (interface, frame)
    pub stack_tx: alloc::collections::VecDeque<(u8, Vec<u8>)>,
    seed: u64,
}

impl Kernel {
    pub fn new(nics: Vec<Box<dyn NetDevice>>, boot: Option<Box<dyn Storage>>, cmdline: String, stack: Box<dyn NetStack>) -> Kernel {
        Kernel {
            nics,
            ifmap: Vec::new(),
            boot,
            cmdline,
            stack,
            stack_by: Provider::boot(),
            boot_by: Provider::boot(),
            manager_by: Provider::boot(),
            drivers: Vec::new(),
            nic_dev: Vec::new(),
            disk_dev: None,
            nic_options: "",
            parked: services::Parked::default(),
            booting: true,
            procs: crate::proc::Procs::default(),
            syscalls: None,
            names: Vec::new(),
            caps: Vec::new(),
            builtin_names: Vec::new(),
            runtime_module: None,
            filesystems: Vec::new(),
            files_fs: None,
            manager: None,
            app_status: Vec::new(),
            unstable_boots: 1,
            safe_mode: false,
            perf: crate::perf::Perf::default(),
            injected: alloc::collections::VecDeque::new(),
            stack_tx: alloc::collections::VecDeque::new(),
            seed: arch::rdtsc() | 1,
        }
    }

    /// The interfaces as the stack has them (after a change to its configuration).
    pub fn sync_ifmap(&mut self) {
        self.ifmap = self.stack.config().ifs.iter().map(|f| IfMap { phys: f.phys as usize, vlan: f.vlan }).collect();
    }

    /// Put a whole network configuration in effect (see `NetStack::set_config`).
    pub fn net_set_running(&mut self, net: &NetConf) -> Result<(), String> {
        let r = self.stack.set_config(net);
        self.sync_ifmap();
        r
    }

    /// An applied candidate that was not confirmed in time goes.
    pub fn net_tick(&mut self) {
        if let Some(m) = self.stack.tick(arch::now_ms()) {
            kprintln!("{}", m);
            self.sync_ifmap();
        }
    }

    /// A reboot or power off on purpose: not an unstable boot.
    pub fn planned_shutdown(&mut self) {
        if let Some(b) = self.boot.as_deref_mut() {
            b.env_set(&[("boot_count", "")]);
            crate::klog::flush(b);
        }
        // the files partition marked clean (else the next mount just finds an empty log)
        self.with_files(|fs, d| fs.close(d));
    }

    /// A call into the driver that has the files partition mounted (a crash
    /// in it is pinned on that module).
    pub fn with_files<T>(&mut self, f: impl FnOnce(&mut dyn Filesystem, &mut dyn Disk) -> T) -> Option<T> {
        let i = self.files_fs?;
        let b = self.boot.as_mut()?;
        let (name, m) = self.filesystems.get_mut(i)?;
        let Some(Export::Filesystem(fs)) = m.export.as_mut() else { return None };
        let before = modules::set_current_native(Some(name));
        let (mut f, mut r) = (Some(f), None);
        b.files(&mut |d| r = f.take().map(|f| f(fs.as_mut(), d)));
        modules::set_current_native(before);
        r
    }

    pub fn runtime(&mut self) -> Option<&mut dyn Runtime> {
        match self.runtime_module.as_mut()?.export.as_mut()? {
            Export::Runtime(r) => Some(r.as_mut()),
            _ => None,
        }
    }

    pub fn runtime_ref(&self) -> Option<&dyn Runtime> {
        match self.runtime_module.as_ref()?.export.as_ref()? {
            Export::Runtime(r) => Some(r.as_ref()),
            _ => None,
        }
    }

    pub fn trial(&self) -> bool {
        self.boot.as_ref().is_some_and(|b| b.slot().1)
    }

    /// The stack plus a link to transmit through.
    pub fn net(&mut self) -> (&mut dyn NetStack, NicLink<'_>) {
        (&mut *self.stack, NicLink { tx: &mut self.stack_tx, ifmap: &self.ifmap, seed: &mut self.seed })
    }
}

fn next_random(seed: &mut u64) -> u64 {
    // the CPU's generator when there is one (update nonces, NAT and TCP
    // secrets depend on it); else xorshift mixed with the TSC
    if let Some(v) = arch::hw_random() {
        return v;
    }
    *seed ^= arch::rdtsc().rotate_left(17);
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

pub struct NicLink<'a> {
    tx: &'a mut alloc::collections::VecDeque<(u8, Vec<u8>)>,
    ifmap: &'a [IfMap],
    seed: &'a mut u64,
}

impl Link for NicLink<'_> {
    fn now_ms(&self) -> u64 {
        arch::now_ms()
    }
    fn send(&mut self, nic: usize, frame: &[u8]) -> bool {
        // queued: the main loop sends it through the egress hook
        if nic >= self.ifmap.len() || self.tx.len() >= STACK_TX_MAX || frame.len() > devices::BUF_SIZE - devices::HEADROOM {
            return false;
        }
        self.tx.push_back((nic as u8, frame.to_vec()));
        true
    }
    fn random(&mut self) -> u64 {
        next_random(self.seed)
    }
    fn notify(&mut self, _owner: usize, _sock: Socket, _events: u32) {
        // Nothing sleeps on a socket yet: apps are polled, and their epoll
        // instances are the stack's. The process layer's wait queues (blocked
        // calls, epoll over all descriptors) hook in here.
    }
}

/// What an application sees as `&mut dyn Sys`.
pub struct Ctx<'a> {
    pub k: &'a mut Kernel,
    pub id: usize,
}

impl Ctx<'_> {
    /// Capabilities granted to the calling app.
    fn caps(&self) -> Caps {
        self.k.caps.get(self.id).copied().unwrap_or(Caps::NONE)
    }

    /// The calling app's key namespace.
    fn ns(&self, key: &str) -> String {
        format!("{}/{}", self.k.names.get(self.id).copied().unwrap_or("?"), key)
    }
}

impl Base for Ctx<'_> {
    fn now_ms(&self) -> u64 {
        arch::now_ms()
    }
    fn now_us(&self) -> u64 {
        arch::now_us()
    }
    fn unix_time(&self) -> u64 {
        arch::unix_time()
    }
    fn print(&mut self, s: &str) {
        console::write_str(s);
    }
    fn random(&mut self) -> u64 {
        next_random(&mut self.k.seed)
    }
}

impl Sys for Ctx<'_> {
    fn kernel_version(&self) -> &str {
        rustros_api::BUILD
    }
    fn cmdline(&self) -> &str {
        &self.k.cmdline
    }
    fn modules(&self) -> Vec<&'static str> {
        self.k.names.iter().copied().filter(|n| !n.is_empty()).collect()
    }
    fn update_info(&self) -> Option<UpdateInfo> {
        let b = self.k.boot.as_ref()?;
        let (slot, trial) = b.slot();
        Some(UpdateInfo {
            slot,
            trial,
            max_bytes: b.slot_bytes(),
            unstable_boots: self.k.unstable_boots,
            safe_mode: self.k.safe_mode,
        })
    }
    fn last_crash(&self) -> Option<String> {
        self.k.boot.as_ref()?.env("last_panic").map(String::from)
    }
    fn caps(&self) -> Caps {
        self.caps()
    }
    fn net(&mut self) -> Option<&mut dyn Net> {
        if self.caps().contains(Caps::NET) { Some(self) } else { None }
    }
    fn kv(&mut self) -> Option<&mut dyn Kv> {
        if self.caps().contains(Caps::KV) { Some(self) } else { None }
    }
    fn packet(&mut self) -> Option<&mut dyn Packet> {
        if self.caps().contains(Caps::PACKET) { Some(self) } else { None }
    }
    fn admin(&mut self) -> Option<&mut dyn Admin> {
        if self.caps().contains(Caps::ADMIN) { Some(self) } else { None }
    }
}

impl Net for Ctx<'_> {
    fn net_info(&self) -> NetInfo {
        self.k.stack.nic_info(0).unwrap()
    }
    fn arp_table(&self) -> Vec<(Ip, [u8; 6], u64)> {
        self.k.stack.arp_table(arch::now_ms())
    }
    fn nic_count(&self) -> usize {
        self.k.ifmap.len()
    }
    fn nic_name(&self, nic: usize) -> String {
        self.k.ifmap.get(nic).map_or_else(String::new, if_name)
    }
    fn nic_info(&self, nic: usize) -> Option<NetInfo> {
        self.k.stack.nic_info(nic)
    }
    fn extra_addrs(&self, nic: usize) -> Vec<Ip> {
        self.k.stack.config().ifs.get(nic).map(|f| f.extra.clone()).unwrap_or_default()
    }
    fn tcp_connections(&self) -> Vec<ConnInfo> {
        self.k.stack.connections()
    }
    fn socket(&mut self, domain: i32, ty: i32, protocol: i32) -> SockResult<Socket> {
        self.k.stack.socket(self.id, domain, ty, protocol)
    }
    fn bind(&mut self, s: Socket, addr: &SockAddr) -> SockResult<()> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.bind(id, &mut link, s, addr)
    }
    fn listen(&mut self, s: Socket, backlog: i32) -> SockResult<()> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.listen(id, &mut link, s, backlog)
    }
    fn accept(&mut self, s: Socket, flags: i32) -> SockResult<(Socket, SockAddr)> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.accept(id, &mut link, s, flags)
    }
    fn connect(&mut self, s: Socket, addr: &SockAddr) -> SockResult<()> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.connect(id, &mut link, s, addr)
    }
    fn sendto(&mut self, s: Socket, data: &[u8], flags: i32, to: Option<&SockAddr>) -> SockResult<usize> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.sendto(id, &mut link, s, data, flags, to)
    }
    fn recvfrom(&mut self, s: Socket, buf: &mut [u8], flags: i32) -> SockResult<(usize, Option<SockAddr>)> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.recvfrom(id, &mut link, s, buf, flags)
    }
    fn shutdown(&mut self, s: Socket, how: i32) -> SockResult<()> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.shutdown(id, &mut link, s, how)
    }
    fn close(&mut self, s: Socket) -> SockResult<()> {
        let id = self.id;
        let (st, mut link) = self.k.net();
        st.close(id, &mut link, s)
    }
    fn getsockname(&self, s: Socket) -> SockResult<SockAddr> {
        self.k.stack.getsockname(self.id, s)
    }
    fn getpeername(&self, s: Socket) -> SockResult<SockAddr> {
        self.k.stack.getpeername(self.id, s)
    }
    fn setsockopt(&mut self, s: Socket, level: i32, name: i32, value: &[u8]) -> SockResult<()> {
        self.k.stack.setsockopt(self.id, s, level, name, value)
    }
    fn getsockopt(&mut self, s: Socket, level: i32, name: i32, value: &mut [u8]) -> SockResult<usize> {
        self.k.stack.getsockopt(self.id, s, level, name, value)
    }
    fn ioctl(&mut self, s: Socket, request: u32, arg: u64) -> SockResult<u64> {
        self.k.stack.ioctl(self.id, s, request, arg)
    }
    fn sock_poll(&self, s: Socket) -> SockResult<(u32, u64)> {
        self.k.stack.sock_poll(self.id, s)
    }
    fn epoll_create(&mut self) -> SockResult<Epoll> {
        self.k.stack.epoll_create(self.id)
    }
    fn epoll_ctl(&mut self, ep: Epoll, op: i32, s: Socket, events: u32, data: u64) -> SockResult<()> {
        self.k.stack.epoll_ctl(self.id, ep, op, s, events, data)
    }
    fn epoll_wait(&mut self, ep: Epoll, out: &mut [EpollEvent]) -> SockResult<usize> {
        self.k.stack.epoll_wait(self.id, ep, out)
    }
    fn epoll_close(&mut self, ep: Epoll) -> SockResult<()> {
        self.k.stack.epoll_close(self.id, ep)
    }
}

/// One file in the files partition is at most this.
const MAX_FILE: usize = 64 << 20;

impl Ctx<'_> {
    fn app_name(&self) -> &'static str {
        self.k.names.get(self.id).copied().unwrap_or("?")
    }

    /// An app's file name as a path on the files partition: its own directory.
    fn file_path(&self, name: &str) -> Option<String> {
        let ok = !name.is_empty() && name.split('/').all(|p| !p.is_empty() && p != "." && p != ".." && !p.contains('\0'));
        ok.then(|| format!("/{}/{name}", self.app_name()))
    }
}

impl Kv for Ctx<'_> {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.k.boot.as_ref()?.kv_get(&self.ns(key)).map(|v| v.to_vec())
    }
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        if key.is_empty() {
            return Err(KvError::TooLarge);
        }
        let k = self.ns(key);
        self.k.boot.as_mut().ok_or(KvError::NoStorage)?.kv_put(&k, value)
    }
    fn delete(&mut self, key: &str) -> Result<bool, KvError> {
        let k = self.ns(key);
        self.k.boot.as_mut().ok_or(KvError::NoStorage)?.kv_delete(&k)
    }
    fn keys(&self, prefix: &str) -> Vec<String> {
        let ns = self.ns("");
        let full = self.ns(prefix);
        match self.k.boot.as_ref() {
            Some(b) => b.kv_keys(&full).into_iter().map(|k| String::from(&k[ns.len()..])).collect(),
            None => Vec::new(),
        }
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        self.k.boot.as_ref()?.kv_info()
    }
    fn file_put(&mut self, name: &str, data: &[u8]) -> Result<(), KvError> {
        let path = self.file_path(name).ok_or(KvError::TooLarge)?;
        if data.len() > MAX_FILE {
            return Err(KvError::TooLarge);
        }
        let now = arch::unix_time() as u32;
        self.k.with_files(|fs, d| fs.put(d, &path, data, now)).unwrap_or(Err(KvError::NoStorage))
    }
    fn file_read(&mut self, name: &str, offset: u64, buf: &mut [u8]) -> Option<usize> {
        let path = self.file_path(name)?;
        self.k.with_files(|fs, d| fs.read(d, &path, offset, buf))?
    }
    fn file_stat(&mut self, name: &str) -> Option<(u64, u64)> {
        let path = self.file_path(name)?;
        let (size, mtime, dir) = self.k.with_files(|fs, d| fs.stat(d, &path))??;
        (!dir).then_some((size, mtime))
    }
    fn file_list(&mut self, prefix: &str) -> Vec<(String, u64)> {
        let owner = format!("/{}", self.app_name());
        let mut out = Vec::new();
        let mut dirs = alloc::vec![String::new()];
        while let Some(rel) = dirs.pop() {
            let path = format!("{owner}/{rel}");
            let Some(Some(list)) = self.k.with_files(|fs, d| fs.list(d, &path)) else { continue };
            for (name, size, dir) in list {
                let p = if rel.is_empty() { name } else { format!("{rel}/{name}") };
                if dir {
                    // only directories that can hold something under the prefix
                    if prefix.starts_with(&p) || p.starts_with(prefix.trim_end_matches('/')) || prefix.is_empty() {
                        dirs.push(p);
                    }
                } else if p.starts_with(prefix) {
                    out.push((p, size));
                }
            }
        }
        rustros_util::sort::sort(&mut out);
        out
    }
    fn file_delete(&mut self, name: &str) -> bool {
        let Some(path) = self.file_path(name) else { return false };
        let now = arch::unix_time() as u32;
        self.k.with_files(|fs, d| fs.remove(d, &path, now)).unwrap_or(false)
    }
}

impl Packet for Ctx<'_> {
    fn mac(&self) -> [u8; 6] {
        self.k.nics[0].mac()
    }
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        self.k.nics[0].send(frame)
    }
    fn send_frame_offload(&mut self, nic: usize, frame: &[u8], offload: rustros_api::Offload) -> bool {
        if_send_offload(&mut self.k.nics, &self.k.ifmap, nic, frame, offload)
    }
    fn route(&self, dst: Ip) -> Option<(usize, Ip)> {
        self.k.stack.route_from(0, dst)
    }
    fn route_from(&self, src: Ip, dst: Ip) -> Option<(usize, Ip)> {
        self.k.stack.route_from(src, dst)
    }
    fn neighbor(&mut self, nic: usize, ip: Ip) -> Option<[u8; 6]> {
        let (st, mut l) = self.k.net();
        st.neighbor(&mut l, nic, ip)
    }
    fn send_packet(&mut self, packet: &[u8]) -> bool {
        let (st, mut l) = self.k.net();
        st.send_packet(&mut l, packet)
    }
    fn inject(&mut self, nic: usize, frame: &[u8], offload: rustros_api::Offload, after_order: i32) -> bool {
        let max = if offload.gso_size > 0 { 65_600 } else { devices::BUF_SIZE - devices::HEADROOM };
        if nic >= self.k.ifmap.len() || self.k.injected.len() >= INJECT_MAX || frame.len() > max {
            return false;
        }
        self.k.injected.push_back((nic as u8, after_order, frame.to_vec(), offload));
        true
    }
    fn resolve(&mut self, f: &mut Frame, after_order: i32) -> bool {
        if f.offload.gso_size == 0 {
            if f.offload.csum_partial {
                rustros_util::offload::complete_csum(f.data_mut());
            }
            f.offload = rustros_api::Offload::default();
            return true;
        }
        for p in devices::plain(f.data(), f.offload) {
            self.k.injected.push_back((f.nic, after_order, p, rustros_api::Offload::default()));
        }
        f.verdict = Verdict::Consumed;
        false
    }
}

impl Admin for Ctx<'_> {
    fn reboot(&mut self) -> ! {
        kprintln!("rebooting...");
        self.k.planned_shutdown(); // after the message, so the log has it
        arch::reboot()
    }
    fn poweroff(&mut self) -> ! {
        kprintln!("powering off...");
        self.k.planned_shutdown();
        crate::poweroff()
    }
    fn debug_freeze(&mut self) -> ! {
        kprintln!("freezing with interrupts off");
        arch::halt_forever()
    }
    fn clear_crash(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.env_set(&[("last_panic", "")]))
    }
    fn boot_net(&self) -> Vec<(String, String)> {
        let Some(b) = self.k.boot.as_ref() else { return Vec::new() };
        b.env_vars().into_iter().filter(|(k, _)| k.starts_with("net")).collect()
    }
    fn boot_net_set(&mut self, key: &str, value: &str) -> bool {
        let ok = key.starts_with("net") && key.len() <= 32 && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        ok && self.k.boot.as_mut().is_some_and(|b| b.env_set(&[(key, value)]))
    }
    fn net_running(&self) -> NetConf {
        self.k.stack.config()
    }
    fn log_list(&mut self) -> Vec<(u64, u64)> {
        let Some(b) = self.k.boot.as_deref_mut() else { return Vec::new() };
        crate::klog::flush(b);
        b.log_list()
    }
    fn perf_report(&self) -> String {
        self.k.perf.report()
    }
    fn perf_reset(&mut self) {
        self.k.perf.reset();
    }
    fn cpu_pct(&self) -> u32 {
        self.k.perf.cpu()
    }
    fn nic_bytes(&self) -> Vec<(u64, u64)> {
        self.k.nics.iter().map(|n| n.stats()).map(|s| (s.rx_bytes, s.tx_bytes)).collect()
    }
    fn log_this_boot(&self) -> Option<u64> {
        self.k.boot.as_ref()?.log_seq()
    }
    fn log_read(&mut self, boot: u64) -> Option<Vec<u8>> {
        let b = self.k.boot.as_deref_mut()?;
        crate::klog::flush(b);
        b.log_read(boot)
    }
    fn net_set_running(&mut self, conf: &NetConf) -> Result<(), String> {
        self.k.net_set_running(conf)
    }
    fn net_candidate(&self) -> Option<NetConf> {
        self.k.stack.candidate()
    }
    fn net_set_candidate(&mut self, conf: Option<NetConf>) {
        self.k.stack.set_candidate(conf);
    }
    fn net_apply(&mut self, seconds: u32) -> Result<(), String> {
        let r = self.k.stack.apply(arch::now_ms(), seconds);
        self.k.sync_ifmap();
        r?;
        kprintln!("net: candidate applied{}", if seconds > 0 { format!("; reverted in {seconds} s unless confirmed") } else { String::new() });
        Ok(())
    }
    fn net_revert(&mut self) -> bool {
        let r = self.k.stack.revert();
        self.k.sync_ifmap();
        r.unwrap_or_else(|e| {
            kprintln!("net: revert failed: {}", e);
            false
        })
    }
    fn net_confirm(&mut self) -> bool {
        self.k.stack.confirm()
    }
    fn net_discard(&mut self) {
        self.k.stack.discard();
        self.k.sync_ifmap();
    }
    fn net_pending(&self) -> Option<u64> {
        self.k.stack.pending(arch::now_ms())
    }
    fn net_applied(&self) -> bool {
        self.k.stack.applied()
    }
    fn esp_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>> {
        self.k.boot.as_mut()?.esp_read(lba, sectors)
    }
    fn boot_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>> {
        let mut buf = alloc::vec![0u8; sectors.min(128) * 512];
        self.k.boot.as_mut()?.boot_area_read(lba, &mut buf).then_some(buf)
    }
    fn boot_write(&mut self, lba: u64, data: &[u8]) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.boot_area_write(lba, data))
    }
    fn esp_move(&mut self, first: u64, last: u64) -> Result<(), String> {
        let r = self.k.boot.as_mut().ok_or_else(|| String::from("no boot disk"))?.esp_move(first, last);
        if r.is_ok() {
            kprintln!("storage: the EFI partition is now sectors {}-{} (from the next boot)", first, last);
        }
        r
    }
    fn esp_write(&mut self, lba: u64, data: &[u8]) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.esp_write(lba, data))
    }
    fn net_save(&mut self) -> bool {
        // saving what runs ends the apply/revert round
        let vars = self.k.stack.save();
        let refs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.k.boot.as_mut().is_some_and(|b| b.env_set(&refs))
    }
    fn update_begin(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.update_begin())
    }
    fn update_write(&mut self, data: &[u8]) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.update_write(data))
    }
    fn update_commit(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.update_commit())
    }
    fn confirm_boot(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.confirm())
    }
    fn module_install(&mut self, name: &str, image: &[u8]) -> Result<ModuleKind, String> {
        modules::manager(self.k, |m, h| m.install(h, name, image)).unwrap_or_else(|| Err(String::from(NO_MANAGER)))
    }
    fn module_remove(&mut self, name: &str, kind: Option<ModuleKind>) -> bool {
        modules::manager(self.k, |m, h| m.remove(h, name, kind)).unwrap_or(false)
    }
    fn module_switch(&mut self, name: &str, kind: ModuleKind) -> Result<(), String> {
        modules::manager(self.k, |m, h| m.switch(h, name, kind)).unwrap_or_else(|| Err(String::from(NO_MANAGER)))
    }
    fn module_list(&mut self) -> Vec<ModuleInfo> {
        let running = modules::running(self.k);
        modules::manager(self.k, |m, h| m.list(h, running)).unwrap_or_default()
    }
    fn module_config(&mut self, name: &str) -> Vec<(String, String)> {
        modules::manager(self.k, |m, h| m.config(h, name)).unwrap_or_default()
    }
    fn module_config_set(&mut self, name: &str, key: &str, value: Option<&str>) -> Result<(), String> {
        modules::manager(self.k, |m, h| m.config_set(h, name, key, value)).unwrap_or_else(|| Err(String::from(NO_MANAGER)))
    }
    fn spawn(&mut self, image: &[u8], args: &[&str]) -> Result<u32, String> {
        self.k.procs.spawn(image, args)
    }
    fn processes(&self) -> Vec<rustros_api::ProcInfo> {
        self.k.procs.list()
    }
    fn kill(&mut self, pid: u32) -> bool {
        self.k.procs.kill(pid)
    }
}
