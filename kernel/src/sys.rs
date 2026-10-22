//! The system side of the application interface: one `Ctx` per call, carrying
//! the calling application's id so sockets stay with their owner.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use netstack::{Link, Stack};
use rustros_util::wire::{Ip, IpFmt};
use kvstore::Store;
use rustros_api::{
    IfConf, NetConf, RouteConf, Admin, ModuleInfo, ModuleKind, Base, Caps, ConnInfo, Kv, KvError, Net, Packet, NetError, NetInfo, RawSocket, SocketAddr, StorageInfo, Sys, TcpListener, TcpStream,
    UdpSocket, UpdateInfo, Frame, Verdict,
};

use devices::{BlockDevice, NetDevice};

use rustros_api::module::{Export, Runtime};

use crate::{arch, console, kprintln, modules};

/// Frames waiting to be put back on the packet path, at most.
const INJECT_MAX: usize = 4096;
/// Frames the stack sent, waiting for the egress hook, at most.
const STACK_TX_MAX: usize = 4096;

/// The boot disk with what lives on it.
pub struct Boot {
    pub disk: Box<dyn BlockDevice>,
    pub upd: slots::Updater,
    pub store: Option<(Store, storage::Info)>,
    /// this boot's console log (cache partition)
    pub log: Option<crate::klog::DiskLog>,
}

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
    pub boot: Option<Boot>,
    pub cmdline: String,
    pub stack: Stack,
    /// Module names by id ("" for a free slot).
    pub names: Vec<&'static str>,
    /// Capabilities granted, by app id.
    pub caps: Vec<Caps>,
    pub builtin_names: Vec<&'static str>,
    /// The WebAssembly runtime: a native module installed as "wasm".
    pub runtime_module: Option<crate::loader::Module>,
    /// Requested installs/switches/removals, applied by the main loop.
    pub app_ops: Vec<modules::ModuleOp>,
    pub app_status: Vec<modules::ModuleStatus>,
    /// Boots in a row that did not run stable (from grubenv via GRUB).
    pub unstable_boots: u32,
    pub safe_mode: bool,
    /// Network configuration being edited, not in effect.
    pub net_candidate: Option<NetConf>,
    /// Throughput and CPU use.
    pub perf: crate::perf::Perf,
    /// Frames put back on the packet path: (interface, after which module
    /// order, frame).
    pub injected: alloc::collections::VecDeque<(u8, i32, Vec<u8>, rustros_api::Offload)>,
    /// Frames the system's stack sends: they pass the egress hook (shapers)
    /// before the NIC, like forwarded ones. (interface, frame)
    pub stack_tx: alloc::collections::VecDeque<(u8, Vec<u8>)>,
    /// What ran before the first apply (the revert point).
    pub net_baseline: Option<NetConf>,
    /// When an applied candidate is reverted unless confirmed.
    pub net_deadline: Option<u64>,
    seed: u64,
}

impl Kernel {
    pub fn new(nics: Vec<Box<dyn NetDevice>>, ifmap: Vec<IfMap>, boot: Option<Boot>, cmdline: String, stack: Stack) -> Kernel {
        Kernel {
            nics,
            ifmap,
            boot,
            cmdline,
            stack,
            names: Vec::new(),
            caps: Vec::new(),
            builtin_names: Vec::new(),
            runtime_module: None,
            app_ops: Vec::new(),
            app_status: Vec::new(),
            unstable_boots: 1,
            safe_mode: false,
            net_candidate: None,
            net_baseline: None,
            perf: crate::perf::Perf::default(),
            injected: alloc::collections::VecDeque::new(),
            stack_tx: alloc::collections::VecDeque::new(),
            net_deadline: None,
            seed: arch::rdtsc() | 1,
        }
    }

    pub fn net_running(&self) -> NetConf {
        let ifs = self
            .ifmap
            .iter()
            .zip(&self.stack.ifs.0)
            .map(|(m, f)| IfConf {
                phys: m.phys as u8,
                vlan: m.vlan,
                ip: f.ip,
                mask: f.mask,
                gw: f.gw,
                mtu: f.mtu as u16,
                extra: f.extra.clone(),
            })
            .collect();
        let routes = self.stack.ifs.1.iter().map(|r| RouteConf { net: r.net, mask: r.mask, gw: r.gw, src: r.src, src_mask: r.src_mask }).collect();
        NetConf { ifs, routes }
    }

    /// Back to the revert point (the candidate and the revert point stay).
    pub fn net_revert(&mut self) -> bool {
        self.net_deadline = None;
        let Some(base) = self.net_baseline.clone() else { return false };
        match self.net_set_running(&base) {
            Ok(()) => true,
            Err(e) => {
                kprintln!("net: revert failed: {}", e);
                false
            }
        }
    }

    /// Put a whole network configuration in effect: the NICs keep their
    /// interfaces (and ARP caches unless their address changes), VLAN
    /// interfaces come and go as listed.
    pub fn net_set_running(&mut self, net: &NetConf) -> Result<(), String> {
        let conf = &net.ifs;
        for r in &net.routes {
            if r.net & !r.mask != 0 || r.src & !r.src_mask != 0 || r.gw == 0 {
                return Err(format!("bad route {}/{}", IpFmt(r.net), r.mask.count_ones()));
            }
        }
        let nics = self.nics.len();
        let mut map: Vec<IfMap> = (0..nics).map(|phys| IfMap { phys, vlan: None }).collect();
        let mut by_map: Vec<Option<&IfConf>> = alloc::vec![None; nics];
        for c in conf {
            let m = IfMap { phys: c.phys as usize, vlan: c.vlan };
            if m.phys >= nics {
                return Err(format!("no nic{}", m.phys));
            }
            match c.vlan {
                None => by_map[m.phys] = Some(c),
                Some(v) if (1..=4094).contains(&v) && !map.contains(&m) => {
                    map.push(m);
                    by_map.push(Some(c));
                }
                Some(_) => return Err(format!("bad or repeated VLAN {}", c.name())),
            }
        }
        let mut old: Vec<(IfMap, netstack::iface::Iface)> = self.ifmap.iter().copied().zip(core::mem::take(&mut self.stack.ifs.0)).collect();
        for (i, m) in map.iter().enumerate() {
            let mut f = match old.iter().position(|(o, _)| o == m) {
                Some(p) => old.swap_remove(p).1,
                None => netstack::iface::Iface::new(i, self.nics[m.phys].mac(), 0, 0, 0),
            };
            f.nic = i;
            if let Some(c) = by_map[i] {
                if (f.ip, f.mask, f.gw) != (c.ip, c.mask, c.gw) {
                    f.arp.clear();
                }
                (f.ip, f.mask, f.gw) = (c.ip, c.mask, c.gw);
                f.mtu = (c.mtu as usize).clamp(576, 1500);
                f.extra = c.extra.iter().copied().filter(|&a| a != 0 && a != c.ip).collect();
                f.extra.sort_unstable();
                f.extra.dedup();
            }
            self.stack.ifs.0.push(f);
        }
        self.ifmap = map;
        self.stack.ifs.1 = net.routes.iter().map(|r| netstack::iface::Route { net: r.net, mask: r.mask, gw: r.gw, src: r.src, src_mask: r.src_mask }).collect();
        Ok(())
    }

    /// A reboot or power off on purpose: not an unstable boot.
    pub fn planned_shutdown(&mut self) {
        if let Some(b) = self.boot.as_mut() {
            b.upd.set_vars(&mut *b.disk, &[("boot_count", "")]);
            if let Some(l) = b.log.as_mut() {
                l.flush(&mut *b.disk);
            }
        }
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

    pub fn store_ref(&self) -> Option<&Store> {
        self.boot.as_ref()?.store.as_ref().map(|(s, _)| s)
    }

    pub fn store(&mut self) -> Option<(&mut Store, &mut dyn BlockDevice)> {
        let b = self.boot.as_mut()?;
        let (store, _) = b.store.as_mut()?;
        Some((store, &mut *b.disk))
    }

    pub fn trial(&self) -> bool {
        self.boot.as_ref().is_some_and(|b| b.upd.trial)
    }

    /// The stack plus a link to transmit through.
    pub fn net(&mut self) -> (&mut Stack, NicLink<'_>) {
        (&mut self.stack, NicLink { tx: &mut self.stack_tx, ifmap: &self.ifmap, seed: &mut self.seed })
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

fn kv_err(e: kvstore::Error) -> KvError {
    match e {
        kvstore::Error::Io => KvError::Io,
        kvstore::Error::TooLarge => KvError::TooLarge,
        kvstore::Error::Full | kvstore::Error::TooSmall => KvError::Full,
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
    fn cmdline(&self) -> &str {
        &self.k.cmdline
    }
    fn modules(&self) -> Vec<&'static str> {
        self.k.names.iter().copied().filter(|n| !n.is_empty()).collect()
    }
    fn update_info(&self) -> Option<UpdateInfo> {
        let u = &self.k.boot.as_ref()?.upd;
        Some(UpdateInfo {
            slot: u.slot,
            trial: u.trial,
            max_bytes: u.sectors * 512,
            unstable_boots: self.k.unstable_boots,
            safe_mode: self.k.safe_mode,
        })
    }
    fn last_crash(&self) -> Option<String> {
        self.k.boot.as_ref()?.upd.get("last_panic").map(String::from)
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
        self.k.stack.info()
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
        self.k.stack.ifs.0.get(nic).map(|f| f.extra.clone()).unwrap_or_default()
    }
    fn tcp_connections(&self) -> Vec<ConnInfo> {
        self.k.stack.connections()
    }
    fn udp_bind(&mut self, port: u16) -> Result<UdpSocket, NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.udp_bind(id, &mut l, port)
    }
    fn udp_local_port(&self, s: UdpSocket) -> Result<u16, NetError> {
        self.k.stack.udp_local_port(self.id, s)
    }
    fn udp_send_to(&mut self, s: UdpSocket, to: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.udp_send_to(id, &mut l, s, to, data)
    }
    fn udp_recv_from(&mut self, s: UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        self.k.stack.udp_recv_from(self.id, s, buf)
    }
    fn udp_close(&mut self, s: UdpSocket) {
        self.k.stack.udp_close(self.id, s);
    }
    fn tcp_listen(&mut self, port: u16) -> Result<TcpListener, NetError> {
        self.k.stack.tcp_listen(self.id, port)
    }
    fn tcp_unlisten(&mut self, lst: TcpListener) {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_unlisten(id, &mut l, lst);
    }
    fn tcp_accept(&mut self, lst: TcpListener) -> Result<(TcpStream, SocketAddr), NetError> {
        self.k.stack.tcp_accept(self.id, lst)
    }
    fn tcp_connect(&mut self, to: SocketAddr) -> Result<TcpStream, NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_connect(id, &mut l, to)
    }
    fn tcp_connect_from(&mut self, src: Ip, to: SocketAddr) -> Result<TcpStream, NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_connect_from(id, &mut l, src, to)
    }
    fn tcp_local_addr(&self, s: TcpStream) -> Result<SocketAddr, NetError> {
        self.k.stack.tcp_local_addr(self.id, s)
    }
    fn tcp_is_connected(&self, s: TcpStream) -> Result<bool, NetError> {
        self.k.stack.tcp_is_connected(self.id, s)
    }
    fn tcp_read(&mut self, s: TcpStream, buf: &mut [u8]) -> Result<usize, NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_read(id, &mut l, s, buf)
    }
    fn tcp_write(&mut self, s: TcpStream, data: &[u8]) -> Result<usize, NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_write(id, &mut l, s, data)
    }
    fn tcp_close(&mut self, s: TcpStream) {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_close(id, &mut l, s);
    }
    fn tcp_abort(&mut self, s: TcpStream) {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.tcp_abort(id, &mut l, s);
    }
    fn raw_open(&mut self, proto: u8) -> Result<RawSocket, NetError> {
        self.k.stack.raw_open(self.id, proto)
    }
    fn raw_recv(&mut self, s: RawSocket, buf: &mut [u8]) -> Result<(usize, Ip, u8), NetError> {
        self.k.stack.raw_recv(self.id, s, buf)
    }
    fn raw_send(&mut self, s: RawSocket, dst: Ip, payload: &[u8]) -> Result<(), NetError> {
        let id = self.id;
        let (st, mut l) = self.k.net();
        st.raw_send(id, &mut l, s, dst, payload)
    }
    fn raw_close(&mut self, s: RawSocket) {
        self.k.stack.raw_close(self.id, s);
    }
}

impl Kv for Ctx<'_> {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let (store, _) = self.k.boot.as_ref()?.store.as_ref()?;
        store.get(&self.ns(key)).map(|v| v.to_vec())
    }
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        if key.is_empty() {
            return Err(KvError::TooLarge);
        }
        let k = self.ns(key);
        let b = self.k.boot.as_mut().ok_or(KvError::NoStorage)?;
        let (store, _) = b.store.as_mut().ok_or(KvError::NoStorage)?;
        store.put(&mut *b.disk, &k, value).map_err(kv_err)
    }
    fn delete(&mut self, key: &str) -> Result<bool, KvError> {
        let k = self.ns(key);
        let b = self.k.boot.as_mut().ok_or(KvError::NoStorage)?;
        let (store, _) = b.store.as_mut().ok_or(KvError::NoStorage)?;
        store.delete(&mut *b.disk, &k).map_err(kv_err)
    }
    fn keys(&self, prefix: &str) -> Vec<String> {
        let ns = self.ns("");
        let full = self.ns(prefix);
        match self.k.boot.as_ref().and_then(|b| b.store.as_ref()) {
            Some((store, _)) => store.keys(&full).map(|k| String::from(&k[ns.len()..])).collect(),
            None => Vec::new(),
        }
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        let (store, part) = self.k.boot.as_ref()?.store.as_ref()?;
        let (live, tail, half) = store.usage();
        Some(StorageInfo {
            partition_bytes: part.sectors * 512,
            store_bytes: half * 2 * 512,
            live_bytes: live as u64,
            log_bytes: tail * 512,
        })
    }
}

impl Packet for Ctx<'_> {
    fn mac(&self) -> [u8; 6] {
        self.k.nics[0].mac()
    }
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        self.k.nics[0].send(frame)
    }
    fn nic_mac(&self, nic: usize) -> Option<[u8; 6]> {
        self.k.nics.get(self.k.ifmap.get(nic)?.phys).map(|n| n.mac())
    }
    fn send_frame_on(&mut self, nic: usize, frame: &[u8]) -> bool {
        if_send(&mut self.k.nics, &self.k.ifmap, nic, frame)
    }
    fn send_frame_offload(&mut self, nic: usize, frame: &[u8], offload: rustros_api::Offload) -> bool {
        if_send_offload(&mut self.k.nics, &self.k.ifmap, nic, frame, offload)
    }
    fn route(&self, dst: Ip) -> Option<(usize, Ip)> {
        self.k.stack.route(dst)
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
        for p in crate::offload::plain(f.data(), f.offload) {
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
        self.k.boot.as_mut().is_some_and(|b| b.upd.set_vars(&mut *b.disk, &[("last_panic", "")]))
    }
    fn net_config(&mut self, ip: Ip, mask: Ip, gw: Ip) {
        self.k.stack.config(ip, mask, gw);
    }
    fn net_set_mtu(&mut self, mtu: usize) {
        self.k.stack.primary().mtu = mtu.clamp(576, 1500);
    }
    fn boot_net(&self) -> Vec<(String, String)> {
        let Some(b) = self.k.boot.as_ref() else { return Vec::new() };
        b.upd.vars().filter(|(k, _)| k.starts_with("net")).map(|(k, v)| (String::from(k), String::from(v))).collect()
    }
    fn boot_net_set(&mut self, key: &str, value: &str) -> bool {
        let ok = key.starts_with("net") && key.len() <= 32 && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        ok && self.k.boot.as_mut().is_some_and(|b| b.upd.set_vars(&mut *b.disk, &[(key, value)]))
    }
    fn net_running(&self) -> NetConf {
        self.k.net_running()
    }
    fn log_list(&mut self) -> Vec<(u64, u64)> {
        let Some(b) = self.k.boot.as_mut() else { return Vec::new() };
        let disk = &mut *b.disk;
        b.log.as_mut().map(|l| {
            l.flush(disk);
            l.list(disk)
        }).unwrap_or_default()
    }
    fn perf_report(&self) -> String {
        self.k.perf.report()
    }
    fn perf_reset(&mut self) {
        self.k.perf.reset();
    }
    fn log_this_boot(&self) -> Option<u64> {
        self.k.boot.as_ref()?.log.as_ref().map(|l| l.seq)
    }
    fn log_read(&mut self, boot: u64) -> Option<Vec<u8>> {
        let b = self.k.boot.as_mut()?;
        let disk = &mut *b.disk;
        let l = b.log.as_mut()?;
        l.flush(disk);
        l.read(disk, boot)
    }
    fn net_set_running(&mut self, conf: &NetConf) -> Result<(), String> {
        self.k.net_set_running(conf)
    }
    fn net_candidate(&self) -> Option<NetConf> {
        self.k.net_candidate.clone()
    }
    fn net_set_candidate(&mut self, conf: Option<NetConf>) {
        self.k.net_candidate = conf;
    }
    fn net_apply(&mut self, seconds: u32) -> Result<(), String> {
        let cand = self.k.net_candidate.clone().ok_or_else(|| String::from("no candidate configuration"))?;
        let before = self.k.net_running();
        self.k.net_set_running(&cand)?;
        // the revert point is what ran before the first apply
        if self.k.net_baseline.is_none() {
            self.k.net_baseline = Some(before);
        }
        self.k.net_deadline = (seconds > 0).then(|| arch::now_ms() + seconds as u64 * 1000);
        kprintln!("net: candidate applied{}", if seconds > 0 { format!("; reverted in {seconds} s unless confirmed") } else { String::new() });
        Ok(())
    }
    fn net_revert(&mut self) -> bool {
        self.k.net_revert()
    }
    fn net_confirm(&mut self) -> bool {
        self.k.net_deadline.take().is_some()
    }
    fn net_discard(&mut self) {
        self.k.net_revert();
        self.k.net_baseline = None;
        self.k.net_candidate = None;
    }
    fn net_pending(&self) -> Option<u64> {
        self.k.net_deadline.map(|t| t.saturating_sub(arch::now_ms()) / 1000)
    }
    fn net_applied(&self) -> bool {
        self.k.net_baseline.is_some() && self.k.net_running() != self.k.net_baseline.clone().unwrap_or_default()
    }
    fn esp_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>> {
        let disk = &mut *self.k.boot.as_mut()?.disk;
        esp_range(disk, lba, sectors as u64)?;
        let mut buf = alloc::vec![0u8; sectors * 512];
        disk.read(lba, &mut buf).then_some(buf)
    }
    fn esp_write(&mut self, lba: u64, data: &[u8]) -> bool {
        let Some(b) = self.k.boot.as_mut() else { return false };
        let disk = &mut *b.disk;
        data.len() % 512 == 0 && esp_range(disk, lba, (data.len() / 512) as u64).is_some() && disk.write(lba, data)
    }
    fn net_save(&mut self) -> bool {
        // saving what runs ends the apply/revert round
        self.k.net_baseline = None;
        self.k.net_deadline = None;
        self.k.net_candidate = None;
        // NIC 0 as net_ip/net_gw/net_mtu (GRUB passes those on the command
        // line), the rest as net<n>_* read straight from grubenv at boot
        let mut vars: Vec<(String, String)> = Vec::new();
        let vlans: Vec<String> = self.k.ifmap.iter().filter_map(|m| m.vlan.map(|v| format!("{}.{}", m.phys, v))).collect();
        vars.push((String::from("net_vlans"), vlans.join(",")));
        let routes: Vec<String> = self.k.stack.ifs.1.iter().map(crate::fmt_route).collect();
        vars.push((String::from("net_routes"), routes.join(",")));
        // clear what interfaces that went away left behind
        for i in self.k.ifmap.len()..16 {
            for k in ["ip", "gw", "mtu", "extra"] {
                vars.push((format!("net{i}_{k}"), String::new()));
            }
        }
        for (i, f) in self.k.stack.ifs.0.iter().enumerate() {
            let p = if i == 0 { String::from("net_") } else { format!("net{i}_") };
            let set = f.ip != 0;
            vars.push((format!("{p}ip"), if set { format!("{}/{}", IpFmt(f.ip), f.mask.count_ones()) } else { String::new() }));
            vars.push((format!("{p}gw"), if set && f.gw != 0 { format!("{}", IpFmt(f.gw)) } else { String::new() }));
            vars.push((format!("{p}mtu"), if f.mtu == 1500 { String::new() } else { format!("{}", f.mtu) }));
            vars.push((format!("{p}extra"), rustros_util::wire::fmt_ip_list(&f.extra)));
        }
        let refs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.k.boot.as_mut().is_some_and(|b| b.upd.set_vars(&mut *b.disk, &refs))
    }
    fn update_begin(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.upd.begin())
    }
    fn update_write(&mut self, data: &[u8]) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.upd.write(&mut *b.disk, data))
    }
    fn update_commit(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.upd.commit(&mut *b.disk))
    }
    fn confirm_boot(&mut self) -> bool {
        self.k.boot.as_mut().is_some_and(|b| b.upd.confirm(&mut *b.disk))
    }
    fn module_install(&mut self, name: &str, image: &[u8]) -> Result<ModuleKind, String> {
        modules::install(self.k, name, image)
    }
    fn module_remove(&mut self, name: &str, kind: Option<ModuleKind>) -> bool {
        modules::remove(self.k, name, kind)
    }
    fn module_switch(&mut self, name: &str, kind: ModuleKind) -> Result<(), String> {
        modules::switch(self.k, name, kind)
    }
    fn module_list(&self) -> Vec<ModuleInfo> {
        modules::list(self.k)
    }
    fn module_config(&self, name: &str) -> Vec<(String, String)> {
        let prefix = format!("{name}/cfg/");
        let Some(store) = self.k.store_ref() else { return Vec::new() };
        store
            .keys(&prefix)
            .map(|k| (String::from(&k[prefix.len()..]), String::from_utf8_lossy(store.get(k).unwrap_or(b"")).into_owned()))
            .collect()
    }
    fn module_config_set(&mut self, name: &str, key: &str, value: Option<&str>) -> Result<(), String> {
        let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_graphic() && c != b'/');
        if !ok(name) || !ok(key) {
            return Err(String::from("bad module or key name"));
        }
        let k = format!("{name}/cfg/{key}");
        let (store, disk) = self.k.store().ok_or_else(|| String::from("no storage"))?;
        match value {
            Some(v) => store.put(disk, &k, v.as_bytes()).map_err(|e| format!("{e:?}")),
            None => store.delete(disk, &k).map(|_| ()).map_err(|e| format!("{e:?}")),
        }
    }
}

/// GPT type of the EFI system partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B, as stored).
const ESP_TYPE: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];

/// Some(()) if `n` sectors from `lba` lie inside the boot disk's ESP.
fn esp_range(disk: &mut dyn devices::BlockDevice, lba: u64, n: u64) -> Option<()> {
    let p = storage::gpt::Gpt::read(disk).ok()?.find(&ESP_TYPE)?;
    (n > 0 && n <= 128 && lba >= p.first && lba.checked_add(n)? <= p.last + 1).then_some(())
}
