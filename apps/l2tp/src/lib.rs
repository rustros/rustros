//! L2TP VPN server module (L2TPv2 without IPsec, PPP with PAP, as
//! rust-l2tp): clients get an address from a /24 pool and reach the
//! outside through NAT, each user from their own egress address if set.
//!
//! Instances: one server per address clients connect to, each its own
//! network (pool, NAT, egress). The same account on two addresses lands in
//! two networks. The unprefixed settings are the default instance, which
//! takes every address no named instance binds (`bind off`: none).
//!
//! Everything goes over the packet path: control messages are answered from
//! the address they were sent to; data packets are handled in place (strip
//! the tunnel headers, translate, send on; replies are translated back and
//! get the tunnel headers in the frame's headroom). Clients of an instance
//! reach each other directly, and ping the server at the pool's .1.
//!
//! Settings (`cfg l2tp <key> <value>`; `<name>.<key>` for instance <name>):
//!
//! ```text
//! bind          a.b.c.d | off       the address to serve (default instance: the
//!                                   ones no other binds; off: none)
//! user.<name>   password[@egress]   accounts (an instance without any uses the
//!                                   default's; none at all: anyone may connect!)
//! egress        a.b.c.d             default egress (default: the bind address,
//!                                   else the one towards the default route)
//! pool          10.0.0.0            client /24, server at .1 (named instances:
//!                                   10.<n>.0.0 by default)
//! dns           8.8.8.8,1.1.1.1
//! mtu           1400                tunnel MTU (TCP MSS clamped to it)
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Frame, Module, Offload, Packet, Sys, Verdict, say};
use rustros_util::wire::{Ip, IpFmt, checksum, parse_ip};
use l2tp_core::{Account, Config, DATA_HEADER, Data, Event, Peer, Server, data_header};
use nat_core::{Inbound, Nat, icmp_error};

/// Place on the packet path (with the other translators).
const ORDER: i32 = 0;
const PORT: u16 = 1701;
const ETH: usize = 14;
/// Ethernet + IPv4 + UDP + L2TP/PPP in front of a client's packet.
const ENCAP: usize = ETH + 20 + 8 + DATA_HEADER;
const RELOAD_MS: u64 = 2000;
const TICK_MS: u64 = 1000;
/// External ports of the NAT, shared out between the instances.
const PORTS: (u16, u16) = (10000, 60999);
const KEYS: &[&str] = &["bind", "egress", "pool", "dns", "mtu"];

#[derive(Clone, Copy, Default)]
struct Nic {
    mac: [u8; 6],
    ip: Ip,
    mtu: usize,
}

struct Instance {
    /// "" for the default one
    name: String,
    /// the address served; None: those no other instance binds
    bind: Option<Ip>,
    server: Server,
    nat: Nat,
    pool: Ip,
    /// the address each tunnel's client sent to (answers come from it)
    local_of: BTreeMap<Peer, Ip>,
}

impl Instance {
    fn label(&self) -> &str {
        if self.name.is_empty() { "default" } else { &self.name }
    }
}

#[derive(Default)]
pub struct L2tpModule {
    instances: Vec<Instance>,
    nics: Vec<Nic>,
    /// our addresses (any NIC, extra ones too)
    local: Vec<Ip>,
    applied: String,
    /// settings last reported (address changes alone are applied quietly)
    shown: String,
    reload_at: u64,
    tick_at: u64,
    dropped: u64,
    /// what happened on the packet path, to report in `poll`: (instance, event)
    events: Vec<(usize, Event)>,
}

fn be16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

fn ip_at(p: &[u8], o: usize) -> Ip {
    u32::from_be_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
}

fn ip_fix(h: &mut [u8]) {
    h[10..12].fill(0);
    let c = checksum(&h[..20], 0);
    h[10..12].copy_from_slice(&c.to_be_bytes());
}

/// (instance name, key) of a setting: "pool" -> ("", "pool"),
/// "wan1.user.bob" -> ("wan1", "user.bob").
fn split_key(k: &str) -> Option<(&str, &str)> {
    if k.starts_with("user.") || KEYS.contains(&k) {
        return Some(("", k));
    }
    let (name, rest) = k.split_once('.')?;
    let ok = !name.is_empty() && name != "user" && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    (ok && (rest.starts_with("user.") || KEYS.contains(&rest))).then_some((name, rest))
}

/// Setting `k` of an instance.
fn get<'a>(s: &[(&str, &'a str)], k: &str) -> Option<&'a str> {
    s.iter().find(|(x, _)| *x == k).map(|(_, v)| *v)
}

fn accounts(settings: &[(&str, &str)]) -> Vec<Account> {
    settings
        .iter()
        .filter_map(|(k, v)| {
            let user = k.strip_prefix("user.")?;
            // the password may contain '@': only an address after the last one is the egress
            let (password, egress) = match v.rsplit_once('@') {
                Some((p, e)) if parse_ip(e).is_some() => (p, parse_ip(e)),
                _ => (*v, None),
            };
            Some(Account { user: String::from(user), password: String::from(password), egress })
        })
        .collect()
}

impl L2tpModule {
    pub fn new() -> L2tpModule {
        L2tpModule::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        if let Some(net) = sys.net() {
            self.nics = (0..net.nic_count()).filter_map(|i| net.nic_info(i)).map(|n| Nic { mac: n.mac, ip: n.ip, mtu: n.mtu }).collect();
            self.local = (0..net.nic_count()).flat_map(|i| net.extra_addrs(i)).chain(self.nics.iter().map(|n| n.ip)).filter(|&a| a != 0).collect();
            self.local.sort_unstable();
        }
        let Some(kv) = sys.kv() else { return };
        let mut settings: Vec<(String, String)> = kv
            .keys("cfg/")
            .into_iter()
            .filter_map(|k| {
                let v = kv.get(&k)?;
                Some((String::from(&k[4..]), String::from_utf8_lossy(&v).into_owned()))
            })
            .collect();
        settings.sort();
        // our address towards the default gateway (any interface, a VLAN
        // too), else the first address we have
        let primary = sys
            .packet()
            .and_then(|p| p.route(0x0808_0808))
            .and_then(|(i, _)| self.nics.get(i))
            .map(|n| n.ip)
            .filter(|&ip| ip != 0)
            .or_else(|| self.nics.iter().map(|n| n.ip).find(|&ip| ip != 0))
            .unwrap_or(0);
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).chain(core::iter::once(format!("egress={primary}"))).collect();
        if text == self.applied {
            return;
        }
        // settings by instance
        let mut by: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
        by.entry("").or_default();
        for (k, v) in &settings {
            match split_key(k) {
                Some((name, key)) => by.entry(name).or_default().push((key, v.as_str())),
                None => say!(sys, "l2tp: unknown setting '{}'\n", k),
            }
        }
        let shared = accounts(&by[""]);
        let wanted: Vec<(&str, &Vec<(&str, &str)>)> = by.iter().map(|(n, s)| (*n, s)).filter(|(n, s)| !(n.is_empty() && get(s, "bind") == Some("off"))).collect();
        let span = (PORTS.1 - PORTS.0 + 1) / wanted.len().max(1) as u16;
        let mut old = core::mem::take(&mut self.instances);
        let mut named = 0u32;
        let mine: String = settings.iter().map(|(k, v)| format!("{k}={v};")).collect();
        let quiet = mine == self.shown;
        for (k, (name, s)) in wanted.iter().enumerate() {
            let bind = match get(s, "bind").map(parse_ip) {
                Some(Some(ip)) => Some(ip),
                Some(None) => {
                    say!(sys, "l2tp: {}: bad bind address\n", if name.is_empty() { "default" } else { name });
                    continue;
                }
                None if name.is_empty() => None,
                None => {
                    say!(sys, "l2tp: {}: no bind address (cfg l2tp {}.bind a.b.c.d)\n", name, name);
                    continue;
                }
            };
            let pool = match get(s, "pool").and_then(parse_ip) {
                Some(p) => p & 0xFFFF_FF00,
                None if name.is_empty() => 0x0A00_0000,
                None => {
                    named += 1;
                    0x0A00_0000 | named << 16
                }
            };
            let mut cfg = Config { host_name: String::from("rustros"), pool, ..Config::default() };
            if let Some(d) = get(s, "dns") {
                let l: Vec<Ip> = d.split(',').filter_map(|x| parse_ip(x.trim())).collect();
                if let [a, rest @ ..] = &l[..] {
                    cfg.dns = [*a, rest.first().copied().unwrap_or(*a)];
                }
            }
            if let Some(m) = get(s, "mtu").and_then(|m| m.parse::<u16>().ok()) {
                cfg.mru = m.clamp(576, 1460);
            }
            let own = accounts(s);
            cfg.accounts = if own.is_empty() { shared.clone() } else { own };
            let mss = cfg.mru - 40;
            let users = cfg.accounts.len();
            let ports = (PORTS.0 + k as u16 * span, PORTS.0 + (k as u16 + 1) * span - 1);
            let egress = get(s, "egress").and_then(parse_ip).or(bind).unwrap_or(primary);
            // keep what runs where nothing important changed
            let mut inst = match old.iter().position(|i| i.name == *name) {
                Some(p) => {
                    let mut i = old.swap_remove(p);
                    if i.server.config().pool == pool {
                        i.server.set_config(cfg);
                    } else {
                        i.server = Server::new(cfg);
                        i.local_of.clear();
                    }
                    if i.nat.config().mss != Some(mss) || i.nat.config().ports != ports {
                        i.nat = Nat::new(nat_core::Config { mss: Some(mss), ports, ..nat_core::Config::default() }, sys.random());
                    }
                    i.bind = bind;
                    i.pool = pool;
                    i
                }
                None => Instance {
                    name: String::from(*name),
                    bind,
                    server: Server::new(cfg),
                    nat: Nat::new(nat_core::Config { mss: Some(mss), ports, ..nat_core::Config::default() }, sys.random()),
                    pool,
                    local_of: BTreeMap::new(),
                },
            };
            inst.nat.set_default_egress(egress);
            if !quiet {
                say!(
                    sys,
                    "l2tp: {} on {}: pool {}/24, egress {}, {}\n",
                    inst.label(),
                    bind.map_or(String::from("any address"), |b| format!("{}", IpFmt(b))),
                    IpFmt(pool),
                    IpFmt(egress),
                    if users == 0 { String::from("NO ACCOUNTS: anyone may connect") } else { format!("{users} accounts") }
                );
            }
            self.instances.push(inst);
        }
        // pools must not overlap: a client's address names its instance
        for (i, a) in self.instances.iter().enumerate() {
            if self.instances[..i].iter().any(|b| b.pool == a.pool) && !quiet {
                say!(sys, "l2tp: {} uses the pool of another instance: set {}.pool\n", a.label(), a.label());
            }
        }
        if self.instances.is_empty() && !quiet {
            say!(sys, "l2tp: no instance serves (bind off and no named ones)\n");
        }
        self.shown = mine;
        self.applied = text;
    }

    /// The instance serving local address `dst`.
    fn instance_for(&self, dst: Ip) -> Option<usize> {
        self.instances
            .iter()
            .position(|i| i.bind == Some(dst))
            .or_else(|| self.instances.iter().position(|i| i.bind.is_none()).filter(|_| !self.instances.iter().any(|i| i.bind == Some(dst))))
    }

    fn report(&mut self, sys: &mut dyn Sys) {
        for (ii, e) in core::mem::take(&mut self.events) {
            let Some(inst) = self.instances.get_mut(ii) else { continue };
            let label = String::from(inst.label());
            let nat = &mut inst.nat;
            match e {
                Event::Up { ip, peer, user, egress } => {
                    nat.set_egress(ip, egress);
                    let shown = if user.is_empty() { String::from("(no account)") } else { user };
                    say!(sys, "l2tp: {}: {} {}:{} up as {}, egress {}\n", label, shown, IpFmt(peer.0), peer.1, IpFmt(ip), IpFmt(nat.egress_of(ip)));
                }
                Event::Down { ip } => {
                    nat.remove_host(ip);
                    nat.set_egress(ip, None);
                    say!(sys, "l2tp: {}: {} down\n", label, IpFmt(ip));
                }
                Event::AuthFailed { peer, user } => say!(sys, "l2tp: {}: {}:{} wrong password for {:?}\n", label, IpFmt(peer.0), peer.1, user),
                Event::NoPap { peer } => say!(sys, "l2tp: {}: {}:{} refuses PAP (allow unencrypted passwords on the client)\n", label, IpFmt(peer.0), peer.1),
                Event::PoolFull { peer } => say!(sys, "l2tp: {}: {}:{} turned away, address pool full\n", label, IpFmt(peer.0), peer.1),
            }
        }
    }

    /// A control message (or anything L2TP over UDP) to `peer`, from `src`.
    fn send_udp(pk: &mut dyn Packet, src: Ip, peer: Peer, payload: &[u8]) {
        let total = 20 + 8 + payload.len();
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0]);
        p.extend_from_slice(&src.to_be_bytes());
        p.extend_from_slice(&peer.0.to_be_bytes());
        ip_fix(&mut p);
        p.extend_from_slice(&PORT.to_be_bytes());
        p.extend_from_slice(&peer.1.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]); // no UDP checksum (IPv4 allows it; L2TP needs none)
        p.extend_from_slice(payload);
        pk.send_packet(&p);
    }

    /// Put the client's IP packet (the frame's data) into its tunnel and
    /// transmit; the frame must start at the IP header with `HEADROOM` free.
    fn encap(&mut self, pk: &mut dyn Packet, f: &mut Frame, ii: usize, client: Ip) {
        let inst = &self.instances[ii];
        let Some(r) = inst.server.route(client) else {
            f.verdict = Verdict::Drop;
            return;
        };
        let inner = be16(f.data(), 2) as usize;
        let local = inst.local_of.get(&r.peer).copied().or(inst.bind);
        let Some((out, hop)) = (match local {
            Some(l) => pk.route_from(l, r.peer.0),
            None => pk.route(r.peer.0),
        }) else {
            f.verdict = Verdict::Drop;
            return;
        };
        let Some(nic) = self.nics.get(out).copied() else { return };
        let src = local.unwrap_or(nic.ip);
        if 20 + 8 + DATA_HEADER + inner > nic.mtu {
            // too big for the tunnel: ask the sender to send smaller packets
            if f.data()[6] & 0x40 != 0 {
                if let Some(e) = icmp_error(nic.ip, f.data(), 3, 4, (nic.mtu - 20 - 8 - DATA_HEADER) as u16) {
                    pk.send_packet(&e);
                }
            }
            f.verdict = Verdict::Drop;
            return;
        }
        f.set_len(inner);
        let Some(h) = f.push_front(ENCAP) else {
            f.verdict = Verdict::Drop;
            return;
        };
        let mac = pk.neighbor(out, hop);
        h[6..12].copy_from_slice(&nic.mac);
        h[12..14].copy_from_slice(&[8, 0]);
        let ip = &mut h[ETH..ETH + 20];
        let total = (20 + 8 + DATA_HEADER + inner) as u16;
        ip.copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[12..16].copy_from_slice(&src.to_be_bytes());
        ip[16..20].copy_from_slice(&r.peer.0.to_be_bytes());
        ip_fix(ip);
        let udp = &mut h[ETH + 20..ETH + 28];
        udp[0..2].copy_from_slice(&PORT.to_be_bytes());
        udp[2..4].copy_from_slice(&r.peer.1.to_be_bytes());
        udp[4..6].copy_from_slice(&(total - 20).to_be_bytes());
        udp[6..8].fill(0); // no UDP checksum (IPv4 allows it; L2TP needs none)
        h[ETH + 28..ENCAP].copy_from_slice(&data_header(&r));
        match mac {
            Some(mac) => {
                f.data_mut()[..6].copy_from_slice(&mac);
                f.nic = out as u8;
                f.verdict = Verdict::Transmit;
            }
            None => {
                pk.send_packet(&f.data()[ETH..]);
                f.verdict = Verdict::Consumed;
            }
        }
    }

    /// A packet from a client of instance `ii`, already stripped to its IP header.
    fn from_client(&mut self, pk: &mut dyn Packet, now: u64, f: &mut Frame, ii: usize, client: Ip) {
        let d = f.data();
        let dst = ip_at(d, 16);
        let pool = self.instances[ii].pool;
        let server_ip = pool | 1;
        if dst == server_ip {
            // ping the server: answer in place
            let ihl = (d[0] & 15) as usize * 4;
            let total = be16(d, 2) as usize;
            if d[9] == 1 && total >= ihl + 8 && d[ihl] == 8 {
                let p = f.data_mut();
                p[12..16].copy_from_slice(&server_ip.to_be_bytes());
                p[16..20].copy_from_slice(&client.to_be_bytes());
                p[8] = 64;
                ip_fix(p);
                p[ihl] = 0;
                p[ihl + 2..ihl + 4].fill(0);
                let c = checksum(&p[ihl..total], 0);
                p[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
                return self.encap(pk, f, ii, client);
            }
            f.verdict = Verdict::Drop;
            return;
        }
        if dst & 0xFFFF_FF00 == pool {
            // client to client (of this instance), straight through the switch
            return self.encap(pk, f, ii, dst);
        }
        let nat = &mut self.instances[ii].nat;
        let Some((mut out, mut hop)) = pk.route(dst) else {
            f.verdict = Verdict::Drop;
            return;
        };
        match nat.outbound(now, f.data_mut(), 0, false) {
            // out of the egress address's own WAN
            Ok(egress) => {
                if let Some(r) = pk.route_from(egress, dst) {
                    (out, hop) = r;
                }
            }
            Err(nat_core::Drop::TtlExceeded) => {
                if let Some(e) = icmp_error(server_ip, f.data(), 11, 0, 0) {
                    f.set_data(&e);
                    return self.encap(pk, f, ii, client);
                }
                f.verdict = Verdict::Drop;
                return;
            }
            Err(_) => {
                self.dropped += 1;
                f.verdict = Verdict::Drop;
                return;
            }
        }
        let Some(nic) = self.nics.get(out).copied() else { return };
        let total = be16(f.data(), 2) as usize;
        match pk.neighbor(out, hop) {
            Some(mac) => {
                let Some(h) = f.push_front(ETH) else { return };
                h[..6].copy_from_slice(&mac);
                h[6..12].copy_from_slice(&nic.mac);
                h[12..14].copy_from_slice(&[8, 0]);
                f.set_len(ETH + total);
                f.nic = out as u8;
                f.verdict = Verdict::Transmit;
            }
            None => {
                pk.send_packet(&f.data()[..total]);
                f.verdict = Verdict::Consumed;
            }
        }
    }

    fn frame(&mut self, pk: &mut dyn Packet, now: u64, f: &mut Frame) {
        let nic = f.nic as usize;
        let Some(me) = self.nics.get(nic).copied() else { return };
        let d = f.data();
        if d.len() < ETH + 28 || d[12..14] != [8, 0] || d[..6] != me.mac {
            return;
        }
        let ihl = (d[ETH] & 15) as usize * 4;
        let total = be16(d, ETH + 2) as usize;
        if ihl < 20 || total < ihl + 8 || ETH + total > d.len() {
            return;
        }
        let dst = ip_at(d, ETH + 16);
        // L2TP from a client: the address it was sent to names the instance
        if d[ETH + 9] == 17 && be16(d, ETH + ihl + 2) == PORT && self.local.binary_search(&dst).is_ok() && be16(d, ETH + 6) & 0x3FFF == 0 {
            let Some(ii) = self.instance_for(dst) else { return };
            let peer = (ip_at(d, ETH + 12), be16(d, ETH + ihl));
            let l2 = ETH + ihl + 8;
            let inst = &mut self.instances[ii];
            match inst.server.classify(now, peer, &d[l2..ETH + total]) {
                Data::Control => {
                    let (mut out, mut ev) = (Vec::new(), Vec::new());
                    inst.server.handle(now, peer, &d[l2..ETH + total], &mut out, &mut ev);
                    inst.local_of.insert(peer, dst);
                    for (p, msg) in out {
                        Self::send_udp(pk, dst, p, &msg);
                    }
                    self.events.extend(ev.into_iter().map(|e| (ii, e)));
                    f.verdict = Verdict::Consumed;
                }
                Data::Drop => f.verdict = Verdict::Drop,
                Data::Ip { client, offset } => {
                    let inner = l2 + offset;
                    let len = be16(d, inner + 2) as usize;
                    if inner + 20 > ETH + total || len < 20 || inner + len > ETH + total {
                        f.verdict = Verdict::Drop;
                        return;
                    }
                    f.pull_front(inner);
                    f.set_len(len);
                    f.offload = Offload::default(); // that was the tunnel's (outer) packet
                    self.from_client(pk, now, f, ii, client);
                }
            }
            return;
        }
        // a reply for a client of some instance?
        for ii in 0..self.instances.len() {
            let nat = &mut self.instances[ii].nat;
            // a big segment or a partial checksum cannot go into the tunnel:
            // plain packets first (they come back here)
            if !f.offload.is_none() {
                if !nat.owns_inbound(now, &f.data()[ETH..]) {
                    continue;
                }
                if !pk.resolve(f, ORDER - 1) {
                    return;
                }
            }
            match nat.inbound(now, &mut f.data_mut()[ETH..], false) {
                Inbound::NotOurs => continue,
                Inbound::Forward { to, .. } => {
                    f.pull_front(ETH);
                    self.encap(pk, f, ii, to);
                }
                Inbound::Drop(_) => {
                    self.dropped += 1;
                    f.verdict = Verdict::Drop;
                }
            }
            return;
        }
    }
}

impl Module for L2tpModule {
    fn name(&self) -> &'static str {
        "l2tp"
    }

    fn order(&self) -> i32 {
        ORDER
    }

    /// Big segments pass by; those for the tunnel are made plain first.
    fn offloads(&self) -> bool {
        true
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::PACKET
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        if now >= self.tick_at {
            self.tick_at = now + TICK_MS;
            for (ii, inst) in self.instances.iter_mut().enumerate() {
                let mut ev = Vec::new();
                inst.server.tick(now, &mut ev);
                inst.nat.expire(now, 4096);
                self.events.extend(ev.into_iter().map(|e| (ii, e)));
                // forget the addresses of tunnels that are gone
                let live: Vec<Peer> = inst.server.sessions().map(|s| s.1).collect();
                inst.local_of.retain(|p, _| live.contains(p));
            }
        }
        if !self.events.is_empty() {
            self.report(sys);
        }
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.instances.is_empty() {
            return;
        }
        let now = sys.now_ms();
        if let Some(pk) = sys.packet() {
            for f in frames.iter_mut() {
                self.frame(pk, now, f);
            }
        }
    }

    fn status(&self) -> String {
        let parts: Vec<String> = self
            .instances
            .iter()
            .map(|i| {
                let clients = i.server.sessions().filter(|x| x.3).count();
                let nat = i.nat.stats();
                let on = i.bind.map_or(String::from("any"), |b| format!("{}", IpFmt(b)));
                format!("{} ({}): {} clients, {} NAT sessions, {} out / {} in packets", i.label(), on, clients, nat.sessions, nat.out_packets, nat.in_packets)
            })
            .collect();
        if parts.is_empty() { String::from("no instance (bind off)") } else { parts.join("; ") }
    }
}
