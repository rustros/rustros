//! WireGuard module: interfaces of wg-core on the packet path.
//!
//! An interface has a private key, an address in its tunnel network, a UDP
//! port, and peers (public key, allowed IPs, endpoint). It serves both ways:
//!
//! * as a server: peers reach this machine (their packets to our addresses
//!   go to the system's stack, the answers back into the tunnel), each
//!   other, and the rest through NAT (`forward nat`, the default) or as
//!   they are (`forward route`);
//! * as a client (WARP and the like): the LAN `hosts` go out through the
//!   tunnel, translated to our tunnel address (`nat on`, the default).
//!
//! Settings (`cfg wireguard <if>.<key> <value>`):
//!
//! ```text
//! <if>.private        base64          our private key (secret)
//! <if>.address        10.8.0.1/24     our address in the tunnel network
//! <if>.listen         51820           UDP port (default 51820, +1 per interface)
//! <if>.bind           a.b.c.d         the address to serve on (default: any of ours)
//! <if>.forward        nat|route|off   peers' traffic beyond us and them
//! <if>.egress         a.b.c.d         NAT address for that (default: towards the
//!                                     default route)
//! <if>.hosts          10.9.0.5,...    LAN hosts that go out through the tunnel
//! <if>.nat            on|off          those translated to our tunnel address
//! <if>.peer.<n>.public    base64
//! <if>.peer.<n>.allowed   10.8.0.2/32,...   (0.0.0.0/0: everything)
//! <if>.peer.<n>.endpoint  a.b.c.d:port      (none: it must call us first)
//! <if>.peer.<n>.keepalive 25
//! <if>.peer.<n>.psk       base64 (secret)
//! <if>.peer.<n>.reserved  a,b,c | base64   the reserved header bytes (WARP:
//!                                   the client id from its registration)
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use nat_core::{Inbound, Nat};
use rustros_api::{Caps, Frame, Module, Offload, Packet, Param, Sys, Verdict, say};
use rustros_util::wire::{Ip, IpFmt, checksum, parse_cidr, parse_ip};
use wg_core::{Device, Endpoint, Out, PeerConfig, Received, key_from_base64, key_to_base64, public_key};

/// Before NAT (0): hosts sent into a tunnel go there first.
const ORDER: i32 = -10;
const ETH: usize = 14;
const RELOAD_MS: u64 = 2000;
const TICK_MS: u64 = 1000;
const PORT: u16 = 51820;

#[derive(Clone, Copy, Default)]
struct Nic {
    mac: [u8; 6],
    ip: Ip,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Forward {
    Nat,
    Route,
    Off,
}

struct Iface {
    name: String,
    dev: Device,
    peer_names: Vec<String>,
    /// our address in the tunnel network and its mask
    addr: Ip,
    mask: Ip,
    port: u16,
    bind: Option<Ip>,
    /// our address the peers talk to (answers and new handshakes from it)
    local: Ip,
    forward: Forward,
    /// peers to the rest of the world
    out_nat: Nat,
    hosts: Vec<(Ip, Ip)>,
    hosts_nat: bool,
    /// LAN hosts into the tunnel
    in_nat: Nat,
    /// the settings it was made with (a change starts it over)
    sig: String,
    dropped: u64,
}

#[derive(Default)]
pub struct WireGuard {
    ifaces: Vec<Iface>,
    nics: Vec<Nic>,
    local: Vec<Ip>,
    applied: String,
    reload_at: u64,
    tick_at: u64,
    /// the clock for handshake timestamps: (unix seconds at boot)
    boot_unix: u64,
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

fn dec_ttl(p: &mut [u8]) -> bool {
    if p.len() < 20 || p[8] <= 1 {
        return false;
    }
    p[8] -= 1;
    ip_fix(p);
    true
}

/// Reserved bytes: "a,b,c" (decimal), or WARP's base64 client id.
fn parse_reserved(v: &str) -> Option<[u8; 3]> {
    if v.contains(',') {
        let b: Vec<u8> = v.split(',').map(|x| x.trim().parse().ok()).collect::<Option<_>>()?;
        return b.try_into().ok();
    }
    // base64 of three bytes: four characters
    let k = wg_core::key_from_base64(&alloc::format!("{}{}", v.trim().trim_end_matches('='), "A".repeat(39)))?;
    Some([k[0], k[1], k[2]])
}

fn get<'a>(s: &[(&str, &'a str)], k: &str) -> Option<&'a str> {
    s.iter().find(|(x, _)| *x == k).map(|(_, v)| *v)
}

fn nets(v: &str) -> Vec<(Ip, Ip)> {
    v.split(',').map(str::trim).filter_map(|h| parse_cidr(h).or_else(|| parse_ip(h).map(|a| (a, !0)))).map(|(n, m)| (n & m, m)).collect()
}

/// A UDP datagram from `src:sport` to `to`, as an IPv4 packet.
fn udp(src: Ip, sport: u16, to: Endpoint, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0]);
    p.extend_from_slice(&src.to_be_bytes());
    p.extend_from_slice(&to.0.to_be_bytes());
    ip_fix(&mut p);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&to.1.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]); // no UDP checksum (IPv4 allows it; the AEAD covers the data)
    p.extend_from_slice(payload);
    p
}

impl WireGuard {
    pub fn new() -> WireGuard {
        WireGuard::default()
    }

    fn unix_ns(&self, now_ms: u64) -> u64 {
        // monotonic: the boot time from the clock, plus the uptime
        (self.boot_unix * 1000 + now_ms) * 1_000_000
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        if let Some(net) = sys.net() {
            self.nics = (0..net.nic_count()).filter_map(|i| net.nic_info(i)).map(|n| Nic { mac: n.mac, ip: n.ip }).collect();
            self.local = (0..net.nic_count()).flat_map(|i| net.extra_addrs(i)).chain(self.nics.iter().map(|n| n.ip)).filter(|&a| a != 0).collect();
            self.local.sort_unstable();
        }
        if self.boot_unix == 0 && sys.unix_time() != 0 {
            self.boot_unix = sys.unix_time() - sys.now_ms() / 1000;
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
        let primary = sys
            .packet()
            .and_then(|p| p.route(0x0808_0808))
            .and_then(|(i, _)| self.nics.get(i))
            .map(|n| n.ip)
            .unwrap_or(0);
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).chain(core::iter::once(format!("{primary}"))).collect();
        if text == self.applied {
            return;
        }
        let mut by: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
        for (k, v) in &settings {
            match k.split_once('.') {
                Some((name, key)) => by.entry(name).or_default().push((key, v.as_str())),
                None => say!(sys, "wireguard: unknown setting '{}' (cfg wireguard wg0.private ...)\n", k),
            }
        }
        let mut old = core::mem::take(&mut self.ifaces);
        for (k, (name, s)) in by.iter().enumerate() {
            let Some(private) = get(s, "private").and_then(key_from_base64) else {
                say!(sys, "wireguard: {}: needs a private key (cfg wireguard {}.private)\n", name, name);
                continue;
            };
            let Some((addr, mask)) = get(s, "address").and_then(parse_cidr) else {
                say!(sys, "wireguard: {}: needs an address (cfg wireguard {}.address 10.8.0.1/24)\n", name, name);
                continue;
            };
            let port = get(s, "listen").and_then(|p| p.parse().ok()).unwrap_or(PORT + k as u16);
            let sig: String = s.iter().filter(|(k, _)| !matches!(*k, "hosts" | "nat" | "forward" | "egress")).map(|(k, v)| format!("{k}={v};")).collect();
            let forward = match get(s, "forward") {
                Some("route") => Forward::Route,
                Some("off") => Forward::Off,
                _ => Forward::Nat,
            };
            let egress = get(s, "egress").and_then(parse_ip).unwrap_or(primary);
            let hosts = nets(get(s, "hosts").unwrap_or(""));
            let hosts_nat = get(s, "nat") != Some("off");
            // the same keys and peers: keep the sessions
            let mut iface = match old.iter().position(|i| i.name == *name && i.sig == sig) {
                Some(p) => old.swap_remove(p),
                None => {
                    let mut seed = [0u8; 32];
                    for c in seed.chunks_mut(8) {
                        c.copy_from_slice(&sys.random().to_le_bytes());
                    }
                    let mut dev = Device::new(private, &seed);
                    let mut peer_names = Vec::new();
                    // peers: <name>.peer.<peer>.<key>
                    let mut peers: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
                    for (key, v) in s {
                        if let Some((p, pk)) = key.strip_prefix("peer.").and_then(|r| r.split_once('.')) {
                            peers.entry(p).or_default().push((pk, *v));
                        }
                    }
                    for (pn, ps) in &peers {
                        let Some(public) = get(ps, "public").and_then(key_from_base64) else {
                            say!(sys, "wireguard: {}: peer {}: needs a public key\n", name, pn);
                            continue;
                        };
                        let endpoint = get(ps, "endpoint").and_then(|e| {
                            let (ip, port) = e.rsplit_once(':')?;
                            Some((parse_ip(ip)?, port.parse().ok()?))
                        });
                        dev.add_peer(PeerConfig {
                            public,
                            psk: get(ps, "psk").and_then(key_from_base64).unwrap_or([0; 32]),
                            endpoint,
                            keepalive: get(ps, "keepalive").and_then(|k| k.parse().ok()).unwrap_or(0),
                            allowed: nets(get(ps, "allowed").unwrap_or("")),
                            reserved: get(ps, "reserved").and_then(parse_reserved).unwrap_or([0; 3]),
                        });
                        peer_names.push(String::from(*pn));
                    }
                    let r = sys.random();
                    Iface {
                        name: String::from(*name),
                        dev,
                        peer_names,
                        addr,
                        mask,
                        port,
                        bind: None,
                        local: 0,
                        forward,
                        out_nat: Nat::new(nat_core::Config { mss: Some(1380), ..nat_core::Config::default() }, r),
                        hosts: Vec::new(),
                        hosts_nat,
                        in_nat: Nat::new(nat_core::Config { mss: Some(1380), ..nat_core::Config::default() }, r.rotate_left(17)),
                        sig,
                        dropped: 0,
                    }
                }
            };
            iface.forward = forward;
            iface.out_nat.set_default_egress(egress);
            iface.in_nat.set_default_egress(addr);
            iface.hosts = hosts;
            iface.hosts_nat = hosts_nat;
            iface.bind = get(s, "bind").and_then(parse_ip);
            say!(
                sys,
                "wireguard: {} {}/{} port {}, public key {}, {} peers{}\n",
                name,
                IpFmt(addr),
                mask.count_ones(),
                port,
                key_to_base64(&public_key(&private)),
                iface.peer_names.len(),
                if iface.hosts.is_empty() { String::new() } else { format!(", {} host networks out through it", iface.hosts.len()) }
            );
            self.ifaces.push(iface);
        }
        self.applied = text;
    }

    /// Send what wg-core produced: UDP from our address on the port.
    fn send_out(&self, pk: &mut dyn Packet, ii: usize, out: &mut Vec<Out>) {
        let i = &self.ifaces[ii];
        for (to, m) in out.drain(..) {
            let src = i.bind.or((i.local != 0).then_some(i.local)).or_else(|| pk.route(to.0).and_then(|(n, _)| self.nics.get(n)).map(|n| n.ip));
            if let Some(src) = src.filter(|&s| s != 0) {
                pk.send_packet(&udp(src, i.port, to, &m));
            }
        }
    }

    /// An IP packet into interface `ii`'s tunnel, to the peer for its destination.
    fn into_tunnel(&mut self, pk: &mut dyn Packet, now: u64, ii: usize, packet: &[u8]) -> bool {
        let unix = self.unix_ns(now);
        let i = &mut self.ifaces[ii];
        let dst = ip_at(packet, 16);
        let Some(peer) = i.dev.peer_for(dst) else { return false };
        let mut out = Vec::new();
        i.dev.send(now, unix, peer, packet, &mut out);
        self.send_out(pk, ii, &mut out);
        true
    }

    /// A decrypted packet from a peer of interface `ii`: where it goes.
    fn from_tunnel(&mut self, pk: &mut dyn Packet, now: u64, ii: usize, f: &mut Frame, data: &[u8]) {
        let i = &mut self.ifaces[ii];
        let dst = ip_at(data, 16);
        // to a LAN host we sent out through the tunnel (client side)
        if !i.hosts.is_empty() && dst == i.addr {
            let mut p = data.to_vec();
            if i.hosts_nat {
                match i.in_nat.inbound(now, &mut p, false) {
                    Inbound::Forward { to, .. } => {
                        f.set_data(&p);
                        return self.forward_ip(pk, f, to);
                    }
                    _ => {}
                }
            }
        }
        // our tunnel address: it answers ping (services are on our real
        // addresses, which peers reach as below)
        if dst == i.addr {
            let ihl = (data[0] & 15) as usize * 4;
            let total = (be16(data, 2) as usize).min(data.len());
            if data[9] == 1 && total >= ihl + 8 && data[ihl] == 8 {
                let mut r = data[..total].to_vec();
                let src = ip_at(data, 12);
                r[12..16].copy_from_slice(&i.addr.to_be_bytes());
                r[16..20].copy_from_slice(&src.to_be_bytes());
                r[8] = 64;
                ip_fix(&mut r);
                r[ihl] = 0;
                r[ihl + 2..ihl + 4].fill(0);
                let c = checksum(&r[ihl..], 0);
                r[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
                self.into_tunnel(pk, now, ii, &r);
            }
            f.verdict = Verdict::Consumed;
            return;
        }
        // for this machine (any of our real addresses)
        if self.local.binary_search(&dst).is_ok() {
            let n = self.nics.iter().position(|n| n.ip == dst).unwrap_or(0);
            let mac = self.nics.get(n).map_or([0; 6], |n| n.mac);
            let mut frame = Vec::with_capacity(ETH + data.len());
            frame.extend_from_slice(&mac);
            frame.extend_from_slice(&mac);
            frame.extend_from_slice(&[8, 0]);
            frame.extend_from_slice(data);
            f.set_data(&frame);
            f.nic = n as u8;
            f.verdict = Verdict::Pass; // on to the system's stack
            return;
        }
        // to another peer
        if i.dev.peer_for(dst).is_some_and(|p| i.dev.peers[p].cfg.allowed.iter().any(|&(n, m)| m != 0 && dst & m == n)) {
            let mut p = data.to_vec();
            if dec_ttl(&mut p) {
                self.into_tunnel(pk, now, ii, &p);
            }
            f.verdict = Verdict::Consumed;
            return;
        }
        // to a LAN host routed in as it is (client side, nat off)
        if !i.hosts.is_empty() && !i.hosts_nat && i.hosts.iter().any(|&(n, m)| dst & m == n) {
            let mut p = data.to_vec();
            if dec_ttl(&mut p) {
                f.set_data(&p);
                return self.forward_ip(pk, f, dst);
            }
            f.verdict = Verdict::Drop;
            return;
        }
        // beyond: the rest of the world
        let mut p = data.to_vec();
        match i.forward {
            Forward::Nat => match i.out_nat.outbound(now, &mut p, 0, false) {
                Ok(egress) => {
                    f.set_data(&p);
                    let to = ip_at(&p, 16);
                    let route = pk.route_from(egress, to);
                    self.forward_via(pk, f, route)
                }
                Err(_) => {
                    i.dropped += 1;
                    f.verdict = Verdict::Drop;
                }
            },
            Forward::Route if dec_ttl(&mut p) => {
                f.set_data(&p);
                self.forward_ip(pk, f, dst);
            }
            _ => {
                i.dropped += 1;
                f.verdict = Verdict::Drop;
            }
        }
    }

    /// Send an IP packet (the frame's data) towards `to` by the system's routes.
    fn forward_ip(&mut self, pk: &mut dyn Packet, f: &mut Frame, to: Ip) {
        let route = pk.route(to);
        self.forward_via(pk, f, route);
    }

    fn forward_via(&mut self, pk: &mut dyn Packet, f: &mut Frame, route: Option<(usize, Ip)>) {
        let Some((out, hop)) = route else {
            f.verdict = Verdict::Drop;
            return;
        };
        let Some(nic) = self.nics.get(out).copied() else { return };
        let total = be16(f.data(), 2) as usize;
        match pk.neighbor(out, hop) {
            Some(mac) => {
                let Some(h) = f.push_front(ETH) else {
                    pk.send_packet(&f.data()[..total]);
                    f.verdict = Verdict::Consumed;
                    return;
                };
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
        let Some(me) = self.nics.get(f.nic as usize).copied() else { return };
        let d = f.data();
        if d.len() < ETH + 28 || d[12..14] != [8, 0] || d[..6] != me.mac {
            return;
        }
        let ihl = (d[ETH] & 15) as usize * 4;
        let total = be16(d, ETH + 2) as usize;
        if ihl < 20 || total < ihl + 8 || ETH + total > d.len() {
            return;
        }
        let (src, dst) = (ip_at(d, ETH + 12), ip_at(d, ETH + 16));
        let local_dst = self.local.binary_search(&dst).is_ok();
        // WireGuard over UDP to one of our ports
        if d[ETH + 9] == 17 && local_dst && be16(d, ETH + 6) & 0x3FFF == 0 {
            let dport = be16(d, ETH + ihl + 2);
            if let Some(ii) = self.ifaces.iter().position(|i| i.port == dport && i.bind.is_none_or(|b| b == dst)) {
                let from = (src, be16(d, ETH + ihl));
                let msg = d[ETH + ihl + 8..ETH + total].to_vec();
                let unix = self.unix_ns(now);
                let mut out = Vec::new();
                let r = self.ifaces[ii].dev.handle(now, unix, from, &msg, &mut out);
                self.ifaces[ii].local = dst;
                self.send_out(pk, ii, &mut out);
                f.offload = Offload::default();
                f.verdict = Verdict::Consumed;
                if let Received::Packet { data, .. } = r {
                    self.from_tunnel(pk, now, ii, f, &data);
                }
                return;
            }
        }
        // a LAN host going out through a tunnel, beyond our own networks
        if let Some(ii) = self.ifaces.iter().position(|i| i.hosts.iter().any(|&(n, m)| src & m == n)) {
            let beyond = !local_dst && dst < 0xE000_0000 && pk.route(dst).is_none_or(|(_, hop)| hop != dst);
            if beyond {
                if !f.offload.is_none() && !pk.resolve(f, ORDER - 1) {
                    return;
                }
                let mut p = f.data()[ETH..ETH + total].to_vec();
                let ok = if self.ifaces[ii].hosts_nat { self.ifaces[ii].in_nat.outbound(now, &mut p, 0, false).is_ok() } else { dec_ttl(&mut p) };
                f.verdict = if ok && self.into_tunnel(pk, now, ii, &p) { Verdict::Consumed } else { Verdict::Drop };
                return;
            }
        }
        // replies for peers that went out through NAT
        for ii in 0..self.ifaces.len() {
            let i = &mut self.ifaces[ii];
            if i.forward != Forward::Nat || !i.out_nat.owns_inbound(now, &f.data()[ETH..ETH + total]) {
                continue;
            }
            if !f.offload.is_none() && !pk.resolve(f, ORDER - 1) {
                return;
            }
            let mut p = f.data()[ETH..ETH + total].to_vec();
            if let Inbound::Forward { .. } = i.out_nat.inbound(now, &mut p, false) {
                f.verdict = if self.into_tunnel(pk, now, ii, &p) { Verdict::Consumed } else { Verdict::Drop };
            }
            return;
        }
        // routed to a peer's network (forward route, or a site behind it)
        if !local_dst {
            for ii in 0..self.ifaces.len() {
                let i = &self.ifaces[ii];
                let routed = i.dev.peer_for(dst).is_some_and(|p| i.dev.peers[p].cfg.allowed.iter().any(|&(n, m)| m != 0 && dst & m == n));
                if routed && i.hosts.is_empty() {
                    if !f.offload.is_none() && !pk.resolve(f, ORDER - 1) {
                        return;
                    }
                    let mut p = f.data()[ETH..ETH + total].to_vec();
                    f.verdict = if dec_ttl(&mut p) && self.into_tunnel(pk, now, ii, &p) { Verdict::Consumed } else { Verdict::Drop };
                    return;
                }
            }
        }
    }
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "<if>.private", kind: "secret", default: "", help: "our private key (base64)" },
    Param { key: "<if>.address", kind: "network", default: "", help: "our address in the tunnel network, e.g. 10.8.0.1/24" },
    Param { key: "<if>.listen", kind: "number", default: "51820", help: "UDP port" },
    Param { key: "<if>.bind", kind: "address", default: "", help: "the address to serve on (default: any of ours)" },
    Param { key: "<if>.forward", kind: "choice:nat|route|off", default: "nat", help: "peers' traffic beyond us and them" },
    Param { key: "<if>.egress", kind: "address", default: "", help: "NAT address for that (default: towards the default route)" },
    Param { key: "<if>.hosts", kind: "list", default: "", help: "LAN hosts or networks that go out through the tunnel" },
    Param { key: "<if>.nat", kind: "switch", default: "on", help: "those translated to our tunnel address" },
    Param { key: "<if>.peer.<n>.public", kind: "text", default: "", help: "the peer's public key (base64)" },
    Param { key: "<if>.peer.<n>.allowed", kind: "list", default: "", help: "its networks, e.g. 10.8.0.2/32 (0.0.0.0/0: everything)" },
    Param { key: "<if>.peer.<n>.endpoint", kind: "text", default: "", help: "a.b.c.d:port (none: it must call us first)" },
    Param { key: "<if>.peer.<n>.keepalive", kind: "number", default: "", help: "seconds between keepalives" },
    Param { key: "<if>.peer.<n>.psk", kind: "secret", default: "", help: "preshared key (base64)" },
    Param { key: "<if>.peer.<n>.reserved", kind: "text", default: "", help: "reserved header bytes: a,b,c or base64 (WARP client id)" },
];

impl Module for WireGuard {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::PACKET
    }

    fn order(&self) -> i32 {
        ORDER
    }

    /// Big segments pass by; those for a tunnel are made plain first.
    fn offloads(&self) -> bool {
        true
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
            let unix = self.unix_ns(now);
            for ii in 0..self.ifaces.len() {
                let mut out = Vec::new();
                let i = &mut self.ifaces[ii];
                i.dev.tick(now, unix, &mut out);
                i.out_nat.expire(now, 4096);
                i.in_nat.expire(now, 4096);
                if let Some(pk) = sys.packet() {
                    self.send_out(pk, ii, &mut out);
                }
            }
        }
    }

    /// What the system's stack sends into a tunnel network (answers to
    /// peers that reached this machine).
    fn on_egress(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.ifaces.is_empty() {
            return;
        }
        let now = sys.now_ms();
        let Some(pk) = sys.packet() else { return };
        for f in frames.iter_mut() {
            let d = f.data();
            if f.verdict != Verdict::Transmit || d.len() < ETH + 20 || d[12..14] != [8, 0] {
                continue;
            }
            let dst = ip_at(d, ETH + 16);
            let Some(ii) = self.ifaces.iter().position(|i| i.mask != !0 && dst & i.mask == i.addr & i.mask && dst != i.addr) else { continue };
            if !f.offload.is_none() && !pk.resolve(f, i32::MAX) {
                continue;
            }
            let total = be16(f.data(), ETH + 2) as usize;
            let p = f.data()[ETH..(ETH + total).min(f.data().len())].to_vec();
            if self.into_tunnel(pk, now, ii, &p) {
                f.verdict = Verdict::Consumed;
            }
        }
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.ifaces.is_empty() {
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
            .ifaces
            .iter()
            .map(|i| {
                let peers: Vec<String> = i
                    .dev
                    .peers
                    .iter()
                    .zip(&i.peer_names)
                    .map(|(p, n)| {
                        let ep = p.endpoint.map_or(String::from("-"), |e| format!("{}:{}", IpFmt(e.0), e.1));
                        format!("{} {} {} rx {} tx {}", n, ep, if p.is_up() { "up" } else { "down" }, p.rx_bytes, p.tx_bytes)
                    })
                    .collect();
                format!("{} {}/{} port {}: {}", i.name, IpFmt(i.addr), i.mask.count_ones(), i.port, if peers.is_empty() { String::from("no peers") } else { peers.join(", ") })
            })
            .collect();
        if parts.is_empty() { String::from("no interface (cfg wireguard wg0.private ...)") } else { parts.join("; ") }
    }
}
