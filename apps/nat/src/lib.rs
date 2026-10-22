//! NAT gateway module: hosts behind the "inside" NICs reach the outside
//! through nat-core, translated in place on the zero-copy packet path.
//!
//! Settings (`cfg nat <key> <value>` in the shell):
//!
//! ```text
//! inside          nic1[,nic2...]    NICs whose hosts are translated (none: idle)
//! outside         nic0[,...]        only traffic leaving through these is
//!                                   translated (default: every interface with
//!                                   a gateway, i.e. each WAN); the rest is
//!                                   left to the router
//! egress          a.b.c.d           default egress address (default: NIC 0's address)
//! egress.<host>   a.b.c.d           egress address of one inside host
//! mss             1360              clamp TCP MSS (tunnels)
//! ports           10000-49151       external port range
//! srcnat.<a.b.c.d> e.f.g.h          static NAT: source a.b.c.d becomes e.f.g.h
//! dstnat.<e.f.g.h> a.b.c.d          static NAT: destination e.f.g.h becomes a.b.c.d
//! ```
//!
//! Egress addresses must be ours: NIC 0's address or an extra address
//! (`ip add`), or the replies never arrive.
//!
//! Static NAT (nat-core's StaticNat) is 1:1, on any interface, every
//! protocol and port: only the address changes, connections are tracked so
//! replies come back (a srcnat needs no dstnat for its replies), and the
//! router module forwards the packet, by its new source: a public address
//! leaves through its own interface. Several dstnat addresses (on several
//! WANs) may lead to one host; each connection answers from its own. The
//! public addresses must reach us: routed here, or added with `ip add`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Frame, Module, Packet, Sys, Verdict, say};
use rustros_util::wire::{Ip, IpFmt, parse_ip};
use nat_core::{Config, Drop, Inbound, Nat, StaticNat, icmp_error};

const ETH: usize = 14;
const RELOAD_MS: u64 = 2000;
const EXPIRE_PER_POLL: usize = 4096;

#[derive(Clone, Copy, Default)]
struct Nic {
    mac: [u8; 6],
    ip: Ip,
    gw: Ip,
    mtu: usize,
}

#[derive(Default)]
pub struct NatModule {
    nat: Option<Nat>,
    /// bit n: NIC n is inside
    inside: u32,
    /// bit n: traffic leaving through NIC n is translated (0: the default route's)
    outside: u32,
    nics: Vec<Nic>,
    /// settings text last applied, to notice changes
    applied: String,
    /// settings last reported (NIC changes alone are applied quietly)
    shown: String,
    reload_at: u64,
    hosts: Vec<Ip>,
    /// our own addresses (any NIC, extra ones too): not NATed
    local: Vec<Ip>,
    dropped: u64,
    /// static NAT (srcnat / dstnat rules)
    fixed: Option<StaticNat>,
}

fn be16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

fn ip_at(p: &[u8], o: usize) -> Ip {
    u32::from_be_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
}

impl NatModule {
    pub fn new() -> NatModule {
        NatModule::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        if let Some(net) = sys.net() {
            self.nics = (0..net.nic_count())
                .filter_map(|i| net.nic_info(i))
                .map(|n| Nic { mac: n.mac, ip: n.ip, gw: n.gw, mtu: n.mtu })
                .collect();
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
        // interface numbers move when a VLAN goes away, addresses change:
        // re-resolve then too
        let names: Vec<String> = sys.net().map(|n| (0..n.nic_count()).map(|i| n.nic_name(i)).collect()).unwrap_or_default();
        let text: String = settings
            .iter()
            .map(|(k, v)| format!("{k}={v};"))
            .chain(names.iter().map(|n| format!("{n};")))
            .chain(self.nics.iter().map(|n| format!("{};", n.ip)))
            .collect();

        if text == self.applied && self.nat.is_some() {
            return;
        }
        let get = |k: &str| settings.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());

        let mut inside = 0u32;
        for n in get("inside").unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match rustros_util::netcmd::find_nic(sys, n) {
                Some(i) if i > 0 && i < 32 => inside |= 1 << i,
                _ => say!(sys, "nat: inside: no interface '{}' (nic1, nic0.20, ...; nic0 is the outside)\n", n),
            }
        }
        let mut outside = 0u32;
        for n in get("outside").unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match rustros_util::netcmd::find_nic(sys, n) {
                Some(i) if i < 32 => outside |= 1 << i,
                _ => say!(sys, "nat: outside: no interface '{}'\n", n),
            }
        }
        self.outside = outside;
        let mut cfg = Config::default();
        if let Some((a, b)) = get("ports").and_then(|p| p.split_once('-')) {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if 1024 <= a && a <= b {
                    cfg.ports = (a, b);
                }
            }
        }
        cfg.mss = get("mss").and_then(|m| m.parse().ok()).filter(|&m| (536..=1460).contains(&m));
        // a new port range or MSS needs a new table (sessions start over)
        let rebuild = self.nat.as_ref().is_none_or(|n| n.config().ports != cfg.ports || n.config().mss != cfg.mss);
        if rebuild {
            self.nat = Some(Nat::new(cfg, sys.random()));
        }
        let nat = self.nat.as_mut().unwrap();
        // default egress: our address towards the default gateway (any
        // interface, a VLAN too), else the first address we have
        let primary = sys
            .packet()
            .and_then(|p| p.route(0x0808_0808))
            .and_then(|(i, _)| self.nics.get(i))
            .map(|n| n.ip)
            .filter(|&ip| ip != 0)
            .or_else(|| self.nics.iter().map(|n| n.ip).find(|&ip| ip != 0))
            .unwrap_or(0);
        nat.set_default_egress(get("egress").and_then(parse_ip).unwrap_or(primary));
        for h in self.hosts.drain(..) {
            nat.set_egress(h, None);
        }
        for (k, v) in &settings {
            let Some(host) = k.strip_prefix("egress.").and_then(parse_ip) else { continue };
            match parse_ip(v) {
                Some(e) => {
                    nat.set_egress(host, Some(e));
                    self.hosts.push(host);
                }
                None => say!(sys, "nat: {}: bad address '{}'\n", k, v),
            }
        }
        self.inside = inside;
        let mut rules = |prefix: &str| -> Vec<(Ip, Ip)> {
            let mut r: Vec<(Ip, Ip)> = Vec::new();
            for (k, v) in &settings {
                let Some(from) = k.strip_prefix(prefix) else { continue };
                match (parse_ip(from), parse_ip(v)) {
                    (Some(a), Some(b)) => r.push((a, b)),
                    _ => say!(sys, "nat: {}: bad rule '{}' (srcnat.10.0.0.5 203.0.113.5)\n", k, v),
                }
            }
            r.sort_unstable();
            r
        };
        let (snat, dnat) = (rules("srcnat."), rules("dstnat."));
        let fixed = self.fixed.get_or_insert_with(|| StaticNat::new(sys.random()));
        fixed.set_rules(snat, dnat);
        let (snat, dnat) = fixed.rules();
        let ins: Vec<String> = (1..32).filter(|&i| inside & (1 << i) != 0).filter_map(|i| names.get(i).cloned()).collect();
        let mine: String = settings.iter().map(|(k, v)| format!("{k}={v};")).collect();
        let quiet = mine == self.shown && !rebuild;
        self.shown = mine;
        if !quiet {
        say!(
            sys,
            "nat: inside {}, egress {}, {} host egress rules, static {} srcnat {} dstnat{}\n",
            if ins.is_empty() { String::from("none") } else { ins.join(",") },
            IpFmt(nat.egress_of(0)),
            self.hosts.len(),
            snat.len(),
            dnat.len(),
            if rebuild { ", table reset" } else { "" }
        );
        for (a, b) in snat {
            say!(sys, "nat: srcnat {} -> {}\n", IpFmt(*a), IpFmt(*b));
        }
        for (a, b) in dnat {
            say!(sys, "nat: dstnat {} -> {}\n", IpFmt(*a), IpFmt(*b));
        }
        }
        self.applied = text;
    }

    /// Send an ICMP error about the packet in `f` (to its source), from `src`.
    fn icmp_back(&self, pk: &mut dyn Packet, f: &Frame, src: Ip, typ: u8, code: u8, mtu: u16) {
        if src == 0 {
            return;
        }
        if let Some(e) = icmp_error(src, &f.data()[ETH..], typ, code, mtu) {
            pk.send_packet(&e);
        }
    }

    /// Hand a translated frame to NIC `out` towards `hop`: rewrite the
    /// Ethernet header and transmit in place, or queue it while ARP resolves.
    fn forward(&mut self, pk: &mut dyn Packet, f: &mut Frame, out: usize, hop: Ip) {
        let total = be16(f.data(), ETH + 2) as usize;
        let Some(nic) = self.nics.get(out).copied() else {
            f.verdict = Verdict::Drop;
            return;
        };
        if total > nic.mtu {
            // too big for the way out: tell the sender if it asked not to fragment
            if f.data()[ETH + 6] & 0x40 != 0 {
                let from = self.nics.get(f.nic as usize).map_or(0, |n| n.ip);
                self.icmp_back(pk, f, from, 3, 4, nic.mtu as u16);
            }
            f.verdict = Verdict::Drop;
            return;
        }
        match pk.neighbor(out, hop) {
            Some(mac) => {
                let d = f.data_mut();
                d[..6].copy_from_slice(&mac);
                d[6..12].copy_from_slice(&nic.mac);
                f.set_len(ETH + total); // drop Ethernet padding
                f.nic = out as u8;
                f.verdict = Verdict::Transmit;
            }
            None => {
                pk.send_packet(&f.data()[ETH..ETH + total]);
                f.verdict = Verdict::Consumed;
            }
        }
    }

    fn frame(&mut self, pk: &mut dyn Packet, now: u64, f: &mut Frame) {
        let nic = f.nic as usize;
        let Some(me) = self.nics.get(nic).copied() else { return };
        let d = f.data();
        // IPv4 to our MAC only (broadcasts, ARP, other hosts: not ours)
        if d.len() < ETH + 20 || d[12..14] != [8, 0] || d[..6] != me.mac || be16(d, ETH + 2) as usize > d.len() - ETH {
            return;
        }
        if let Some(fixed) = self.fixed.as_mut().filter(|x| !x.is_empty()) {
            let local = &self.local;
            let total = be16(f.data(), ETH + 2) as usize;
            if fixed.process(now, &mut f.data_mut()[ETH..ETH + total], &|a| local.binary_search(&a).is_ok()) {
                return; // the router forwards it, by its new source
            }
        }
        let d = f.data();
        let Some(nat) = self.nat.as_mut() else { return };
        if self.inside & (1 << nic) != 0 {
            let dst = ip_at(d, ETH + 16);
            // for the gateway itself, or routed between inside networks: not NAT
            // (by source too: a source route may send this host out of another WAN)
            let Some((out, hop)) = pk.route_from(ip_at(d, ETH + 12), dst) else { return };
            if out < 32 && self.inside & (1 << out) != 0 || self.local.binary_search(&dst).is_ok() {
                return;
            }
            // only what leaves through an outside interface (default: one
            // with a gateway, a WAN); other networks are the router's business
            let wan = if self.outside != 0 {
                out < 32 && self.outside & (1 << out) != 0
            } else {
                self.nics.get(out).is_some_and(|n| n.gw != 0) || pk.route(0x0808_0808).is_some_and(|(i, _)| i == out)
            };
            if !wan {
                return;
            }
            match nat.outbound(now, &mut f.data_mut()[ETH..], nic as u32) {
                // out of the egress address's own WAN
                Ok(egress) => {
                    let (out, hop) = pk.route_from(egress, dst).unwrap_or((out, hop));
                    self.forward(pk, f, out, hop)
                }
                Err(Drop::TtlExceeded) => {
                    self.icmp_back(pk, f, me.ip, 11, 0, 0);
                    f.verdict = Verdict::Drop;
                }
                Err(_) => {
                    self.dropped += 1;
                    f.verdict = Verdict::Drop;
                }
            }
        } else {
            match nat.inbound(now, &mut f.data_mut()[ETH..]) {
                Inbound::NotOurs => {}
                Inbound::Forward { to, tag } => self.forward(pk, f, tag as usize, to),
                Inbound::Drop(Drop::TtlExceeded) => {
                    // the packet is untouched: answer from the address it was sent to
                    let dst = ip_at(f.data(), ETH + 16);
                    self.icmp_back(pk, f, dst, 11, 0, 0);
                    f.verdict = Verdict::Drop;
                }
                Inbound::Drop(_) => {
                    self.dropped += 1;
                    f.verdict = Verdict::Drop;
                }
            }
        }
    }
}

impl Module for NatModule {
    fn name(&self) -> &'static str {
        "nat"
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
        if let Some(n) = self.nat.as_mut() {
            n.expire(now, EXPIRE_PER_POLL);
        }
        if let Some(n) = self.fixed.as_mut() {
            n.expire(now, EXPIRE_PER_POLL);
        }
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.inside == 0 && self.fixed.as_ref().is_none_or(|x| x.is_empty()) {
            return;
        }
        let now = sys.now_ms();
        let Some(pk) = sys.packet() else { return };
        for f in frames.iter_mut() {
            self.frame(pk, now, f);
        }
    }

    fn status(&self) -> String {
        let mut s = match &self.nat {
            Some(n) if self.inside != 0 => {
                let s = n.stats();
                format!("{} sessions, {} out / {} in packets, {} dropped", s.sessions, s.out_packets, s.in_packets, s.dropped)
            }
            _ => String::from("idle (cfg nat inside nic1)"),
        };
        if let Some(x) = self.fixed.as_ref().filter(|x| !x.is_empty()) {
            let (sn, dn) = x.rules();
            s += &format!("; static {} srcnat {} dstnat, {} connections, {} packets", sn.len(), dn.len(), x.stats.conns, x.stats.packets);
        }
        s
    }
}
