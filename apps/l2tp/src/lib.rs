//! L2TP VPN server module (L2TPv2 without IPsec, PPP with PAP, as
//! rust-l2tp): clients get an address from a /24 pool and reach the
//! outside through NAT, each user from their own egress address if set.
//!
//! Control messages go through a UDP socket on port 1701 (the slow path).
//! Data packets are caught on the packet path and handled in place: strip
//! the tunnel headers, translate, send on; replies are translated back and
//! get the tunnel headers in the frame's headroom. Clients reach each other
//! directly, and ping the server at the pool's .1.
//!
//! Settings (`cfg l2tp <key> <value>`):
//!
//! ```text
//! user.<name>   password[@egress]   accounts (none: anyone may connect!)
//! egress        a.b.c.d             default egress (default: NIC 0's address)
//! pool          10.0.0.0            client /24, server at .1
//! dns           8.8.8.8,1.1.1.1
//! mtu           1400                tunnel MTU (TCP MSS clamped to it)
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Frame, Module, Packet, SocketAddr, Sys, UdpSocket, Verdict, say};
use rustros_util::wire::{Ip, IpFmt, checksum, parse_ip};
use l2tp_core::{Account, Config, DATA_HEADER, Data, Event, Server, data_header};
use nat_core::{Inbound, Nat, icmp_error};

const PORT: u16 = 1701;
const ETH: usize = 14;
/// Ethernet + IPv4 + UDP + L2TP/PPP in front of a client's packet.
const ENCAP: usize = ETH + 20 + 8 + DATA_HEADER;
const RELOAD_MS: u64 = 2000;
const TICK_MS: u64 = 1000;

#[derive(Clone, Copy, Default)]
struct Nic {
    mac: [u8; 6],
    ip: Ip,
    mtu: usize,
}

#[derive(Default)]
pub struct L2tpModule {
    sock: Option<UdpSocket>,
    server: Option<Server>,
    nat: Option<Nat>,
    nics: Vec<Nic>,
    /// our addresses (any NIC, extra ones too)
    local: Vec<Ip>,
    applied: String,
    /// settings last reported (address changes alone are applied quietly)
    shown: String,
    reload_at: u64,
    tick_at: u64,
    pool: Ip,
    dropped: u64,
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
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).chain(core::iter::once(format!("egress={primary}"))).collect();
        if text == self.applied {
            return;
        }
        let get = |k: &str| settings.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());

        let mut cfg = Config { host_name: String::from("rustros"), ..Config::default() };
        if let Some(p) = get("pool").and_then(parse_ip) {
            cfg.pool = p & 0xFFFF_FF00;
        }
        if let Some(d) = get("dns") {
            let l: Vec<Ip> = d.split(',').filter_map(|s| parse_ip(s.trim())).collect();
            if let [a, rest @ ..] = &l[..] {
                cfg.dns = [*a, rest.first().copied().unwrap_or(*a)];
            }
        }
        if let Some(m) = get("mtu").and_then(|m| m.parse::<u16>().ok()) {
            cfg.mru = m.clamp(576, 1460);
        }
        for (k, v) in &settings {
            let Some(user) = k.strip_prefix("user.") else { continue };
            // the password may contain '@': only an address after the last one is the egress
            let (password, egress) = match v.rsplit_once('@') {
                Some((p, e)) if parse_ip(e).is_some() => (p, parse_ip(e)),
                _ => (v.as_str(), None),
            };
            cfg.accounts.push(Account { user: String::from(user), password: String::from(password), egress });
        }
        let mss = cfg.mru - 40;
        let users = cfg.accounts.len();
        self.pool = cfg.pool;
        match self.server.as_mut() {
            Some(s) if s.config().pool == cfg.pool => s.set_config(cfg),
            _ => self.server = Some(Server::new(cfg)),
        }
        let rebuild = self.nat.as_ref().is_none_or(|n| n.config().mss != Some(mss));
        if rebuild {
            let nc = nat_core::Config { mss: Some(mss), ..nat_core::Config::default() };
            self.nat = Some(Nat::new(nc, sys.random()));
        }
        let egress = get("egress").and_then(parse_ip).unwrap_or(primary);
        self.nat.as_mut().unwrap().set_default_egress(egress);
        let mine: String = settings.iter().map(|(k, v)| format!("{k}={v};")).collect();
        let quiet = mine == self.shown;
        self.shown = mine;
        if !quiet {
        say!(
            sys,
            "l2tp: pool {}/24, egress {}, {}\n",
            IpFmt(self.pool),
            IpFmt(egress),
            if users == 0 { String::from("NO ACCOUNTS: anyone may connect") } else { format!("{users} accounts") }
        );
        }
        self.applied = text;
    }

    fn events(&mut self, sys: &mut dyn Sys, ev: Vec<Event>) {
        let Some(nat) = self.nat.as_mut() else { return };
        for e in ev {
            match e {
                Event::Up { ip, peer, user, egress } => {
                    nat.set_egress(ip, egress);
                    let shown = if user.is_empty() { String::from("(no account)") } else { user };
                    say!(sys, "l2tp: {} {}:{} up as {}, egress {}\n", shown, IpFmt(peer.0), peer.1, IpFmt(ip), IpFmt(nat.egress_of(ip)));
                }
                Event::Down { ip } => {
                    nat.remove_host(ip);
                    nat.set_egress(ip, None);
                    say!(sys, "l2tp: {} down\n", IpFmt(ip));
                }
                Event::AuthFailed { peer, user } => say!(sys, "l2tp: {}:{} wrong password for {:?}\n", IpFmt(peer.0), peer.1, user),
                Event::NoPap { peer } => say!(sys, "l2tp: {}:{} refuses PAP (allow unencrypted passwords on the client)\n", IpFmt(peer.0), peer.1),
                Event::PoolFull { peer } => say!(sys, "l2tp: {}:{} turned away, address pool full\n", IpFmt(peer.0), peer.1),
            }
        }
    }

    /// Put the client's IP packet (the frame's data) into its tunnel and
    /// transmit; the frame must start at the IP header with `HEADROOM` free.
    fn encap(&mut self, pk: &mut dyn Packet, f: &mut Frame, client: Ip) {
        let Some(r) = self.server.as_ref().and_then(|s| s.route(client)) else {
            f.verdict = Verdict::Drop;
            return;
        };
        let inner = be16(f.data(), 2) as usize;
        let Some((out, hop)) = pk.route(r.peer.0) else {
            f.verdict = Verdict::Drop;
            return;
        };
        let Some(nic) = self.nics.get(out).copied() else { return };
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
        ip[12..16].copy_from_slice(&nic.ip.to_be_bytes());
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

    /// A packet from a client, already stripped to its IP header.
    fn from_client(&mut self, pk: &mut dyn Packet, now: u64, f: &mut Frame, client: Ip) {
        let d = f.data();
        let dst = ip_at(d, 16);
        let server_ip = self.pool | 1;
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
                return self.encap(pk, f, client);
            }
            f.verdict = Verdict::Drop;
            return;
        }
        if dst & 0xFFFF_FF00 == self.pool {
            // client to client, straight through the switch
            return self.encap(pk, f, dst);
        }
        let Some(nat) = self.nat.as_mut() else { return };
        let Some((mut out, mut hop)) = pk.route(dst) else {
            f.verdict = Verdict::Drop;
            return;
        };
        match nat.outbound(now, f.data_mut(), 0) {
            // out of the egress address's own WAN
            Ok(egress) => {
                if let Some(r) = pk.route_from(egress, dst) {
                    (out, hop) = r;
                }
            }
            Err(nat_core::Drop::TtlExceeded) => {
                if let Some(e) = icmp_error(server_ip, f.data(), 11, 0, 0) {
                    f.set_data(&e);
                    return self.encap(pk, f, client);
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
        // L2TP data from a client?
        if d[ETH + 9] == 17 && be16(d, ETH + ihl + 2) == PORT && self.local.binary_search(&dst).is_ok() && be16(d, ETH + 6) & 0x3FFF == 0 {
            let peer = (ip_at(d, ETH + 12), be16(d, ETH + ihl));
            let l2 = ETH + ihl + 8;
            let Some(server) = self.server.as_mut() else { return };
            match server.classify(now, peer, &d[l2..ETH + total]) {
                Data::Control => {} // to the socket
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
                    self.from_client(pk, now, f, client);
                }
            }
            return;
        }
        // a reply for a client?
        let Some(nat) = self.nat.as_mut() else { return };
        match nat.inbound(now, &mut f.data_mut()[ETH..]) {
            Inbound::NotOurs => {}
            Inbound::Forward { to, .. } => {
                f.pull_front(ETH);
                self.encap(pk, f, to);
            }
            Inbound::Drop(_) => {
                self.dropped += 1;
                f.verdict = Verdict::Drop;
            }
        }
    }
}

impl Module for L2tpModule {
    fn name(&self) -> &'static str {
        "l2tp"
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::PACKET
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.reload(sys);
        match sys.net().map(|n| n.udp_bind(PORT)) {
            Some(Ok(s)) => self.sock = Some(s),
            other => say!(sys, "l2tp: cannot listen on UDP {}: {:?}\n", PORT, other.map(|r| r.err())),
        }
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        let mut out = Vec::new();
        let mut ev = Vec::new();
        let mut buf = [0u8; 2048];
        while let (Some(sock), Some(net), Some(server)) = (self.sock, sys.net(), self.server.as_mut()) {
            let Ok((n, from)) = net.udp_recv_from(sock, &mut buf) else { break };
            server.handle(now, (from.ip, from.port), &buf[..n], &mut out, &mut ev);
        }
        if now >= self.tick_at {
            self.tick_at = now + TICK_MS;
            if let Some(s) = self.server.as_mut() {
                s.tick(now, &mut ev);
            }
            if let Some(n) = self.nat.as_mut() {
                n.expire(now, 4096);
            }
        }
        if let (Some(sock), Some(net)) = (self.sock, sys.net()) {
            for (peer, p) in out {
                let _ = net.udp_send_to(sock, SocketAddr { ip: peer.0, port: peer.1 }, &p);
            }
        }
        if !ev.is_empty() {
            self.events(sys, ev);
        }
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.server.is_none() {
            return;
        }
        let now = sys.now_ms();
        let Some(pk) = sys.packet() else { return };
        for f in frames.iter_mut() {
            self.frame(pk, now, f);
        }
    }

    fn status(&self) -> String {
        let clients = self.server.as_ref().map_or(0, |s| s.sessions().filter(|x| x.3).count());
        let nat = self.nat.as_ref().map(|n| n.stats()).unwrap_or_default();
        format!("{} clients, {} NAT sessions, {} out / {} in packets", clients, nat.sessions, nat.out_packets, nat.in_packets)
    }
}
