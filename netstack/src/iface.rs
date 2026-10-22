//! Host interfaces: Ethernet + ARP + IPv4 + ICMP echo, one per NIC, each
//! with a primary address and optional extra addresses (for NAT egress), and
//! the routing between them.

use alloc::vec::Vec;

use rustros_util::wire::{BROADCAST, Ip, be16, be32, checksum, pseudo};
pub use rustros_util::wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};

use crate::Link;

const ETH_ARP: u16 = 0x0806;
const ETH_IP: u16 = 0x0800;
const ARP_TTL_MS: u64 = 10 * 60 * 1000;
const PENDING_MS: u64 = 1000;

/// A received IPv4 packet addressed to us.
pub struct IpPkt<'a> {
    pub src: Ip,
    pub dst: Ip,
    pub proto: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

pub struct ArpEntry {
    pub ip: Ip,
    pub mac: [u8; 6],
    pub seen: u64,
}

#[derive(Default)]
pub struct Stats {
    pub rx: u64,
    pub tx: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

pub struct Iface {
    /// Index of the NIC (for `Link::send`).
    pub nic: usize,
    pub mac: [u8; 6],
    pub ip: Ip,
    pub mask: Ip,
    pub gw: Ip,
    /// Largest IP packet we send (cloud networks often use less than 1500).
    pub mtu: usize,
    /// Extra addresses, sorted (answered in ARP and ping, used as NAT
    /// egress; the system's own sockets live on the primary address).
    pub extra: Vec<Ip>,
    pub arp: Vec<ArpEntry>,
    /// IP packets waiting for an ARP reply: (next hop, packet, queued at)
    pending: Vec<(Ip, Vec<u8>, u64)>,
    ip_id: u16,
    pub stats: Stats,
}

impl Iface {
    pub fn new(nic: usize, mac: [u8; 6], ip: Ip, mask: Ip, gw: Ip) -> Iface {
        Iface { nic, mac, ip, mask, gw, mtu: 1500, extra: Vec::new(), arp: Vec::new(), pending: Vec::new(), ip_id: 1, stats: Stats::default() }
    }

    pub fn on_link(&self, ip: Ip) -> bool {
        self.ip != 0 && ip & self.mask == self.ip & self.mask
    }

    /// One of our addresses on this interface.
    pub fn is_local(&self, ip: Ip) -> bool {
        ip != 0 && (ip == self.ip || self.extra.binary_search(&ip).is_ok())
    }

    fn eth_send(&mut self, link: &mut dyn Link, dst: [u8; 6], ty: u16, payload: &[u8]) {
        let mut f = Vec::with_capacity(14 + payload.len().max(46));
        f.extend_from_slice(&dst);
        f.extend_from_slice(&self.mac);
        f.extend_from_slice(&ty.to_be_bytes());
        f.extend_from_slice(payload);
        f.resize(f.len().max(60), 0);
        if link.send(self.nic, &f) {
            self.stats.tx += 1;
        } else {
            self.stats.tx_dropped += 1;
        }
    }

    fn arp_send(&mut self, link: &mut dyn Link, op: u16, spa: Ip, tha: [u8; 6], tpa: Ip) {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(&self.mac);
        p.extend_from_slice(&spa.to_be_bytes());
        p.extend_from_slice(&tha);
        p.extend_from_slice(&tpa.to_be_bytes());
        let dst = if op == 1 { [0xFF; 6] } else { tha };
        self.eth_send(link, dst, ETH_ARP, &p);
    }

    fn arp_learn(&mut self, link: &mut dyn Link, ip: Ip, mac: [u8; 6]) {
        let now = link.now_ms();
        match self.arp.iter_mut().find(|e| e.ip == ip) {
            Some(e) => {
                e.mac = mac;
                e.seen = now;
            }
            None => {
                if self.arp.len() >= 64 {
                    let oldest = (0..self.arp.len()).min_by_key(|&i| self.arp[i].seen).unwrap_or(0);
                    self.arp.swap_remove(oldest);
                }
                self.arp.push(ArpEntry { ip, mac, seen: now });
            }
        }
        // flush packets that were waiting for this neighbour
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 == ip {
                let (_, pkt, _) = self.pending.swap_remove(i);
                if !pkt.is_empty() {
                    self.eth_send(link, mac, ETH_IP, &pkt);
                }
            } else {
                i += 1;
            }
        }
    }

    fn handle_arp(&mut self, link: &mut dyn Link, p: &[u8]) {
        if p.len() < 28 || be16(p, 0) != 1 || be16(p, 2) != ETH_IP || p[4] != 6 || p[5] != 4 {
            return;
        }
        let op = be16(p, 6);
        let sha: [u8; 6] = p[8..14].try_into().unwrap();
        let spa = be32(p, 14);
        let tpa = be32(p, 24);
        if spa == 0 || self.ip == 0 {
            return;
        }
        if self.is_local(tpa) {
            self.arp_learn(link, spa, sha);
            if op == 1 {
                self.arp_send(link, 2, tpa, sha, spa);
            }
        } else if self.arp.iter().any(|e| e.ip == spa) {
            self.arp_learn(link, spa, sha); // refresh, e.g. gratuitous ARP
        }
    }

    /// Process one received frame. ARP and ICMP echo requests are answered
    /// here; other IPv4 packets for us are returned to the caller.
    /// `elsewhere(ip)`: an address of another interface (pings to those are
    /// answered too, as on Linux).
    pub fn handle<'a>(&mut self, link: &mut dyn Link, frame: &'a [u8], elsewhere: &dyn Fn(Ip) -> bool) -> Option<IpPkt<'a>> {
        self.stats.rx += 1;
        if frame.len() < 14 {
            return None;
        }
        let ty = be16(frame, 12);
        let p = &frame[14..];
        if ty == ETH_ARP {
            self.handle_arp(link, p);
            return None;
        }
        if ty != ETH_IP || p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0xF) as usize * 4;
        let total = be16(p, 2) as usize;
        if ihl < 20 || total < ihl || total > p.len() || checksum(&p[..ihl], 0) != 0 {
            self.stats.rx_dropped += 1;
            return None;
        }
        if be16(p, 6) & 0x3FFF != 0 {
            self.stats.rx_dropped += 1; // fragments are not supported
            return None;
        }
        let src = be32(p, 12);
        let dst = be32(p, 16);
        let bcast = self.ip | !self.mask;
        let local = self.is_local(dst) || elsewhere(dst);
        if !local && dst != BROADCAST && dst != bcast {
            return None;
        }
        if self.on_link(src) && src != 0 {
            let mac: [u8; 6] = frame[6..12].try_into().unwrap();
            if self.arp.iter().any(|e| e.ip == src && e.mac != mac) || !self.arp.iter().any(|e| e.ip == src) {
                self.arp_learn(link, src, mac);
            }
        }
        let pkt = IpPkt { src, dst, proto: p[9], ttl: p[8], payload: &p[ihl..total] };
        if pkt.proto == PROTO_ICMP && local {
            let m = pkt.payload;
            if m.len() >= 8 && m[0] == 8 && checksum(m, 0) == 0 {
                let mut r = m.to_vec();
                r[0] = 0;
                r[2..4].fill(0);
                let c = checksum(&r, 0);
                r[2..4].copy_from_slice(&c.to_be_bytes());
                // answer from the address that was pinged, back the way it
                // came: to the MAC it came from (a router, with several WANs)
                let mac: [u8; 6] = frame[6..12].try_into().unwrap();
                let p = self.ip_packet(dst, src, PROTO_ICMP, &r);
                self.eth_send(link, mac, ETH_IP, &p);
                return None;
            }
        }
        if dst != self.ip && dst != BROADCAST && dst != bcast && !(matches!(pkt.proto, PROTO_ICMP | PROTO_TCP) && local) {
            return None; // extra addresses serve NAT, ping, and what we started from them
        }
        Some(pkt)
    }

    fn ip_packet(&mut self, src: Ip, dst: Ip, proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(20 + payload.len());
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&self.ip_id.to_be_bytes());
        p.extend_from_slice(&[0x40, 0, 64, proto, 0, 0]); // DF, TTL 64
        p.extend_from_slice(&src.to_be_bytes());
        p.extend_from_slice(&dst.to_be_bytes());
        let c = checksum(&p, 0);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(payload);
        self.ip_id = self.ip_id.wrapping_add(1);
        p
    }

    /// Send an IPv4 packet from our primary address. Returns false if it
    /// was dropped (it may also be queued until ARP resolves, which counts
    /// as sent).
    pub fn send_ip(&mut self, link: &mut dyn Link, dst: Ip, proto: u8, payload: &[u8]) -> bool {
        if 20 + payload.len() > self.mtu {
            self.stats.tx_dropped += 1;
            return false;
        }
        let hop = if dst == BROADCAST || self.on_link(dst) { dst } else { self.gw };
        let p = self.ip_packet(self.ip, dst, proto, payload);
        self.send_packet(link, hop, p)
    }

    /// Send a finished IPv4 packet to next hop `hop` (resolving it with ARP).
    pub fn send_packet(&mut self, link: &mut dyn Link, hop: Ip, p: Vec<u8>) -> bool {
        if hop == BROADCAST || (self.ip != 0 && hop == self.ip | !self.mask) {
            self.eth_send(link, [0xFF; 6], ETH_IP, &p);
            return true;
        }
        if hop == 0 {
            self.stats.tx_dropped += 1;
            return false;
        }
        if let Some(mac) = self.neighbor(link, hop) {
            self.eth_send(link, mac, ETH_IP, &p);
            return true;
        }
        if self.pending.len() >= 32 {
            self.stats.tx_dropped += 1;
            return false;
        }
        self.pending.push((hop, p, link.now_ms()));
        true
    }

    /// The MAC of neighbour `ip`; None (and an ARP request goes out, at most
    /// once a second) if it is not known yet.
    pub fn neighbor(&mut self, link: &mut dyn Link, ip: Ip) -> Option<[u8; 6]> {
        if let Some(e) = self.arp.iter().find(|e| e.ip == ip) {
            return Some(e.mac);
        }
        let now = link.now_ms();
        if !self.pending.iter().any(|q| q.0 == ip && now - q.2 < PENDING_MS) || self.pending.is_empty() {
            let spa = self.ip;
            self.arp_send(link, 1, spa, [0; 6], ip);
            // remember that we asked, so the next caller does not flood
            self.pending.push((ip, Vec::new(), now));
        }
        None
    }

    pub fn send_udp(&mut self, link: &mut dyn Link, dst: Ip, sport: u16, dport: u16, data: &[u8]) -> bool {
        let len = 8 + data.len();
        let mut u = Vec::with_capacity(len);
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&(len as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(data);
        let c = match checksum(&u, pseudo(self.ip, dst, PROTO_UDP, len)) {
            0 => 0xFFFF,
            c => c,
        };
        u[6..8].copy_from_slice(&c.to_be_bytes());
        self.send_ip(link, dst, PROTO_UDP, &u)
    }

    /// Expire stale ARP entries and unanswered pending packets.
    pub fn poll(&mut self, link: &mut dyn Link) {
        let now = link.now_ms();
        let before = self.pending.iter().filter(|q| !q.1.is_empty()).count();
        self.pending.retain(|q| now - q.2 < PENDING_MS);
        let after = self.pending.iter().filter(|q| !q.1.is_empty()).count();
        self.stats.tx_dropped += before.saturating_sub(after) as u64;
        self.arp.retain(|e| now - e.seen < ARP_TTL_MS);
    }
}

/// Parse a UDP datagram: (source port, destination port, payload).
pub fn parse_udp<'a>(p: &IpPkt<'a>) -> Option<(u16, u16, &'a [u8])> {
    let u = p.payload;
    if u.len() < 8 {
        return None;
    }
    let len = be16(u, 4) as usize;
    if len < 8 || len > u.len() {
        return None;
    }
    if be16(u, 6) != 0 && checksum(&u[..len], pseudo(p.src, p.dst, PROTO_UDP, len)) != 0 {
        return None;
    }
    Some((be16(u, 0), be16(u, 2), &u[8..len]))
}

/// A static route: `net`/`mask` via `gw`, for packets from `src`/`src_mask`
/// only (mask 0: from anywhere).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Route {
    pub net: Ip,
    pub mask: Ip,
    pub gw: Ip,
    pub src: Ip,
    pub src_mask: Ip,
}

/// All interfaces, and routing between them (several WANs too):
///
/// 1. connected networks (the longest prefix);
/// 2. static routes (`.1`), whose gateway is on a connected network: the
///    longest destination prefix, then the longest source prefix, so a
///    route for one source beats the general one to the same place;
/// 3. a packet from one of our addresses leaves through that address's
///    interface, if it has a gateway (replies go back the WAN they came in
///    on) — as a source route for that address alone to anywhere;
/// 4. the first interface with a gateway.
pub struct Ifaces(pub Vec<Iface>, pub Vec<Route>);

impl Ifaces {
    fn connected(&self, dst: Ip) -> Option<usize> {
        (0..self.0.len()).filter(|&i| self.0[i].on_link(dst)).max_by_key(|&i| self.0[i].mask.count_ones())
    }

    /// (interface, next hop) for `dst`.
    pub fn route(&self, dst: Ip) -> Option<(usize, Ip)> {
        self.route_from(0, dst)
    }

    /// (interface, next hop) for a packet from `src` (0: any) to `dst`.
    pub fn route_from(&self, src: Ip, dst: Ip) -> Option<(usize, Ip)> {
        if let Some(i) = self.connected(dst) {
            return Some((i, dst));
        }
        let from = |r: &Route| if r.src_mask == 0 { r.src == 0 } else { src != 0 && src & r.src_mask == r.src };
        let mut best = self
            .1
            .iter()
            .filter(|r| dst & r.mask == r.net && from(r))
            .filter_map(|r| Some(((r.mask.count_ones(), r.src_mask.count_ones()), self.connected(r.gw)?, r.gw)))
            .max_by_key(|(k, _, _)| *k);
        if src != 0 && best.is_none_or(|(k, _, _)| k < (0, 32)) {
            if let Some(i) = self.0.iter().position(|f| f.gw != 0 && f.is_local(src)) {
                best = Some(((0, 32), i, self.0[i].gw));
            }
        }
        if let Some((_, i, gw)) = best {
            return Some((i, gw));
        }
        self.0.iter().position(|f| f.gw != 0 && f.ip != 0).map(|i| (i, self.0[i].gw))
    }

    /// Our address on the interface that leads to `dst`.
    pub fn src_for(&self, dst: Ip) -> Ip {
        self.route(dst).map_or(self.0[0].ip, |(i, _)| self.0[i].ip)
    }

    pub fn mtu_for(&self, dst: Ip) -> usize {
        self.route(dst).map_or(self.0[0].mtu, |(i, _)| self.0[i].mtu)
    }

    /// Send from the address of the outgoing interface; limited broadcasts
    /// go out of the first interface.
    pub fn send_ip(&mut self, link: &mut dyn Link, dst: Ip, proto: u8, payload: &[u8]) -> bool {
        self.send_ip_from(link, 0, dst, proto, payload)
    }

    /// Send from our address `src` (0: the outgoing interface's), routed
    /// for that source.
    pub fn send_ip_from(&mut self, link: &mut dyn Link, src: Ip, dst: Ip, proto: u8, payload: &[u8]) -> bool {
        if dst == BROADCAST {
            return self.0[0].send_ip(link, dst, proto, payload);
        }
        let Some((i, hop)) = self.route_from(src, dst) else {
            self.0[0].stats.tx_dropped += 1;
            return false;
        };
        let f = &mut self.0[i];
        if 20 + payload.len() > f.mtu {
            f.stats.tx_dropped += 1;
            return false;
        }
        let p = f.ip_packet(if src != 0 { src } else { f.ip }, dst, proto, payload);
        f.send_packet(link, hop, p)
    }

    /// The source address for a packet to `dst` from `src` (0: ours towards `dst`).
    pub fn src_or(&self, src: Ip, dst: Ip) -> Ip {
        if src != 0 { src } else { self.src_for(dst) }
    }

    pub fn send_udp(&mut self, link: &mut dyn Link, dst: Ip, sport: u16, dport: u16, data: &[u8]) -> bool {
        self.send_udp_from(link, 0, dst, sport, dport, data)
    }

    pub fn send_udp_from(&mut self, link: &mut dyn Link, src: Ip, dst: Ip, sport: u16, dport: u16, data: &[u8]) -> bool {
        if dst == BROADCAST {
            return self.0[0].send_udp(link, dst, sport, dport, data);
        }
        let len = 8 + data.len();
        let mut u = Vec::with_capacity(len);
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&(len as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(data);
        let c = match checksum(&u, pseudo(self.src_or(src, dst), dst, PROTO_UDP, len)) {
            0 => 0xFFFF,
            c => c,
        };
        u[6..8].copy_from_slice(&c.to_be_bytes());
        self.send_ip_from(link, src, dst, PROTO_UDP, &u)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
        u32::from_be_bytes([a, b, c, d])
    }
    const M24: Ip = 0xFFFF_FF00;

    /// nic0: WAN 2 (203.0.113.240/24 gw .1); nic1: WAN 1 (198.51.100.1/24
    /// gw .254, extra .240); nic2: LAN 10.20.0.254/24.
    fn wans() -> Ifaces {
        let mut a = Iface::new(0, [2; 6], ip(203, 0, 113, 240), M24, ip(203, 0, 113, 1));
        let mut b = Iface::new(1, [3; 6], ip(198, 51, 100, 1), M24, ip(198, 51, 100, 254));
        b.extra = alloc::vec![ip(198, 51, 100, 240)];
        let c = Iface::new(2, [4; 6], ip(10, 20, 0, 254), M24, 0);
        a.mtu = 1500;
        Ifaces(alloc::vec![a, b, c], Vec::new())
    }

    #[test]
    fn several_wans() {
        let mut f = wans();
        let far = ip(8, 8, 8, 8);
        // no default route: the first interface with a gateway
        assert_eq!(f.route(far), Some((0, ip(203, 0, 113, 1))));
        // the main default via WAN 1
        f.1.push(Route { net: 0, mask: 0, gw: ip(198, 51, 100, 254), ..Default::default() });
        assert_eq!(f.route(far), Some((1, ip(198, 51, 100, 254))));
        // our addresses leave by their own WAN: replies, srcnat'ed packets
        assert_eq!(f.route_from(ip(203, 0, 113, 240), far), Some((0, ip(203, 0, 113, 1))));
        assert_eq!(f.route_from(ip(198, 51, 100, 240), far), Some((1, ip(198, 51, 100, 254))));
        // connected networks first, whatever the source
        assert_eq!(f.route_from(ip(203, 0, 113, 240), ip(10, 20, 0, 1)), Some((2, ip(10, 20, 0, 1))));
        // a LAN host is routed out of WAN 2 by a source route
        let lan = ip(10, 20, 0, 1);
        assert_eq!(f.route_from(lan, far), Some((1, ip(198, 51, 100, 254))));
        f.1.push(Route { net: 0, mask: 0, gw: ip(203, 0, 113, 1), src: lan, src_mask: !0 });
        assert_eq!(f.route_from(lan, far), Some((0, ip(203, 0, 113, 1))));
        assert_eq!(f.route_from(ip(10, 20, 0, 2), far), Some((1, ip(198, 51, 100, 254))), "other hosts keep the main default");
        assert_eq!(f.route(far), Some((1, ip(198, 51, 100, 254))), "no source: the main default");
        // a more specific destination route still wins over the source route
        f.1.push(Route { net: ip(10, 99, 0, 0), mask: 0xFFFF_0000, gw: ip(10, 20, 0, 5), ..Default::default() });
        assert_eq!(f.route_from(lan, ip(10, 99, 1, 1)), Some((2, ip(10, 20, 0, 5))));
        assert_eq!(f.route_from(ip(203, 0, 113, 240), ip(10, 99, 1, 1)), Some((2, ip(10, 20, 0, 5))));
        // a source route whose gateway is not reachable is skipped
        f.1.push(Route { net: 0, mask: 0, gw: ip(192, 0, 2, 1), src: ip(10, 20, 0, 7), src_mask: !0 });
        assert_eq!(f.route_from(ip(10, 20, 0, 7), far), Some((1, ip(198, 51, 100, 254))));
    }
}
