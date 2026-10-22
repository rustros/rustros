//! The system network stack: one interface per NIC, demultiplexed to the sockets of
//! many applications. Applications are identified by an owner index; a socket
//! can only be used by the application that created it.

use alloc::collections::VecDeque;

use rustros_util::wire::{be16, be32, checksum};
use alloc::vec::Vec;

use rustros_api::{ConnInfo, Ip, NetError, NetInfo, RawSocket, SocketAddr, TcpListener, TcpStream, UdpSocket};

use crate::Link;
use crate::iface::{Iface, Ifaces, IpPkt, PROTO_ICMP, PROTO_TCP, PROTO_UDP, parse_udp};
use crate::tcp::{Handle, State, Tcp};

/// Datagrams queued per socket before new ones are dropped.
const QUEUE: usize = 64;
const EPHEMERAL: core::ops::Range<u32> = 49152..65536;

struct Udp {
    id: u32,
    owner: usize,
    port: u16,
    rx: VecDeque<(SocketAddr, Vec<u8>)>,
    /// (peer, our address it sent to): replies go from that address (and
    /// out of its WAN)
    peers: Vec<(Ip, Ip)>,
}

/// Peers per UDP socket whose local address is remembered.
const PEERS: usize = 256;

struct Raw {
    id: u32,
    owner: usize,
    proto: u8,
    rx: VecDeque<(Ip, u8, Vec<u8>)>,
}

pub struct Stack {
    /// One per NIC; the first is the primary (management) interface.
    pub ifs: Ifaces,
    tcp: Tcp,
    listeners: Vec<(u16, usize)>,
    udp: Vec<Udp>,
    raw: Vec<Raw>,
    next_id: u32,
    /// Application names by owner index, for connection listings.
    pub owner_names: Vec<&'static str>,
    /// A pass of `loopback` used its whole budget: the last packet, for
    /// the log (a storm between two of our own sockets).
    pub loop_storm: Option<alloc::string::String>,
}

type R<T> = Result<T, NetError>;

fn stream(h: Handle) -> TcpStream {
    TcpStream::from_raw(h.to_raw())
}

fn handle(s: TcpStream) -> Handle {
    Handle::from_raw(s.to_raw())
}

impl Stack {
    pub fn new(mac: [u8; 6], ip: Ip, mask: Ip, gw: Ip) -> Stack {
        Stack {
            ifs: Ifaces(alloc::vec![Iface::new(0, mac, ip, mask, gw)], Vec::new(), VecDeque::new()),
            tcp: Tcp::new(1024),
            listeners: Vec::new(),
            udp: Vec::new(),
            raw: Vec::new(),
            next_id: 1,
            owner_names: Vec::new(),
            loop_storm: None,
        }
    }

    /// Add the interface of another NIC (unconfigured); returns its index.
    pub fn add_iface(&mut self, mac: [u8; 6]) -> usize {
        let n = self.ifs.0.len();
        self.ifs.0.push(Iface::new(n, mac, 0, 0, 0));
        n
    }

    /// Remove interface `i`; the ones after it move down by one.
    pub fn remove_iface(&mut self, i: usize) {
        if i > 0 && i < self.ifs.0.len() {
            self.ifs.0.remove(i);
            for (n, f) in self.ifs.0.iter_mut().enumerate() {
                f.nic = n;
            }
        }
    }

    pub fn primary(&mut self) -> &mut Iface {
        &mut self.ifs.0[0]
    }

    fn id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Feed one received frame into the stack.
    pub fn input(&mut self, link: &mut dyn Link, nic: usize, frame: &[u8]) {
        if nic >= self.ifs.0.len() {
            return;
        }
        let (before, rest) = self.ifs.0.split_at_mut(nic);
        let (f, after) = rest.split_first_mut().unwrap();
        let elsewhere = |ip: Ip| before.iter().chain(after.iter()).any(|o| o.is_local(ip));
        let Some(pkt) = f.handle(link, frame, &elsewhere) else { return };
        // an extra address only serves connections made from it
        let open = pkt.dst == self.ifs.0[nic].ip;
        self.deliver(link, nic, &pkt, open);
    }

    /// Packets we sent to ourselves (`Ifaces::is_ours`), received: a
    /// bounded number per call (`poll`, once a main-loop pass).
    pub fn loopback(&mut self, link: &mut dyn Link) {
        // replies queue more: a bound keeps a ping-pong from running away
        for n in 0..256 {
            let Some(p) = self.ifs.2.pop_front() else { return };
            if n == 255 && p[9] == PROTO_TCP {
                let ihl = (p[0] & 0xF) as usize * 4;
                if let Some(t) = p.get(ihl..ihl + 14) {
                    let ip = |o: usize| rustros_util::wire::IpFmt(be32(&p, o));
                    self.loop_storm = Some(alloc::format!(
                        "{}:{} -> {}:{} flags {:#04x} seq {} ack {} len {}, {} queued",
                        ip(12),
                        be16(t, 0),
                        ip(16),
                        be16(t, 2),
                        t[13],
                        be32(t, 4),
                        be32(t, 8),
                        p.len() - ihl - (t[12] >> 4) as usize * 4,
                        self.ifs.2.len()
                    ));
                }
            }
            let ihl = (p[0] & 0xF) as usize * 4;
            let total = (be16(&p, 2) as usize).min(p.len());
            let pkt = IpPkt { src: be32(&p, 12), dst: be32(&p, 16), proto: p[9], ttl: p[8], payload: &p[ihl..total] };
            let m = pkt.payload;
            if pkt.proto == PROTO_ICMP && m.len() >= 8 && m[0] == 8 {
                let mut r = m.to_vec();
                r[0] = 0;
                r[2..4].fill(0);
                let c = checksum(&r, 0);
                r[2..4].copy_from_slice(&c.to_be_bytes());
                self.ifs.send_ip_from(link, pkt.dst, pkt.src, PROTO_ICMP, &r);
            } else {
                self.deliver(link, 0, &pkt, true);
            }
        }
    }

    fn deliver(&mut self, link: &mut dyn Link, nic: usize, pkt: &IpPkt, open: bool) {
        match pkt.proto {
            PROTO_TCP => {
                self.tcp.input(&mut self.ifs, link, pkt, open);
            }
            PROTO_UDP => {
                let Some((sport, dport, data)) = parse_udp(pkt) else { return };
                // the address it was sent to (an interface's or an extra one)
                let local = pkt.dst;
                let ours = self.ifs.0.iter().any(|f| f.is_local(local));
                match self.udp.iter_mut().find(|u| u.port == dport) {
                    Some(u) if u.rx.len() < QUEUE => {
                        if ours {
                            match u.peers.iter().position(|p| p.0 == pkt.src) {
                                Some(i) => u.peers[i].1 = local,
                                None if u.peers.len() < PEERS => u.peers.push((pkt.src, local)),
                                None => u.peers[pkt.src as usize % PEERS] = (pkt.src, local),
                            }
                        }
                        u.rx.push_back((SocketAddr { ip: pkt.src, port: sport }, data.to_vec()))
                    }
                    _ => self.ifs.0[nic].stats.rx_dropped += 1,
                }
            }
            proto => {
                for r in self.raw.iter_mut().filter(|r| r.proto == proto) {
                    if r.rx.len() < QUEUE {
                        r.rx.push_back((pkt.src, pkt.ttl, pkt.payload.to_vec()));
                    }
                }
            }
        }
    }

    /// Timers: ARP expiry, TCP retransmissions.
    pub fn poll(&mut self, link: &mut dyn Link) {
        for f in self.ifs.0.iter_mut() {
            f.poll(link);
        }
        self.tcp.poll(&mut self.ifs, link);
        self.loopback(link);
    }

    // ---------------------------------------------------------------- info

    pub fn info(&self) -> NetInfo {
        self.nic_info(0).unwrap()
    }

    pub fn nic_info(&self, nic: usize) -> Option<NetInfo> {
        let i = self.ifs.0.get(nic)?;
        Some(NetInfo {
            mac: i.mac,
            ip: i.ip,
            mask: i.mask,
            gw: i.gw,
            mtu: i.mtu,
            rx: i.stats.rx,
            tx: i.stats.tx,
            rx_dropped: i.stats.rx_dropped,
            tx_dropped: i.stats.tx_dropped,
        })
    }

    pub fn config(&mut self, ip: Ip, mask: Ip, gw: Ip) {
        self.config_nic(0, ip, mask, gw);
    }

    pub fn config_nic(&mut self, nic: usize, ip: Ip, mask: Ip, gw: Ip) {
        if let Some(f) = self.ifs.0.get_mut(nic) {
            f.ip = ip;
            f.mask = mask;
            f.gw = gw;
            f.arp.clear();
        }
    }

    pub fn arp_table(&self, now: u64) -> Vec<(Ip, [u8; 6], u64)> {
        self.ifs.0.iter().flat_map(|f| f.arp.iter()).map(|e| (e.ip, e.mac, now - e.seen)).collect()
    }

    // ---------------------------------------------------------------- forwarding

    /// (interface, next hop) towards `dst`.
    pub fn route(&self, dst: Ip) -> Option<(usize, Ip)> {
        self.ifs.route(dst)
    }

    /// (interface, next hop) for a packet from `src` to `dst`.
    pub fn route_from(&self, src: Ip, dst: Ip) -> Option<(usize, Ip)> {
        self.ifs.route_from(src, dst)
    }

    /// MAC of `ip` on interface `nic`; None (asking ARP) if not known yet.
    pub fn neighbor(&mut self, link: &mut dyn Link, nic: usize, ip: Ip) -> Option<[u8; 6]> {
        self.ifs.0.get_mut(nic)?.neighbor(link, ip)
    }

    /// Route and send a finished IPv4 packet (forwarded traffic; its source
    /// address is left alone).
    pub fn send_packet(&mut self, link: &mut dyn Link, p: &[u8]) -> bool {
        if p.len() < 20 {
            return false;
        }
        let src = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
        let dst = u32::from_be_bytes([p[16], p[17], p[18], p[19]]);
        let Some((i, hop)) = self.ifs.route_from(src, dst) else { return false };
        let f = &mut self.ifs.0[i];
        if p.len() > f.mtu {
            f.stats.tx_dropped += 1;
            return false;
        }
        f.send_packet(link, hop, p.to_vec())
    }

    pub fn connections(&self) -> Vec<ConnInfo> {
        self.tcp
            .connections()
            .map(|s| ConnInfo {
                local_port: s.lport,
                remote: SocketAddr { ip: s.rip, port: s.rport },
                state: match s.state {
                    State::SynSent => "SYN_SENT",
                    State::SynRcvd => "SYN_RCVD",
                    State::Established => "ESTABLISHED",
                    State::FinWait1 => "FIN_WAIT_1",
                    State::FinWait2 => "FIN_WAIT_2",
                    State::CloseWait => "CLOSE_WAIT",
                    State::Closing => "CLOSING",
                    State::LastAck => "LAST_ACK",
                    State::TimeWait => "TIME_WAIT",
                },
                owner: self.owner_names.get(s.owner).copied(),
            })
            .collect()
    }

    /// Drop everything `owner` holds (it was stopped or crashed): reset its
    /// connections, close its listeners and sockets.
    pub fn release_owner(&mut self, owner: usize, link: &mut dyn Link) {
        for h in self.tcp.owned_by(owner) {
            self.tcp.abort(&mut self.ifs, link, h);
        }
        let ports: Vec<u16> = self.listeners.iter().filter(|l| l.1 == owner).map(|l| l.0).collect();
        for port in ports {
            self.listeners.retain(|l| l.0 != port);
            self.tcp.unlisten(&mut self.ifs, link, port);
        }
        self.udp.retain(|u| u.owner != owner);
        self.raw.retain(|r| r.owner != owner);
    }

    // ---------------------------------------------------------------- UDP

    pub fn udp_bind(&mut self, owner: usize, link: &mut dyn Link, port: u16) -> R<UdpSocket> {
        let port = if port != 0 {
            if self.udp.iter().any(|u| u.port == port) {
                return Err(NetError::AddrInUse);
            }
            port
        } else {
            let span = EPHEMERAL.end - EPHEMERAL.start;
            let start = (link.random() % span as u64) as u32;
            (0..span)
                .map(|i| (EPHEMERAL.start + (start + i) % span) as u16)
                .find(|p| !self.udp.iter().any(|u| u.port == *p))
                .ok_or(NetError::AddrInUse)?
        };
        let id = self.id();
        self.udp.push(Udp { id, owner, port, rx: VecDeque::new(), peers: Vec::new() });
        Ok(UdpSocket::from_raw(id as u64))
    }

    fn udp_mut(&mut self, owner: usize, s: UdpSocket) -> R<&mut Udp> {
        self.udp.iter_mut().find(|u| u.id as u64 == s.to_raw() && u.owner == owner).ok_or(NetError::BadHandle)
    }

    pub fn udp_local_port(&self, owner: usize, s: UdpSocket) -> R<u16> {
        self.udp.iter().find(|u| u.id as u64 == s.to_raw() && u.owner == owner).map(|u| u.port).ok_or(NetError::BadHandle)
    }

    pub fn udp_send_to(&mut self, owner: usize, link: &mut dyn Link, s: UdpSocket, to: SocketAddr, data: &[u8]) -> R<()> {
        let u = self.udp_mut(owner, s)?;
        let port = u.port;
        // still one of ours? (addresses change)
        let from = u.peers.iter().find(|p| p.0 == to.ip).map_or(0, |p| p.1);
        let from = if self.ifs.0.iter().any(|f| f.is_local(from)) { from } else { 0 };
        if 20 + 8 + data.len() > self.ifs.mtu_for(to.ip) {
            return Err(NetError::TooLarge);
        }
        if self.ifs.src_for(to.ip) == 0 && to.ip != u32::MAX {
            return Err(NetError::NoRoute);
        }
        if self.ifs.send_udp_from(link, from, to.ip, port, to.port, data) { Ok(()) } else { Err(NetError::NoRoute) }
    }

    pub fn udp_recv_from(&mut self, owner: usize, s: UdpSocket, buf: &mut [u8]) -> R<(usize, SocketAddr)> {
        let (from, data) = self.udp_mut(owner, s)?.rx.pop_front().ok_or(NetError::WouldBlock)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }

    pub fn udp_close(&mut self, owner: usize, s: UdpSocket) {
        self.udp.retain(|u| !(u.id as u64 == s.to_raw() && u.owner == owner));
    }

    // ---------------------------------------------------------------- TCP

    pub fn tcp_listen(&mut self, owner: usize, port: u16) -> R<TcpListener> {
        if port == 0 || self.listeners.iter().any(|l| l.0 == port) {
            return Err(NetError::AddrInUse);
        }
        self.listeners.push((port, owner));
        self.tcp.listen(port);
        Ok(TcpListener::from_raw(port as u64))
    }

    fn own_listener(&self, owner: usize, l: TcpListener) -> R<()> {
        if self.listeners.contains(&(l.to_raw() as u16, owner)) { Ok(()) } else { Err(NetError::BadHandle) }
    }

    pub fn tcp_unlisten(&mut self, owner: usize, link: &mut dyn Link, l: TcpListener) {
        if self.own_listener(owner, l).is_ok() {
            let port = l.to_raw() as u16;
            self.listeners.retain(|x| x.0 != port);
            self.tcp.unlisten(&mut self.ifs, link, port);
        }
    }

    pub fn tcp_accept(&mut self, owner: usize, l: TcpListener) -> R<(TcpStream, SocketAddr)> {
        self.own_listener(owner, l)?;
        let h = self.tcp.accept(l.to_raw() as u16, owner).ok_or(NetError::WouldBlock)?;
        let s = self.tcp.sock(h).ok_or(NetError::Closed)?;
        Ok((stream(h), SocketAddr { ip: s.rip, port: s.rport }))
    }

    /// Start an outgoing connection from a free ephemeral port.
    pub fn tcp_connect(&mut self, owner: usize, link: &mut dyn Link, to: SocketAddr) -> R<TcpStream> {
        self.tcp_connect_from(owner, link, 0, to)
    }

    /// Connect from our address `src` (an interface's or an extra one; 0:
    /// the one towards `to`).
    pub fn tcp_connect_from(&mut self, owner: usize, link: &mut dyn Link, src: Ip, to: SocketAddr) -> R<TcpStream> {
        if self.ifs.src_for(to.ip) == 0 || to.ip == 0 || to.port == 0 {
            return Err(NetError::NoRoute);
        }
        if src != 0 && !self.ifs.0.iter().any(|f| f.is_local(src)) {
            return Err(NetError::NoRoute);
        }
        let span = EPHEMERAL.end - EPHEMERAL.start;
        let start = (link.random() % span as u64) as u32;
        let lport = (0..span)
            .map(|i| (EPHEMERAL.start + (start + i) % span) as u16)
            .find(|&p| !self.tcp.port_in_use(p))
            .ok_or(NetError::AddrInUse)?;
        let h = self.tcp.connect(&mut self.ifs, link, src, to.ip, to.port, lport, owner).ok_or(NetError::AddrInUse)?;
        Ok(stream(h))
    }

    pub fn tcp_is_connected(&self, owner: usize, s: TcpStream) -> R<bool> {
        self.own_stream(owner, s)?;
        self.tcp.is_established(handle(s)).ok_or(NetError::Closed)
    }

    pub fn tcp_local_addr(&self, owner: usize, s: TcpStream) -> R<SocketAddr> {
        self.own_stream(owner, s)?;
        let k = self.tcp.sock(handle(s)).ok_or(NetError::Closed)?;
        Ok(SocketAddr { ip: k.lip, port: k.lport })
    }

    fn own_stream(&self, owner: usize, s: TcpStream) -> R<()> {
        match self.tcp.sock(handle(s)) {
            None => Err(NetError::Closed),
            Some(k) if k.owner != owner => Err(NetError::BadHandle),
            Some(k) if k.released => Err(NetError::Closed),
            Some(_) => Ok(()),
        }
    }

    pub fn tcp_read(&mut self, owner: usize, link: &mut dyn Link, s: TcpStream, buf: &mut [u8]) -> R<usize> {
        self.own_stream(owner, s)?;
        if !self.tcp.peek(handle(s)).is_empty() {
            return Ok(self.tcp.recv(&mut self.ifs, link, handle(s), buf));
        }
        if self.tcp.peer_done(handle(s)) { Ok(0) } else { Err(NetError::WouldBlock) }
    }

    pub fn tcp_write(&mut self, owner: usize, link: &mut dyn Link, s: TcpStream, data: &[u8]) -> R<usize> {
        self.own_stream(owner, s)?;
        if data.is_empty() {
            return Ok(0);
        }
        match self.tcp.send(&mut self.ifs, link, handle(s), data) {
            0 => Err(NetError::WouldBlock),
            n => Ok(n),
        }
    }

    pub fn tcp_close(&mut self, owner: usize, link: &mut dyn Link, s: TcpStream) {
        if self.own_stream(owner, s).is_ok() {
            self.tcp.close(&mut self.ifs, link, handle(s));
        }
    }

    pub fn tcp_abort(&mut self, owner: usize, link: &mut dyn Link, s: TcpStream) {
        if self.own_stream(owner, s).is_ok() {
            self.tcp.abort(&mut self.ifs, link, handle(s));
        }
    }

    // ---------------------------------------------------------------- raw IP

    pub fn raw_open(&mut self, owner: usize, proto: u8) -> R<RawSocket> {
        if proto == PROTO_TCP || proto == PROTO_UDP {
            return Err(NetError::AddrInUse); // owned by the stack itself
        }
        let id = self.id();
        self.raw.push(Raw { id, owner, proto, rx: VecDeque::new() });
        Ok(RawSocket::from_raw(id as u64))
    }

    fn raw_mut(&mut self, owner: usize, s: RawSocket) -> R<&mut Raw> {
        self.raw.iter_mut().find(|r| r.id as u64 == s.to_raw() && r.owner == owner).ok_or(NetError::BadHandle)
    }

    pub fn raw_recv(&mut self, owner: usize, s: RawSocket, buf: &mut [u8]) -> R<(usize, Ip, u8)> {
        let (src, ttl, data) = self.raw_mut(owner, s)?.rx.pop_front().ok_or(NetError::WouldBlock)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, src, ttl))
    }

    pub fn raw_send(&mut self, owner: usize, link: &mut dyn Link, s: RawSocket, dst: Ip, payload: &[u8]) -> R<()> {
        let proto = self.raw_mut(owner, s)?.proto;
        if 20 + payload.len() > self.ifs.mtu_for(dst) {
            return Err(NetError::TooLarge);
        }
        if self.ifs.send_ip(link, dst, proto, payload) { Ok(()) } else { Err(NetError::NoRoute) }
    }

    pub fn raw_close(&mut self, owner: usize, s: RawSocket) {
        self.raw.retain(|r| !(r.id as u64 == s.to_raw() && r.owner == owner));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Wire {
        now: u64,
        sent: usize,
    }
    impl Link for Wire {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn send(&mut self, _nic: usize, _frame: &[u8]) -> bool {
            self.sent += 1;
            true
        }
        fn random(&mut self) -> u64 {
            0x1234_5678
        }
    }

    const fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
        u32::from_be_bytes([a, b, c, d])
    }

    fn talk(st: &mut Stack, w: &mut Wire, to: Ip, port: u16) -> SocketAddr {
        let l = st.tcp_listen(1, port).unwrap();
        let c = st.tcp_connect(2, w, SocketAddr { ip: to, port }).unwrap();
        for _ in 0..10 {
            w.now += 1;
            st.poll(w);
        }
        let (s, peer) = st.tcp_accept(1, l).expect("accepted");
        assert_eq!(st.tcp_is_connected(2, c), Ok(true));
        st.tcp_write(2, w, c, b"hello").unwrap();
        st.poll(w);
        let mut b = [0u8; 16];
        assert_eq!(st.tcp_read(1, w, s, &mut b), Ok(5));
        assert_eq!(&b[..5], b"hello");
        st.tcp_write(1, w, s, b"back").unwrap();
        st.poll(w);
        assert_eq!(st.tcp_read(2, w, c, &mut b), Ok(4));
        st.tcp_close(2, w, c);
        st.tcp_close(1, w, s);
        st.tcp_unlisten(1, w, l);
        peer
    }

    /// Both ends close: the FINs are acknowledged once, and then nothing
    /// more goes back and forth (it once bounced FINs forever).
    #[test]
    fn close_to_ourselves_settles() {
        let mut st = Stack::new([2; 6], ip(10, 0, 0, 1), 0xFFFF_FF00, ip(10, 0, 0, 254));
        let mut w = Wire { now: 1, sent: 0 };
        let l = st.tcp_listen(1, 80).unwrap();
        let c = st.tcp_connect(2, &mut w, SocketAddr { ip: ip(10, 0, 0, 1), port: 80 }).unwrap();
        st.poll(&mut w);
        let (s, _) = st.tcp_accept(1, l).unwrap();
        st.tcp_write(2, &mut w, c, b"GET").unwrap();
        st.poll(&mut w);
        st.tcp_write(1, &mut w, s, b"answer").unwrap();
        st.tcp_close(1, &mut w, s); // the server ends first
        st.poll(&mut w);
        st.tcp_close(2, &mut w, c);
        for _ in 0..5 {
            w.now += 1;
            st.poll(&mut w);
        }
        assert!(st.ifs.2.is_empty(), "{} packets still bouncing", st.ifs.2.len());
        assert!(st.loop_storm.is_none());
    }

    #[test]
    fn to_ourselves() {
        let mut st = Stack::new([2; 6], ip(10, 0, 0, 1), 0xFFFF_FF00, ip(10, 0, 0, 254));
        st.ifs.0[0].extra = alloc::vec![ip(203, 0, 113, 7)];
        let mut w = Wire { now: 1, sent: 0 };
        // our address, loopback, an extra address (a cloud's public one)
        assert_eq!(talk(&mut st, &mut w, ip(10, 0, 0, 1), 8888).ip, ip(10, 0, 0, 1));
        assert_eq!(talk(&mut st, &mut w, ip(127, 0, 0, 1), 8889).ip, ip(127, 0, 0, 1));
        assert_eq!(talk(&mut st, &mut w, ip(203, 0, 113, 7), 8890).ip, ip(203, 0, 113, 7));
        // ping ourselves
        let r = st.raw_open(3, PROTO_ICMP).unwrap();
        let mut echo = alloc::vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        let c = checksum(&echo, 0);
        echo[2..4].copy_from_slice(&c.to_be_bytes());
        st.raw_send(3, &mut w, r, ip(10, 0, 0, 1), &echo).unwrap();
        st.poll(&mut w);
        let mut b = [0u8; 64];
        let mut got = None;
        while let Ok((n, from, _)) = st.raw_recv(3, r, &mut b) {
            if b[0] == 0 {
                got = Some((n, from));
            }
        }
        assert_eq!(got, Some((8, ip(10, 0, 0, 1))));
        assert_eq!(w.sent, 0, "nothing to ourselves went on the wire");
    }
}
