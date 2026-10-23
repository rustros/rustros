//! The system network stack: one interface per NIC, demultiplexed to the sockets of
//! many applications. Applications are identified by an owner index; a socket
//! can only be used by the application that created it.

use alloc::collections::VecDeque;

use rustros_util::wire::{be16, be32, checksum};
use alloc::vec::Vec;

use alloc::string::String;
use rustros_api::module::NetStack;
use rustros_api::socket::*;
use rustros_api::{ConnInfo, Ip, NetConf, NetInfo};

use crate::Link;
use crate::iface::{Iface, Ifaces, IpPkt, PROTO_ICMP, PROTO_TCP, PROTO_UDP, parse_udp};
use crate::tcp::{State, Tcp};

/// Datagrams queued per socket before new ones are dropped.
const QUEUE: usize = 64;

/// An IPv4 address and port (the stack's own; sockets see `SockAddr`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Addr {
    pub(crate) ip: Ip,
    pub(crate) port: u16,
}

pub(crate) struct Udp {
    pub(crate) id: u32,
    pub(crate) owner: usize,
    pub(crate) port: u16,
    pub(crate) rx: VecDeque<(Addr, Vec<u8>)>,
    /// (peer, our address it sent to): replies go from that address (and
    /// out of its WAN)
    pub(crate) peers: Vec<(Ip, Ip)>,
    /// The socket (its slot in `socks`).
    pub(crate) sock: usize,
    /// Bound to this address only (0: any).
    pub(crate) lip: Ip,
    /// connect()ed: only datagrams from it, sends go to it.
    pub(crate) peer: Option<Addr>,
}

/// Peers per UDP socket whose local address is remembered.
const PEERS: usize = 256;

pub(crate) struct Raw {
    pub(crate) id: u32,
    pub(crate) owner: usize,
    pub(crate) proto: u8,
    pub(crate) rx: VecDeque<(Ip, u8, Vec<u8>)>,
    pub(crate) sock: usize,
}

pub struct Stack {
    /// One per NIC; the first is the primary (management) interface.
    pub ifs: Ifaces,
    pub(crate) tcp: Tcp,
    pub(crate) listeners: Vec<(u16, usize)>,
    pub(crate) udp: Vec<Udp>,
    pub(crate) raw: Vec<Raw>,
    next_id: u32,
    /// The applications' sockets and epoll instances (socket.rs).
    pub(crate) sk: crate::socket::Sockets,
    /// Application names by owner index, for connection listings.
    pub owner_names: Vec<&'static str>,
    /// A pass of `loopback` used its whole budget: the last packet, for
    /// the log (a storm between two of our own sockets).
    pub loop_storm: Option<alloc::string::String>,
    /// The interfaces' and routes' configuration (config.rs).
    pub(crate) conf: crate::config::Config,
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
            conf: crate::config::Config::default(),
            sk: crate::socket::Sockets::default(),
        }
    }

    pub(crate) fn id(&mut self) -> u32 {
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
        self.tcp_events(link);
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
                let from = Addr { ip: pkt.src, port: sport };
                let mine = |u: &&mut Udp| u.port == dport && (u.lip == 0 || u.lip == local) && u.peer.is_none_or(|p| p == from);
                match self.udp.iter_mut().find(mine) {
                    Some(u) if u.rx.len() < QUEUE => {
                        if ours {
                            match u.peers.iter().position(|p| p.0 == pkt.src) {
                                Some(i) => u.peers[i].1 = local,
                                None if u.peers.len() < PEERS => u.peers.push((pkt.src, local)),
                                None => u.peers[pkt.src as usize % PEERS] = (pkt.src, local),
                            }
                        }
                        u.rx.push_back((from, data.to_vec()));
                        let i = u.sock;
                        self.note(link, i, EPOLLIN | EPOLLRDNORM);
                    }
                    _ => self.ifs.0[nic].stats.rx_dropped += 1,
                }
            }
            proto => {
                let mut woke = Vec::new();
                for r in self.raw.iter_mut().filter(|r| r.proto == proto) {
                    if r.rx.len() < QUEUE {
                        r.rx.push_back((pkt.src, pkt.ttl, pkt.payload.to_vec()));
                        woke.push(r.sock);
                    }
                }
                for i in woke {
                    self.note(link, i, EPOLLIN | EPOLLRDNORM);
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
        self.tcp_events(link);
    }

    // ---------------------------------------------------------------- info

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
                remote: SockAddr::v4(s.rip, s.rport),
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
            // what waits: TCP listeners ("LISTEN") and bound UDP sockets ("UDP")
            .chain(self.listeners.iter().map(|&(port, owner)| ConnInfo { local_port: port, remote: SockAddr::v4(0, 0), state: "LISTEN", owner: self.owner_names.get(owner).copied() }))
            .chain(self.udp.iter().map(|u| ConnInfo { local_port: u.port, remote: SockAddr::v4(0, 0), state: "UDP", owner: self.owner_names.get(u.owner).copied() }))
            .collect()
    }

    /// Drop everything `owner` holds (it was stopped or crashed): reset its
    /// connections, close its listeners and sockets.
    pub fn release_owner(&mut self, owner: usize, link: &mut dyn Link) {
        self.sk_release(owner, link);
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

}

// ---------------------------------------------------------------- the kernel's view

impl NetStack for Stack {
    fn input(&mut self, link: &mut dyn Link, nic: usize, frame: &[u8]) {
        Stack::input(self, link, nic, frame)
    }
    fn poll(&mut self, link: &mut dyn Link) -> Option<String> {
        Stack::poll(self, link);
        self.loop_storm.take()
    }
    fn set_nics(&mut self, macs: Vec<[u8; 6]>) {
        self.conf.macs = macs;
    }
    fn config(&self) -> NetConf {
        Stack::running(self)
    }
    fn set_config(&mut self, conf: &NetConf) -> Result<(), String> {
        Stack::set_config(self, conf)
    }
    fn candidate(&self) -> Option<NetConf> {
        Stack::candidate(self)
    }
    fn set_candidate(&mut self, conf: Option<NetConf>) {
        Stack::set_candidate(self, conf)
    }
    fn apply(&mut self, now: u64, seconds: u32) -> Result<(), String> {
        Stack::apply(self, now, seconds)
    }
    fn revert(&mut self) -> Result<bool, String> {
        Stack::revert(self)
    }
    fn confirm(&mut self) -> bool {
        Stack::confirm(self)
    }
    fn discard(&mut self) {
        Stack::discard(self)
    }
    fn pending(&self, now: u64) -> Option<u64> {
        Stack::pending(self, now)
    }
    fn applied(&self) -> bool {
        Stack::applied(self)
    }
    fn tick(&mut self, now: u64) -> Option<String> {
        Stack::tick(self, now)
    }
    fn boot_config(&self, nics: usize, cmdline: &str, env: &dyn Fn(&str) -> Option<String>) -> (NetConf, Vec<String>) {
        rustros_util::netconf::from_boot(nics, cmdline, env)
    }
    fn save(&mut self) -> Vec<(String, String)> {
        Stack::save(self)
    }
    fn set_owner_names(&mut self, names: Vec<&'static str>) {
        self.owner_names = names;
    }
    fn release_owner(&mut self, owner: usize, link: &mut dyn Link) {
        Stack::release_owner(self, owner, link)
    }
    fn nic_info(&self, nic: usize) -> Option<NetInfo> {
        Stack::nic_info(self, nic)
    }
    fn arp_table(&self, now: u64) -> Vec<(Ip, [u8; 6], u64)> {
        Stack::arp_table(self, now)
    }
    fn connections(&self) -> Vec<ConnInfo> {
        Stack::connections(self)
    }
    fn route_from(&self, src: Ip, dst: Ip) -> Option<(usize, Ip)> {
        Stack::route_from(self, src, dst)
    }
    fn neighbor(&mut self, link: &mut dyn Link, nic: usize, ip: Ip) -> Option<[u8; 6]> {
        Stack::neighbor(self, link, nic, ip)
    }
    fn send_packet(&mut self, link: &mut dyn Link, packet: &[u8]) -> bool {
        Stack::send_packet(self, link, packet)
    }
    fn socket(&mut self, owner: usize, domain: i32, ty: i32, protocol: i32) -> SockResult<Socket> {
        self.sk_socket(owner, domain, ty, protocol)
    }
    fn bind(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()> {
        self.sk_bind(owner, link, s, addr)
    }
    fn listen(&mut self, owner: usize, link: &mut dyn Link, s: Socket, backlog: i32) -> SockResult<()> {
        self.sk_listen(owner, link, s, backlog)
    }
    fn accept(&mut self, owner: usize, _link: &mut dyn Link, s: Socket, flags: i32) -> SockResult<(Socket, SockAddr)> {
        self.sk_accept(owner, s, flags)
    }
    fn connect(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()> {
        self.sk_connect(owner, link, s, addr)
    }
    fn sendto(&mut self, owner: usize, link: &mut dyn Link, s: Socket, data: &[u8], flags: i32, to: Option<&SockAddr>) -> SockResult<usize> {
        self.sk_sendto(owner, link, s, data, flags, to)
    }
    fn recvfrom(&mut self, owner: usize, link: &mut dyn Link, s: Socket, buf: &mut [u8], flags: i32) -> SockResult<(usize, Option<SockAddr>)> {
        self.sk_recvfrom(owner, link, s, buf, flags)
    }
    fn shutdown(&mut self, owner: usize, link: &mut dyn Link, s: Socket, how: i32) -> SockResult<()> {
        self.sk_shutdown(owner, link, s, how)
    }
    fn close(&mut self, owner: usize, link: &mut dyn Link, s: Socket) -> SockResult<()> {
        self.sk_close(owner, link, s)
    }
    fn getsockname(&self, owner: usize, s: Socket) -> SockResult<SockAddr> {
        self.sk_getsockname(owner, s)
    }
    fn getpeername(&self, owner: usize, s: Socket) -> SockResult<SockAddr> {
        self.sk_getpeername(owner, s)
    }
    fn setsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &[u8]) -> SockResult<()> {
        self.sk_setsockopt(owner, s, level, name, value)
    }
    fn getsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &mut [u8]) -> SockResult<usize> {
        self.sk_getsockopt(owner, s, level, name, value)
    }
    fn ioctl(&mut self, owner: usize, s: Socket, request: u32, arg: u64) -> SockResult<u64> {
        self.sk_ioctl(owner, s, request, arg)
    }
    fn sock_poll(&self, owner: usize, s: Socket) -> SockResult<(u32, u64)> {
        self.sk_poll(owner, s)
    }
    fn epoll_create(&mut self, owner: usize) -> SockResult<Epoll> {
        self.sk_epoll_create(owner)
    }
    fn epoll_ctl(&mut self, owner: usize, ep: Epoll, op: i32, s: Socket, events: u32, data: u64) -> SockResult<()> {
        self.sk_epoll_ctl(owner, ep, op, s, events, data)
    }
    fn epoll_wait(&mut self, owner: usize, ep: Epoll, out: &mut [EpollEvent]) -> SockResult<usize> {
        self.sk_epoll_wait(owner, ep, out)
    }
    fn epoll_close(&mut self, owner: usize, ep: Epoll) -> SockResult<()> {
        self.sk_epoll_close(owner, ep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Wire {
        now: u64,
        sent: usize,
        /// what the stack reported: (owner, socket, events)
        notes: Vec<(usize, Socket, u32)>,
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
        fn notify(&mut self, owner: usize, sock: Socket, events: u32) {
            self.notes.push((owner, sock, events));
        }
    }

    const fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
        u32::from_be_bytes([a, b, c, d])
    }

    fn conn(st: &mut Stack, w: &mut Wire, owner: usize, to: Ip, port: u16) -> Socket {
        let c = st.sk_socket(owner, AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(st.sk_connect(owner, w, c, &SockAddr::v4(to, port)), Err(Errno::EINPROGRESS));
        c
    }

    fn listen(st: &mut Stack, w: &mut Wire, owner: usize, port: u16) -> Socket {
        let l = st.sk_socket(owner, AF_INET, SOCK_STREAM, 0).unwrap();
        st.sk_bind(owner, w, l, &SockAddr::v4(0, port)).unwrap();
        st.sk_listen(owner, w, l, 16).unwrap();
        l
    }

    fn talk(st: &mut Stack, w: &mut Wire, to: Ip, port: u16) -> SockAddr {
        let l = listen(st, w, 1, port);
        let c = conn(st, w, 2, to, port);
        for _ in 0..10 {
            w.now += 1;
            st.poll(w);
        }
        let (s, peer) = st.sk_accept(1, l, 0).expect("accepted");
        assert!(st.sk_getpeername(2, c).is_ok(), "connected");
        st.sk_sendto(2, w, c, b"hello", 0, None).unwrap();
        st.poll(w);
        let mut b = [0u8; 16];
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Ok((5, None)));
        assert_eq!(&b[..5], b"hello");
        st.sk_sendto(1, w, s, b"back", 0, None).unwrap();
        st.poll(w);
        assert_eq!(st.sk_recvfrom(2, w, c, &mut b, 0), Ok((4, None)));
        st.sk_close(2, w, c).unwrap();
        st.sk_close(1, w, s).unwrap();
        st.sk_close(1, w, l).unwrap();
        peer
    }

    /// Both ends close: the FINs are acknowledged once, and then nothing
    /// more goes back and forth (it once bounced FINs forever).
    #[test]
    fn close_to_ourselves_settles() {
        let mut st = Stack::new([2; 6], ip(10, 0, 0, 1), 0xFFFF_FF00, ip(10, 0, 0, 254));
        let mut w = Wire { now: 1, sent: 0, notes: Vec::new() };
        let l = listen(&mut st, &mut w, 1, 80);
        let c = conn(&mut st, &mut w, 2, ip(10, 0, 0, 1), 80);
        st.poll(&mut w);
        let (s, _) = st.sk_accept(1, l, 0).unwrap();
        st.sk_sendto(2, &mut w, c, b"GET", 0, None).unwrap();
        st.poll(&mut w);
        st.sk_sendto(1, &mut w, s, b"answer", 0, None).unwrap();
        st.sk_close(1, &mut w, s).unwrap(); // the server ends first
        st.poll(&mut w);
        st.sk_close(2, &mut w, c).unwrap();
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
        let mut w = Wire { now: 1, sent: 0, notes: Vec::new() };
        // our address, loopback, an extra address (a cloud's public one)
        assert_eq!(talk(&mut st, &mut w, ip(10, 0, 0, 1), 8888).ipv4(), Some(ip(10, 0, 0, 1)));
        assert_eq!(talk(&mut st, &mut w, ip(127, 0, 0, 1), 8889).ipv4(), Some(ip(127, 0, 0, 1)));
        assert_eq!(talk(&mut st, &mut w, ip(203, 0, 113, 7), 8890).ipv4(), Some(ip(203, 0, 113, 7)));
        // ping ourselves
        let r = st.sk_socket(3, AF_INET, SOCK_RAW, PROTO_ICMP as i32).unwrap();
        let mut echo = alloc::vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        let c = checksum(&echo, 0);
        echo[2..4].copy_from_slice(&c.to_be_bytes());
        st.sk_sendto(3, &mut w, r, &echo, 0, Some(&SockAddr::v4(ip(10, 0, 0, 1), 0))).unwrap();
        st.poll(&mut w);
        let mut b = [0u8; 64];
        let mut got = None;
        // the IP header, then the message (as on Linux)
        while let Ok((n, from)) = st.sk_recvfrom(3, &mut w, r, &mut b, 0) {
            if b[20] == 0 {
                got = Some((n, from));
            }
        }
        assert_eq!(got, Some((28, Some(SockAddr::v4(ip(10, 0, 0, 1), 0)))));
        assert_eq!(w.sent, 0, "nothing to ourselves went on the wire");
    }

    fn pump(st: &mut Stack, w: &mut Wire) {
        for _ in 0..4 {
            w.now += 1;
            st.poll(w);
        }
    }

    /// The socket calls with Linux semantics, and their notifications.
    #[test]
    fn sockets() {
        let us = ip(10, 0, 0, 1);
        let mut st = Stack::new([2; 6], us, 0xFFFF_FF00, ip(10, 0, 0, 254));
        let w = &mut Wire { now: 1, sent: 0, notes: Vec::new() };
        assert_eq!(st.sk_socket(1, AF_INET6, SOCK_STREAM, 0), Err(Errno::EAFNOSUPPORT));
        assert_eq!(st.sk_socket(1, AF_UNIX, SOCK_STREAM, 0), Err(Errno::EAFNOSUPPORT));
        assert_eq!(st.sk_socket(1, AF_INET, SOCK_STREAM, 17), Err(Errno::EPROTONOSUPPORT));
        // a listener with an edge-triggered epoll on it
        let l = st.sk_socket(1, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0).unwrap();
        st.sk_bind(1, w, l, &SockAddr::v4(0, 7000)).unwrap();
        assert_eq!(st.sk_setsockopt(1, l, SOL_SOCKET, SO_REUSEPORT, &1i32.to_ne_bytes()), Err(Errno::ENOPROTOOPT));
        st.sk_listen(1, w, l, 16).unwrap();
        let ep = st.sk_epoll_create(1).unwrap();
        st.sk_epoll_ctl(1, ep, EPOLL_CTL_ADD, l, EPOLLIN | EPOLLET, 77).unwrap();
        assert_eq!(st.sk_accept(1, l, 0).map(|_| ()), Err(Errno::EAGAIN));
        // connect: in progress, then writable
        let c = st.sk_socket(2, AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(st.sk_connect(2, w, c, &SockAddr::v4(us, 7000)), Err(Errno::EINPROGRESS));
        assert_eq!(st.sk_connect(2, w, c, &SockAddr::v4(us, 7000)), Err(Errno::EALREADY));
        assert_eq!(st.sk_poll(2, c).unwrap().0 & EPOLLOUT, 0);
        let seq = st.sk_poll(2, c).unwrap().1;
        pump(&mut st, w);
        assert!(w.notes.iter().any(|n| n.0 == 2 && n.1 == c && n.2 & EPOLLOUT != 0), "connected is reported");
        assert!(st.sk_poll(2, c).unwrap().1 > seq, "the event counter moves");
        assert_ne!(st.sk_poll(2, c).unwrap().0 & EPOLLOUT, 0);
        // the listener's epoll has it, once (edge)
        let mut out = [EpollEvent::default(); 4];
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(1));
        assert_eq!(out[0], EpollEvent { events: EPOLLIN, data: 77 });
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(0));
        let (s, peer) = st.sk_accept(1, l, SOCK_CLOEXEC).unwrap();
        assert_eq!(peer, st.sk_getsockname(2, c).unwrap());
        assert_eq!(st.sk_accept(1, l, 0x10).map(|_| ()), Err(Errno::EINVAL));
        // data: EPOLLIN at once, FIONREAD, peek, read
        st.sk_epoll_ctl(1, ep, EPOLL_CTL_ADD, s, EPOLLIN | EPOLLRDHUP | EPOLLET, 5).unwrap();
        assert_eq!(st.sk_sendto(2, w, c, b"hello", MSG_NOSIGNAL, None), Ok(5));
        pump(&mut st, w);
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(1));
        assert_eq!((out[0].data, out[0].events & EPOLLIN), (5, EPOLLIN));
        assert_eq!(st.sk_ioctl(1, s, FIONREAD, 0), Ok(5));
        let mut b = [0u8; 16];
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, MSG_PEEK), Ok((5, None)));
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b[..3], 0), Ok((3, None)));
        // more data on a socket that is still readable: a new edge
        st.sk_sendto(2, w, c, b"!", 0, None).unwrap();
        pump(&mut st, w);
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(1));
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Ok((3, None)));
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Err(Errno::EAGAIN));
        // the client stops sending: the server sees RDHUP and the end
        st.sk_shutdown(2, w, c, SHUT_WR).unwrap();
        assert_eq!(st.sk_sendto(2, w, c, b"x", 0, None), Err(Errno::EPIPE));
        pump(&mut st, w);
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(1));
        assert_ne!(out[0].events & EPOLLRDHUP, 0);
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Ok((0, None)));
        // the server still answers on its half
        assert_eq!(st.sk_sendto(1, w, s, b"bye", 0, None), Ok(3));
        pump(&mut st, w);
        assert_eq!(st.sk_recvfrom(2, w, c, &mut b, 0), Ok((3, None)));
        st.sk_close(1, w, s).unwrap();
        st.sk_close(2, w, c).unwrap();
        assert_eq!(st.sk_poll(2, c), Err(Errno::EBADF));
        // nobody listens: refused, reported once through SO_ERROR
        let r = st.sk_socket(2, AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(st.sk_connect(2, w, r, &SockAddr::v4(us, 7001)), Err(Errno::EINPROGRESS));
        pump(&mut st, w);
        assert_ne!(st.sk_poll(2, r).unwrap().0 & EPOLLERR, 0);
        let mut v = [0u8; 4];
        assert_eq!(st.sk_getsockopt(2, r, SOL_SOCKET, SO_ERROR, &mut v), Ok(4));
        assert_eq!(i32::from_ne_bytes(v), Errno::ECONNREFUSED.0);
        st.sk_getsockopt(2, r, SOL_SOCKET, SO_ERROR, &mut v).unwrap();
        assert_eq!(i32::from_ne_bytes(v), 0);
        st.sk_getsockopt(2, r, SOL_SOCKET, SO_TYPE, &mut v).unwrap();
        assert_eq!(i32::from_ne_bytes(v), SOCK_STREAM);
        assert_eq!(st.sk_getsockopt(2, r, SOL_SOCKET, 999, &mut v), Err(Errno::ENOPROTOOPT));
        // UDP: connected, peek, truncation
        let u1 = st.sk_socket(3, AF_INET, SOCK_DGRAM, 0).unwrap();
        st.sk_bind(3, w, u1, &SockAddr::v4(us, 5300)).unwrap();
        let u2 = st.sk_socket(4, AF_INET, SOCK_DGRAM, 0).unwrap();
        assert_eq!(st.sk_sendto(4, w, u2, b"x", 0, None), Err(Errno::EDESTADDRREQ));
        st.sk_connect(4, w, u2, &SockAddr::v4(us, 5300)).unwrap();
        assert_eq!(st.sk_sendto(4, w, u2, b"datagram", 0, None), Ok(8));
        assert_eq!(st.sk_sendto(4, w, u2, b"x", 0, Some(&SockAddr::v4(u32::MAX, 9))), Err(Errno::EACCES));
        pump(&mut st, w);
        assert_eq!(st.sk_ioctl(3, u1, FIONREAD, 0), Ok(8));
        let me = st.sk_getsockname(4, u2).unwrap();
        assert_eq!(st.sk_recvfrom(3, w, u1, &mut b[..4], MSG_PEEK | MSG_TRUNC), Ok((8, Some(me))));
        assert_eq!(st.sk_recvfrom(3, w, u1, &mut b[..4], 0), Ok((4, Some(me))));
        assert_eq!(st.sk_recvfrom(3, w, u1, &mut b, 0), Err(Errno::EAGAIN));
        assert_eq!(st.sk_getpeername(4, u2), Ok(SockAddr::v4(us, 5300)));
        assert_eq!(st.sk_getpeername(3, u1), Err(Errno::ENOTCONN));
        // another owner cannot use it
        assert_eq!(st.sk_recvfrom(4, w, u1, &mut b, 0), Err(Errno::EBADF));
    }
}
