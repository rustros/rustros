//! Hot replacement: the whole stack's state, for the next version to take
//! over (`rustros_api::module::Export`). Open TCP connections carry on with
//! their sequence numbers, buffers and timers; sockets, epoll instances and
//! their ready lists, ARP caches and the configuration stay as they are.
//! Timers are the kernel's clock, which both versions share.
//!
//! Format 1: the NICs' MACs; the configuration in effect, the candidate, the
//! revert point and its deadline; per interface its ARP cache, the packets
//! waiting for ARP, the IP ident and counters; the loopback queue; TCP (its
//! connections, listening ports, events not yet seen); listeners; UDP and
//! raw sockets with their queues; the socket table and epoll instances.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{IfConf, NetConf, RouteConf};
use rustros_util::snap::{Bad, R, W};

use crate::stack::{Addr, Raw, Stack, Udp};
use crate::tcp::{Event, Gone, Handle, Slot, Sock, State};

const TAG: &[u8; 4] = b"NETS";
/// The newest format this version reads (and the one it writes).
pub const VERSION: u32 = 1;

const STATES: [State; 9] = [State::SynSent, State::SynRcvd, State::Established, State::FinWait1, State::FinWait2, State::CloseWait, State::Closing, State::LastAck, State::TimeWait];
const GONE: [Gone; 4] = [Gone::Done, Gone::Refused, Gone::Reset, Gone::TimedOut];

fn save_conf(w: &mut W, c: &NetConf) {
    w.n(c.ifs.len());
    for f in &c.ifs {
        w.u8(f.phys);
        w.u16(f.vlan.unwrap_or(0));
        w.u32(f.ip);
        w.u32(f.mask);
        w.u32(f.gw);
        w.u16(f.mtu);
        w.n(f.extra.len());
        f.extra.iter().for_each(|&a| w.u32(a));
    }
    w.n(c.routes.len());
    for r in &c.routes {
        [r.net, r.mask, r.gw, r.src, r.src_mask].into_iter().for_each(|v| w.u32(v));
    }
}

fn load_conf(r: &mut R) -> Result<NetConf, Bad> {
    let ifs = r.list(|r| {
        let (phys, vlan) = (r.u8()?, r.u16()?);
        let (ip, mask, gw, mtu) = (r.u32()?, r.u32()?, r.u32()?, r.u16()?);
        Ok(IfConf { phys, vlan: (vlan != 0).then_some(vlan), ip, mask, gw, mtu, extra: r.list(|r| r.u32())? })
    })?;
    let routes = r.list(|r| Ok(RouteConf { net: r.u32()?, mask: r.u32()?, gw: r.u32()?, src: r.u32()?, src_mask: r.u32()? }))?;
    Ok(NetConf { ifs, routes })
}

fn save_opt_conf(w: &mut W, c: &Option<NetConf>) {
    w.u8(c.is_some() as u8);
    if let Some(c) = c {
        save_conf(w, c);
    }
}

fn load_opt_conf(r: &mut R) -> Result<Option<NetConf>, Bad> {
    if r.bool()? { load_conf(r).map(Some) } else { Ok(None) }
}

impl Stack {
    pub fn save_state(&self, version: u32) -> Option<Vec<u8>> {
        if version != VERSION {
            return None;
        }
        let mut w = W::new(TAG, VERSION);
        let w = &mut w;
        w.n(self.conf.macs.len());
        self.conf.macs.iter().for_each(|m| w.mac(m));
        save_conf(w, &self.running());
        save_opt_conf(w, &self.conf.candidate);
        save_opt_conf(w, &self.conf.baseline);
        w.u64(self.conf.deadline.map_or(u64::MAX, |d| d));
        w.n(self.ifs.0.len());
        for f in &self.ifs.0 {
            w.n(f.arp.len());
            for e in &f.arp {
                w.u32(e.ip);
                w.mac(&e.mac);
                w.u64(e.seen);
            }
            w.n(f.pending.len());
            for (hop, p, at) in &f.pending {
                w.u32(*hop);
                w.bytes(p);
                w.u64(*at);
            }
            w.u16(f.ip_id);
            [f.stats.rx, f.stats.tx, f.stats.rx_dropped, f.stats.tx_dropped].into_iter().for_each(|v| w.u64(v));
        }
        w.n(self.ifs.2.len());
        self.ifs.2.iter().for_each(|p| w.bytes(p));
        // TCP
        let t = &self.tcp;
        w.n(t.max_conns);
        w.n(t.listening.len());
        t.listening.iter().for_each(|&p| w.u16(p));
        w.n(t.slots.len());
        for slot in &t.slots {
            w.u32(slot.generation);
            let Some(s) = &slot.sock else {
                w.u8(0);
                continue;
            };
            w.u8(1);
            w.u8(STATES.iter().position(|&x| x == s.state).unwrap_or(0) as u8);
            w.u32(s.lip);
            w.u16(s.lport);
            w.u32(s.rip);
            w.u16(s.rport);
            [s.snd_una, s.snd_nxt, s.snd_max, s.snd_wnd, s.rcv_nxt, s.retries].into_iter().for_each(|v| w.u32(v));
            w.bytes(&s.tx);
            w.bytes(&s.rx);
            [s.rto, s.rtx_at, s.deadline].into_iter().for_each(|v| w.u64(v));
            w.n(s.mss);
            w.n(s.owner);
            w.u8(s.fin_queued as u8 | (s.accepted as u8) << 1 | (s.released as u8) << 2);
        }
        w.n(t.events.len());
        for e in &t.events {
            match *e {
                Event::Conn(h, bits) => {
                    w.u8(0);
                    w.u64(h.to_raw());
                    w.u8(bits);
                }
                Event::Gone(h, why) => {
                    w.u8(1);
                    w.u64(h.to_raw());
                    w.u8(GONE.iter().position(|&g| g == why).unwrap_or(0) as u8);
                }
                Event::Accept(port) => {
                    w.u8(2);
                    w.u64(port as u64);
                    w.u8(0);
                }
            }
        }
        // the sockets
        w.n(self.listeners.len());
        for &(port, owner) in &self.listeners {
            w.u16(port);
            w.n(owner);
        }
        w.n(self.udp.len());
        for u in &self.udp {
            w.u32(u.id);
            w.n(u.owner);
            w.u16(u.port);
            w.n(u.rx.len());
            for (a, d) in &u.rx {
                w.u32(a.ip);
                w.u16(a.port);
                w.bytes(d);
            }
            w.n(u.peers.len());
            for &(a, b) in &u.peers {
                w.u32(a);
                w.u32(b);
            }
            w.n(u.sock);
            w.u32(u.lip);
            w.u8(u.peer.is_some() as u8);
            let p = u.peer.unwrap_or(Addr { ip: 0, port: 0 });
            w.u32(p.ip);
            w.u16(p.port);
        }
        w.n(self.raw.len());
        for x in &self.raw {
            w.u32(x.id);
            w.n(x.owner);
            w.u8(x.proto);
            w.n(x.rx.len());
            for (ip, ttl, d) in &x.rx {
                w.u32(*ip);
                w.u8(*ttl);
                w.bytes(d);
            }
            w.n(x.sock);
        }
        w.u32(self.next_id);
        self.sk.save(w);
        Some(core::mem::take(&mut w.0))
    }

    /// Take over another version's state; on an error nothing changed.
    pub fn load_state(&mut self, state: &[u8]) -> Result<(), String> {
        let (mut r, v) = R::new(state, TAG)?;
        if v == 0 || v > VERSION {
            return Err(format!("state format {v}: this version reads 1 to {VERSION}"));
        }
        let r = &mut r;
        let mut st = Stack::new([0; 6], 0, 0, 0);
        st.conf.macs = r.list(|r| r.mac())?;
        let running = load_conf(r)?;
        st.set_config(&running)?;
        st.conf.candidate = load_opt_conf(r)?;
        st.conf.baseline = load_opt_conf(r)?;
        st.conf.deadline = Some(r.u64()?).filter(|&d| d != u64::MAX);
        if r.n()? != st.ifs.0.len() {
            return Err(String::from("damaged state (interfaces)"));
        }
        for f in st.ifs.0.iter_mut() {
            f.arp = r.list(|r| Ok(crate::iface::ArpEntry { ip: r.u32()?, mac: r.mac()?, seen: r.u64()? }))?;
            f.pending = r.list(|r| Ok((r.u32()?, r.bytes()?, r.u64()?)))?;
            f.ip_id = r.u16()?;
            (f.stats.rx, f.stats.tx, f.stats.rx_dropped, f.stats.tx_dropped) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
        }
        st.ifs.2 = r.list(|r| r.bytes())?.into();
        let t = &mut st.tcp;
        t.max_conns = r.n()?;
        t.listening = r.list(|r| r.u16())?;
        t.slots = r.list(|r| {
            let generation = r.u32()?;
            if !r.bool()? {
                return Ok(Slot { generation, sock: None });
            }
            let state = *STATES.get(r.u8()? as usize).ok_or(Bad)?;
            let (lip, lport, rip, rport) = (r.u32()?, r.u16()?, r.u32()?, r.u16()?);
            let (snd_una, snd_nxt, snd_max, snd_wnd, rcv_nxt, retries) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
            let (tx, rx) = (r.bytes()?, r.bytes()?);
            let (rto, rtx_at, deadline, mss, owner, f) = (r.u64()?, r.u64()?, r.u64()?, r.n()?, r.n()?, r.u8()?);
            let s = Sock {
                state,
                lip,
                lport,
                rip,
                rport,
                snd_una,
                snd_nxt,
                snd_max,
                snd_wnd,
                rcv_nxt,
                tx,
                rx,
                fin_queued: f & 1 != 0,
                rto,
                rtx_at,
                retries,
                deadline,
                mss,
                accepted: f & 2 != 0,
                owner,
                released: f & 4 != 0,
            };
            Ok(Slot { generation, sock: Some(s) })
        })?;
        t.events = r.list(|r| {
            let (kind, v, b) = (r.u8()?, r.u64()?, r.u8()?);
            Ok(match kind {
                0 => Event::Conn(Handle::from_raw(v), b),
                1 => Event::Gone(Handle::from_raw(v), *GONE.get(b as usize).ok_or(Bad)?),
                2 => Event::Accept(v as u16),
                _ => return Err(Bad),
            })
        })?;
        st.listeners = r.list(|r| Ok((r.u16()?, r.n()?)))?;
        st.udp = r.list(|r| {
            let (id, owner, port) = (r.u32()?, r.n()?, r.u16()?);
            let rx = r.list(|r| Ok((Addr { ip: r.u32()?, port: r.u16()? }, r.bytes()?)))?.into();
            let peers = r.list(|r| Ok((r.u32()?, r.u32()?)))?;
            let (sock, lip, has_peer) = (r.n()?, r.u32()?, r.bool()?);
            let peer = Addr { ip: r.u32()?, port: r.u16()? };
            Ok(Udp { id, owner, port, rx, peers, sock, lip, peer: has_peer.then_some(peer) })
        })?;
        st.raw = r.list(|r| {
            let (id, owner, proto) = (r.u32()?, r.n()?, r.u8()?);
            let rx = r.list(|r| Ok((r.u32()?, r.u8()?, r.bytes()?)))?.into();
            Ok(Raw { id, owner, proto, rx, sock: r.n()? })
        })?;
        st.next_id = r.u32()?;
        st.sk = crate::socket::Sockets::load(r)?;
        r.end()?;
        st.owner_names = core::mem::take(&mut self.owner_names);
        *self = st;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Link;
    use rustros_api::socket::*;

    struct Wire {
        now: u64,
    }
    impl Link for Wire {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn send(&mut self, _nic: usize, _frame: &[u8]) -> bool {
            true
        }
        fn random(&mut self) -> u64 {
            0x1234_5678
        }
        fn notify(&mut self, _owner: usize, _sock: Socket, _events: u32) {}
    }

    const US: u32 = 0x0a00_0001;

    fn pump(st: &mut Stack, w: &mut Wire) {
        for _ in 0..4 {
            w.now += 1;
            st.poll(w);
        }
    }

    /// A connection with data in flight both ways, an epoll instance with
    /// an event on its ready list, a UDP socket with a datagram queued and a
    /// configuration being tried: the next version carries on with all of it.
    #[test]
    fn carries_on() {
        let w = &mut Wire { now: 1 };
        let mut st = Stack::new([2; 6], 0, 0, 0);
        st.conf.macs = alloc::vec![[2; 6], [3; 6]];
        let conf = NetConf {
            ifs: alloc::vec![IfConf { phys: 0, vlan: None, ip: US, mask: 0xFFFF_FF00, gw: 0x0a00_00fe, mtu: 1500, extra: alloc::vec![0x0a00_0009] }, IfConf { phys: 1, vlan: Some(20), ip: 0x0a14_0001, mask: 0xFFFF_FF00, gw: 0, mtu: 1400, extra: Vec::new() }],
            routes: alloc::vec![RouteConf { net: 0x0a63_0000, mask: 0xFFFF_0000, gw: 0x0a00_0005, src: 0, src_mask: 0 }],
        };
        st.set_config(&conf).unwrap();
        st.set_candidate(Some(NetConf::default()));
        st.ifs.0[0].arp.push(crate::iface::ArpEntry { ip: 0x0a00_0005, mac: [9; 6], seen: 1 });
        let l = st.sk_socket(1, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0).unwrap();
        st.sk_bind(1, w, l, &SockAddr::v4(0, 80)).unwrap();
        st.sk_listen(1, w, l, 8).unwrap();
        let c = st.sk_socket(2, AF_INET, SOCK_STREAM, 0).unwrap();
        assert_eq!(st.sk_connect(2, w, c, &SockAddr::v4(US, 80)), Err(Errno::EINPROGRESS));
        pump(&mut st, w);
        let (s, _) = st.sk_accept(1, l, 0).unwrap();
        let ep = st.sk_epoll_create(1).unwrap();
        st.sk_epoll_ctl(1, ep, EPOLL_CTL_ADD, s, EPOLLIN | EPOLLET, 42).unwrap();
        st.sk_sendto(2, w, c, b"before", 0, None).unwrap();
        pump(&mut st, w);
        let u = st.sk_socket(3, AF_INET, SOCK_DGRAM, 0).unwrap();
        st.sk_bind(3, w, u, &SockAddr::v4(0, 53)).unwrap();
        let u2 = st.sk_socket(4, AF_INET, SOCK_DGRAM, 0).unwrap();
        st.sk_sendto(4, w, u2, b"dgram", 0, Some(&SockAddr::v4(US, 53))).unwrap();
        pump(&mut st, w);
        // unsent data queued: written to the loopback queue only after the handover
        st.sk_sendto(1, w, s, b"answer", 0, None).unwrap();

        let running = st.running();
        assert_eq!(running.ifs.len(), 3, "both NICs and the VLAN");
        let state = st.save_state(VERSION).unwrap();
        assert!(st.save_state(VERSION + 1).is_none());
        let mut next = Stack::new([0; 6], 0, 0, 0);
        assert!(next.load_state(&state[..state.len() - 1]).is_err(), "a short state is refused");
        assert!(next.load_state(b"NETS\x02\0\0\0").is_err(), "a newer format is refused");
        next.load_state(&state).unwrap();
        assert_eq!(next.save_state(VERSION).unwrap(), state, "the same state again");
        let mut st = next;

        assert_eq!(st.running(), running);
        assert_eq!(st.candidate(), Some(NetConf::default()));
        assert_eq!(st.ifs.0[0].arp.len(), 1);
        let mut out = [EpollEvent::default(); 4];
        assert_eq!(st.sk_epoll_wait(1, ep, &mut out), Ok(1));
        assert_eq!(out[0].data, 42);
        let mut b = [0u8; 32];
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Ok((6, None)));
        assert_eq!(&b[..6], b"before");
        assert_eq!(st.sk_recvfrom(3, w, u, &mut b, 0).map(|r| r.0), Ok(5));
        // both directions go on over the same connection
        st.sk_sendto(2, w, c, b"after", 0, None).unwrap();
        pump(&mut st, w);
        assert_eq!(st.sk_recvfrom(1, w, s, &mut b, 0), Ok((5, None)));
        assert_eq!(st.sk_recvfrom(2, w, c, &mut b, 0), Ok((6, None)));
        assert_eq!(&b[..6], b"answer");
        // and close cleanly
        st.sk_close(2, w, c).unwrap();
        st.sk_close(1, w, s).unwrap();
        pump(&mut st, w);
        w.now += 5000;
        pump(&mut st, w);
        assert_eq!(st.tcp.connections().count(), 0);
    }
}
