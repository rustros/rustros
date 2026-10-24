//! The applications' sockets, with Linux semantics (`rustros_api::socket`),
//! on top of the stack's TCP, UDP and raw IP. Every change of a socket is
//! reported at the moment it happens: its event counter moves, the kernel
//! hears of it (`Link::notify`) and the owner's epoll instances get it on
//! their ready lists.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use rustros_api::socket::*;
use rustros_api::Ip;
use rustros_util::epoll::EpollSet;
#[cfg(feature = "handover")]
use rustros_util::snap::{Bad, R, W};

use crate::Link;
use crate::iface::{PROTO_TCP, PROTO_UDP};
use crate::stack::{Addr, Raw, Stack, Udp};
use crate::tcp::{EV_CONNECTED, EV_DATA, EV_FIN, EV_SPACE, Event, Gone, Handle};

const EPHEMERAL: core::ops::Range<u32> = 49152..65536;
/// Options the stack keeps for the caller without acting on them (the
/// process layer's timeouts, buffer sizes, keepalive ...).
const KEPT: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    /// TCP, not listening or connected (maybe bound)
    Fresh,
    Listen(u16),
    /// TCP connection; true while the handshake is going on
    Conn(Handle, bool),
    /// TCP connection gone (`err` says why, if it failed)
    Dead,
    /// UDP, bound once it has a port
    Dgram(Option<u32>),
    Raw(u32),
}

pub(crate) struct Entry {
    owner: usize,
    ty: i32,
    proto: i32,
    /// SOCK_NONBLOCK / SOCK_CLOEXEC as given (kept for the process layer)
    flags: i32,
    st: St,
    /// bound address (port 0: not bound)
    local: (Ip, u16),
    /// moves with every event
    seq: u64,
    /// pending error (SO_ERROR), reported once
    err: Option<Errno>,
    shut_rd: bool,
    shut_wr: bool,
    broadcast: bool,
    /// SO_LINGER with a zero timeout: close resets
    linger0: bool,
    kept: Vec<(i32, i32, Vec<u8>)>,
}

struct Slot<T> {
    generation: u32,
    it: Option<T>,
}

#[derive(Default)]
pub struct Sockets {
    socks: Vec<Slot<Entry>>,
    /// TCP connection -> socket
    by_conn: BTreeMap<u64, usize>,
    epolls: Vec<Slot<(usize, EpollSet)>>,
}

// ---------------------------------------------------------------- state handover

#[cfg(feature = "handover")]
impl Sockets {
    /// The socket table and the epoll instances, for the next version.
    pub(crate) fn save(&self, w: &mut W) {
        w.n(self.socks.len());
        for s in &self.socks {
            w.u32(s.generation);
            let Some(e) = &s.it else {
                w.u8(0);
                continue;
            };
            w.u8(1);
            w.n(e.owner);
            w.u32(e.ty as u32);
            w.u32(e.proto as u32);
            w.u32(e.flags as u32);
            match e.st {
                St::Fresh => w.u8(0),
                St::Listen(port) => {
                    w.u8(1);
                    w.u16(port);
                }
                St::Conn(h, hs) => {
                    w.u8(2);
                    w.u64(h.to_raw());
                    w.u8(hs as u8);
                }
                St::Dead => w.u8(3),
                St::Dgram(id) => {
                    w.u8(4);
                    w.u64(id.map_or(u64::MAX, u64::from));
                }
                St::Raw(id) => {
                    w.u8(5);
                    w.u32(id);
                }
            }
            w.u32(e.local.0);
            w.u16(e.local.1);
            w.u64(e.seq);
            w.u32(e.err.map_or(0, |e| e.0 as u32));
            w.u8(e.shut_rd as u8 | (e.shut_wr as u8) << 1 | (e.broadcast as u8) << 2 | (e.linger0 as u8) << 3);
            w.n(e.kept.len());
            for (level, name, v) in &e.kept {
                w.u32(*level as u32);
                w.u32(*name as u32);
                w.bytes(v);
            }
        }
        w.n(self.by_conn.len());
        for (&h, &i) in &self.by_conn {
            w.u64(h);
            w.n(i);
        }
        w.n(self.epolls.len());
        for s in &self.epolls {
            w.u32(s.generation);
            match &s.it {
                Some((owner, set)) => {
                    w.u8(1);
                    w.n(*owner);
                    set.save(w);
                }
                None => w.u8(0),
            }
        }
    }

    pub(crate) fn load(r: &mut R) -> Result<Sockets, Bad> {
        let socks = r.list(|r| {
            let generation = r.u32()?;
            if !r.bool()? {
                return Ok(Slot { generation, it: None });
            }
            let (owner, ty, proto, flags) = (r.n()?, r.u32()? as i32, r.u32()? as i32, r.u32()? as i32);
            let st = match r.u8()? {
                0 => St::Fresh,
                1 => St::Listen(r.u16()?),
                2 => St::Conn(Handle::from_raw(r.u64()?), r.bool()?),
                3 => St::Dead,
                4 => St::Dgram(u32::try_from(r.u64()?).ok()),
                5 => St::Raw(r.u32()?),
                _ => return Err(Bad),
            };
            let local = (r.u32()?, r.u16()?);
            let seq = r.u64()?;
            let err = match r.u32()? as i32 {
                0 => None,
                e => Some(Errno(e)),
            };
            let f = r.u8()?;
            let kept = r.list(|r| Ok((r.u32()? as i32, r.u32()? as i32, r.bytes()?)))?;
            let e = Entry { owner, ty, proto, flags, st, local, seq, err, shut_rd: f & 1 != 0, shut_wr: f & 2 != 0, broadcast: f & 4 != 0, linger0: f & 8 != 0, kept };
            Ok(Slot { generation, it: Some(e) })
        })?;
        let mut by_conn = BTreeMap::new();
        for _ in 0..r.count()? {
            by_conn.insert(r.u64()?, r.n()?);
        }
        let epolls = r.list(|r| {
            let generation = r.u32()?;
            let it = if r.bool()? { Some((r.n()?, EpollSet::load(r)?)) } else { None };
            Ok(Slot { generation, it })
        })?;
        Ok(Sockets { socks, by_conn, epolls })
    }
}

fn raw_of(idx: usize, generation: u32) -> u64 {
    (idx as u64) << 32 | generation as u64
}

fn put<T>(slots: &mut Vec<Slot<T>>, it: T) -> u64 {
    match slots.iter().position(|s| s.it.is_none()) {
        Some(i) => {
            slots[i].it = Some(it);
            raw_of(i, slots[i].generation)
        }
        None => {
            slots.push(Slot { generation: 0, it: Some(it) });
            raw_of(slots.len() - 1, 0)
        }
    }
}

fn find<T>(slots: &[Slot<T>], raw: u64) -> Option<usize> {
    let idx = (raw >> 32) as usize;
    let s = slots.get(idx)?;
    (s.generation == raw as u32 && s.it.is_some()).then_some(idx)
}

fn int(v: &[u8]) -> SockResult<i32> {
    v.get(..4).map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]])).ok_or(Errno::EINVAL)
}

fn v4(a: &SockAddr) -> SockResult<(Ip, u16)> {
    match a.ipv4() {
        Some(ip) => Ok((ip, a.port())),
        None => Err(Errno::EAFNOSUPPORT),
    }
}

impl Stack {
    fn idx(&self, owner: usize, s: Socket) -> SockResult<usize> {
        let i = find(&self.sk.socks, s.to_raw()).ok_or(Errno::EBADF)?;
        if self.ent(i).owner != owner {
            return Err(Errno::EBADF);
        }
        Ok(i)
    }

    fn ent(&self, i: usize) -> &Entry {
        self.sk.socks[i].it.as_ref().unwrap()
    }

    fn ent_mut(&mut self, i: usize) -> &mut Entry {
        self.sk.socks[i].it.as_mut().unwrap()
    }

    fn sock_of(&self, i: usize) -> Socket {
        Socket::from_raw(raw_of(i, self.sk.socks[i].generation))
    }

    /// Socket `i` changed (`ev`: what happened): tell the kernel and the
    /// owner's epoll instances.
    pub(crate) fn note(&mut self, link: &mut dyn Link, i: usize, ev: u32) {
        let Some(e) = self.sk.socks.get_mut(i).and_then(|s| s.it.as_mut()) else { return };
        e.seq += 1;
        let owner = e.owner;
        let s = self.sock_of(i);
        link.notify(owner, s, ev);
        for (o, set) in self.sk.epolls.iter_mut().filter_map(|e| e.it.as_mut()) {
            if *o == owner {
                set.event(s.to_raw(), ev);
            }
        }
    }

    /// What the TCP layer did since last time, as socket events.
    pub(crate) fn tcp_events(&mut self, link: &mut dyn Link) {
        for ev in self.tcp.take_events() {
            match ev {
                Event::Conn(h, bits) => {
                    let Some(&i) = self.sk.by_conn.get(&h.to_raw()) else { continue };
                    let mut e = 0;
                    if bits & EV_CONNECTED != 0 {
                        self.ent_mut(i).st = St::Conn(h, false);
                        e |= EPOLLOUT | EPOLLWRNORM;
                    }
                    if bits & EV_DATA != 0 {
                        e |= EPOLLIN | EPOLLRDNORM;
                    }
                    if bits & EV_SPACE != 0 {
                        e |= EPOLLOUT | EPOLLWRNORM;
                    }
                    if bits & EV_FIN != 0 {
                        e |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
                    }
                    self.note(link, i, e);
                }
                Event::Gone(h, why) => {
                    let Some(i) = self.sk.by_conn.remove(&h.to_raw()) else { continue };
                    let err = match why {
                        Gone::Done => None,
                        Gone::Refused => Some(Errno::ECONNREFUSED),
                        Gone::Reset => Some(Errno::ECONNRESET),
                        Gone::TimedOut => Some(Errno::ETIMEDOUT),
                    };
                    let e = self.ent_mut(i);
                    e.st = St::Dead;
                    e.err = err;
                    let ev = EPOLLIN | EPOLLRDNORM | EPOLLRDHUP | EPOLLHUP | EPOLLOUT | if err.is_some() { EPOLLERR } else { 0 };
                    self.note(link, i, ev);
                }
                Event::Accept(port) => {
                    let ls: Vec<usize> = (0..self.sk.socks.len()).filter(|&i| self.sk.socks[i].it.as_ref().is_some_and(|e| e.st == St::Listen(port))).collect();
                    for i in ls {
                        self.note(link, i, EPOLLIN | EPOLLRDNORM);
                    }
                }
            }
        }
    }

    /// Readiness of socket `i` now.
    fn mask(&self, i: usize) -> u32 {
        let e = self.ent(i);
        let err = if e.err.is_some() { EPOLLERR } else { 0 };
        let m = match e.st {
            St::Fresh => EPOLLOUT | EPOLLWRNORM | EPOLLHUP,
            St::Listen(port) => {
                if self.tcp.acceptable(port) {
                    EPOLLIN | EPOLLRDNORM
                } else {
                    0
                }
            }
            St::Conn(_, true) => 0,
            St::Conn(h, false) => {
                let fin = self.tcp.fin_received(h);
                let mut m = 0;
                if self.tcp.queued(h).0 > 0 || fin || e.shut_rd {
                    m |= EPOLLIN | EPOLLRDNORM;
                }
                if fin {
                    m |= EPOLLRDHUP;
                }
                if !e.shut_wr && self.tcp.send_space(h) > 0 {
                    m |= EPOLLOUT | EPOLLWRNORM;
                }
                if fin && e.shut_wr {
                    m |= EPOLLHUP;
                }
                m
            }
            St::Dead => EPOLLIN | EPOLLRDNORM | EPOLLRDHUP | EPOLLHUP | EPOLLOUT | EPOLLWRNORM,
            St::Dgram(id) => {
                let full = id.and_then(|id| self.udp.iter().find(|u| u.id == id)).is_some_and(|u| !u.rx.is_empty());
                EPOLLOUT | EPOLLWRNORM | if full { EPOLLIN | EPOLLRDNORM } else { 0 }
            }
            St::Raw(id) => {
                let full = self.raw.iter().find(|r| r.id == id).is_some_and(|r| !r.rx.is_empty());
                EPOLLOUT | EPOLLWRNORM | if full { EPOLLIN | EPOLLRDNORM } else { 0 }
            }
        };
        m | err
    }

    fn ephemeral(&self, link: &mut dyn Link, used: impl Fn(u16) -> bool) -> SockResult<u16> {
        let span = EPHEMERAL.end - EPHEMERAL.start;
        let start = (link.random() % span as u64) as u32;
        (0..span).map(|i| (EPHEMERAL.start + (start + i) % span) as u16).find(|&p| !used(p)).ok_or(Errno::EADDRINUSE)
    }

    fn is_local(&self, ip: Ip) -> bool {
        self.ifs.0.iter().any(|f| f.is_local(ip))
    }

    fn tcp_port_used(&self, port: u16) -> bool {
        self.tcp.is_listening(port) || self.sk.socks.iter().filter_map(|s| s.it.as_ref()).any(|e| e.ty == SOCK_STREAM && e.local.1 == port && matches!(e.st, St::Fresh | St::Listen(_)))
    }

    /// Bind UDP socket `i` (0: an ephemeral port).
    fn udp_bind_at(&mut self, link: &mut dyn Link, i: usize, ip: Ip, port: u16) -> SockResult<u32> {
        let port = if port == 0 {
            self.ephemeral(link, |p| self.udp.iter().any(|u| u.port == p))?
        } else if self.udp.iter().any(|u| u.port == port && (u.lip == 0 || ip == 0 || u.lip == ip)) {
            return Err(Errno::EADDRINUSE);
        } else {
            port
        };
        let id = self.id();
        let owner = self.ent(i).owner;
        self.udp.push(Udp { id, owner, port, rx: VecDeque::new(), peers: Vec::new(), sock: i, lip: ip, peer: None });
        let e = self.ent_mut(i);
        e.st = St::Dgram(Some(id));
        e.local = (ip, port);
        Ok(id)
    }

    fn udp_of(&mut self, link: &mut dyn Link, i: usize) -> SockResult<u32> {
        match self.ent(i).st {
            St::Dgram(Some(id)) => Ok(id),
            St::Dgram(None) => self.udp_bind_at(link, i, 0, 0),
            _ => Err(Errno::EINVAL),
        }
    }

    // ---------------------------------------------------------------- the calls

    pub fn sk_socket(&mut self, owner: usize, domain: i32, ty: i32, protocol: i32) -> SockResult<Socket> {
        if domain != AF_INET {
            return Err(Errno::EAFNOSUPPORT);
        }
        let flags = ty & !0xF;
        if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        let ty = ty & 0xF;
        let (st, proto) = match (ty, protocol) {
            (SOCK_STREAM, 0 | IPPROTO_TCP) => (St::Fresh, IPPROTO_TCP),
            (SOCK_DGRAM, 0 | IPPROTO_UDP) => (St::Dgram(None), IPPROTO_UDP),
            (SOCK_RAW, p) if (1..=254).contains(&p) && p != PROTO_TCP as i32 && p != PROTO_UDP as i32 => (St::Raw(0), p),
            (SOCK_STREAM | SOCK_DGRAM | SOCK_RAW, _) => return Err(Errno::EPROTONOSUPPORT),
            _ => return Err(Errno::ESOCKTNOSUPPORT),
        };
        let e = Entry { owner, ty, proto, flags, st, local: (0, 0), seq: 0, err: None, shut_rd: false, shut_wr: false, broadcast: false, linger0: false, kept: Vec::new() };
        let raw = put(&mut self.sk.socks, e);
        let i = (raw >> 32) as usize;
        if ty == SOCK_RAW {
            let id = self.id();
            self.raw.push(Raw { id, owner, proto: proto as u8, rx: VecDeque::new(), sock: i });
            self.ent_mut(i).st = St::Raw(id);
        }
        Ok(Socket::from_raw(raw))
    }

    pub fn sk_bind(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        let (ip, port) = v4(addr)?;
        if ip != 0 && !self.is_local(ip) {
            return Err(Errno::EADDRNOTAVAIL);
        }
        match self.ent(i).st {
            St::Fresh if self.ent(i).local.1 == 0 => {
                let port = if port == 0 {
                    self.ephemeral(link, |p| self.tcp_port_used(p) || self.tcp.port_in_use(p))?
                } else if self.tcp_port_used(port) {
                    return Err(Errno::EADDRINUSE);
                } else {
                    port
                };
                self.ent_mut(i).local = (ip, port);
                Ok(())
            }
            St::Dgram(None) => self.udp_bind_at(link, i, ip, port).map(|_| ()),
            St::Raw(_) => {
                self.ent_mut(i).local = (ip, 0);
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn sk_listen(&mut self, owner: usize, link: &mut dyn Link, s: Socket, _backlog: i32) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        match self.ent(i).st {
            St::Listen(_) => Ok(()),
            St::Fresh => {
                let port = match self.ent(i).local.1 {
                    0 => self.ephemeral(link, |p| self.tcp_port_used(p) || self.tcp.port_in_use(p))?,
                    p => p,
                };
                if self.tcp.is_listening(port) {
                    return Err(Errno::EADDRINUSE);
                }
                self.tcp.listen(port);
                self.listeners.push((port, owner));
                let e = self.ent_mut(i);
                e.local.1 = port;
                e.st = St::Listen(port);
                Ok(())
            }
            St::Dgram(_) | St::Raw(_) => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn sk_accept(&mut self, owner: usize, s: Socket, flags: i32) -> SockResult<(Socket, SockAddr)> {
        let i = self.idx(owner, s)?;
        if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        let St::Listen(port) = self.ent(i).st else { return Err(Errno::EINVAL) };
        let h = self.tcp.accept(port, owner).ok_or(Errno::EAGAIN)?;
        let k = self.tcp.sock(h).ok_or(Errno::ECONNABORTED)?;
        let (local, peer) = ((k.lip, k.lport), SockAddr::v4(k.rip, k.rport));
        let e = Entry { owner, ty: SOCK_STREAM, proto: IPPROTO_TCP, flags, st: St::Conn(h, false), local, seq: 0, err: None, shut_rd: false, shut_wr: false, broadcast: false, linger0: false, kept: Vec::new() };
        let raw = put(&mut self.sk.socks, e);
        self.sk.by_conn.insert(h.to_raw(), (raw >> 32) as usize);
        Ok((Socket::from_raw(raw), peer))
    }

    pub fn sk_connect(&mut self, owner: usize, link: &mut dyn Link, s: Socket, addr: &SockAddr) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        let (ip, port) = v4(addr)?;
        match self.ent(i).st {
            St::Fresh => {
                if ip == 0 || port == 0 || self.ifs.src_for(ip) == 0 {
                    return Err(Errno::ENETUNREACH);
                }
                let (lip, lport) = self.ent(i).local;
                let lport = if lport != 0 { lport } else { self.ephemeral(link, |p| self.tcp.port_in_use(p) || self.tcp_port_used(p))? };
                let h = self.tcp.connect(&mut self.ifs, link, lip, ip, port, lport, owner).ok_or(Errno::EAGAIN)?;
                let lip = self.tcp.sock(h).map_or(lip, |k| k.lip);
                let e = self.ent_mut(i);
                e.st = St::Conn(h, true);
                e.local = (lip, lport);
                self.sk.by_conn.insert(h.to_raw(), i);
                Err(Errno::EINPROGRESS)
            }
            St::Conn(_, true) => Err(Errno::EALREADY),
            St::Conn(_, false) => Err(Errno::EISCONN),
            St::Dead => Err(self.ent_mut(i).err.take().unwrap_or(Errno::ECONNABORTED)),
            St::Listen(_) => Err(Errno::EINVAL),
            St::Dgram(_) => {
                let id = self.udp_of(link, i)?;
                if let Some(u) = self.udp.iter_mut().find(|u| u.id == id) {
                    u.peer = Some(Addr { ip, port });
                }
                // as on Linux, the local address is now the one towards the peer
                if self.ent(i).local.0 == 0 {
                    let src = self.ifs.src_for(ip);
                    self.ent_mut(i).local.0 = src;
                }
                Ok(())
            }
            St::Raw(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub fn sk_sendto(&mut self, owner: usize, link: &mut dyn Link, s: Socket, data: &[u8], _flags: i32, to: Option<&SockAddr>) -> SockResult<usize> {
        let i = self.idx(owner, s)?;
        match self.ent(i).st {
            St::Fresh | St::Listen(_) => Err(Errno::ENOTCONN),
            St::Conn(_, true) => Err(Errno::EAGAIN),
            St::Conn(h, false) => {
                if self.ent(i).shut_wr {
                    return Err(Errno::EPIPE);
                }
                if data.is_empty() {
                    return Ok(0);
                }
                match self.tcp.send(&mut self.ifs, link, h, data) {
                    0 => Err(Errno::EAGAIN),
                    n => Ok(n),
                }
            }
            // after a reset: ECONNRESET once, then EPIPE (SIGPIPE is the process layer's)
            St::Dead => Err(self.ent_mut(i).err.take().unwrap_or(Errno::EPIPE)),
            St::Dgram(_) => {
                let id = self.udp_of(link, i)?;
                let u = self.udp.iter().find(|u| u.id == id).ok_or(Errno::EBADF)?;
                let to = match to {
                    Some(a) => {
                        let (ip, port) = v4(a)?;
                        Addr { ip, port }
                    }
                    None => u.peer.ok_or(Errno::EDESTADDRREQ)?,
                };
                if to.ip == u32::MAX && !self.ent(i).broadcast {
                    return Err(Errno::EACCES);
                }
                let (port, lip) = (u.port, u.lip);
                // reply from the address the peer sent to (still one of ours?)
                let from = if lip != 0 { lip } else { u.peers.iter().find(|p| p.0 == to.ip).map_or(0, |p| p.1) };
                let from = if self.is_local(from) { from } else { 0 };
                if 20 + 8 + data.len() > self.ifs.mtu_for(to.ip) {
                    return Err(Errno::EMSGSIZE);
                }
                if self.ifs.src_for(to.ip) == 0 && to.ip != u32::MAX {
                    return Err(Errno::ENETUNREACH);
                }
                if self.ifs.send_udp_from(link, from, to.ip, port, to.port, data) { Ok(data.len()) } else { Err(Errno::ENETUNREACH) }
            }
            St::Raw(id) => {
                let dst = to.ok_or(Errno::EDESTADDRREQ).and_then(v4)?.0;
                let proto = self.raw.iter().find(|r| r.id == id).map_or(0, |r| r.proto);
                if 20 + data.len() > self.ifs.mtu_for(dst) {
                    return Err(Errno::EMSGSIZE);
                }
                if self.ifs.send_ip(link, dst, proto, data) { Ok(data.len()) } else { Err(Errno::ENETUNREACH) }
            }
        }
    }

    pub fn sk_recvfrom(&mut self, owner: usize, link: &mut dyn Link, s: Socket, buf: &mut [u8], flags: i32) -> SockResult<(usize, Option<SockAddr>)> {
        let i = self.idx(owner, s)?;
        let peek = flags & MSG_PEEK != 0;
        match self.ent(i).st {
            St::Fresh | St::Listen(_) => Err(Errno::ENOTCONN),
            St::Conn(_, true) => Err(Errno::EAGAIN),
            St::Conn(h, false) => {
                if self.ent(i).shut_rd {
                    return Ok((0, None));
                }
                let data = self.tcp.peek(h);
                if !data.is_empty() {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if !peek {
                        self.tcp.consume(&mut self.ifs, link, h, n);
                    }
                    return Ok((n, None));
                }
                if self.tcp.fin_received(h) { Ok((0, None)) } else { Err(Errno::EAGAIN) }
            }
            // a failure is reported once, then it reads as the end
            St::Dead => match self.ent_mut(i).err.take() {
                Some(e) => Err(e),
                None => Ok((0, None)),
            },
            St::Dgram(None) => Err(Errno::EAGAIN),
            St::Dgram(Some(id)) => {
                let u = self.udp.iter_mut().find(|u| u.id == id).ok_or(Errno::EBADF)?;
                let (from, data) = if peek { u.rx.front().cloned() } else { u.rx.pop_front() }.ok_or(Errno::EAGAIN)?;
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                let len = if flags & MSG_TRUNC != 0 { data.len() } else { n };
                Ok((len, Some(SockAddr::v4(from.ip, from.port))))
            }
            St::Raw(id) => {
                let r = self.raw.iter_mut().find(|r| r.id == id).ok_or(Errno::EBADF)?;
                let (src, ttl, payload) = if peek { r.rx.front().cloned() } else { r.rx.pop_front() }.ok_or(Errno::EAGAIN)?;
                // as on Linux: the IP header, then the payload
                let (proto, dst) = (r.proto, self.ifs.src_for(src));
                let mut p = Vec::with_capacity(20 + payload.len());
                p.extend_from_slice(&[0x45, 0]);
                p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
                p.extend_from_slice(&[0, 0, 0, 0, ttl, proto, 0, 0]);
                p.extend_from_slice(&src.to_be_bytes());
                p.extend_from_slice(&dst.to_be_bytes());
                let c = rustros_util::wire::checksum(&p[..20], 0);
                p[10..12].copy_from_slice(&c.to_be_bytes());
                p.extend_from_slice(&payload);
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                let len = if flags & MSG_TRUNC != 0 { p.len() } else { n };
                Ok((len, Some(SockAddr::v4(src, 0))))
            }
        }
    }

    pub fn sk_shutdown(&mut self, owner: usize, link: &mut dyn Link, s: Socket, how: i32) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        if !(SHUT_RD..=SHUT_RDWR).contains(&how) {
            return Err(Errno::EINVAL);
        }
        match self.ent(i).st {
            St::Conn(h, false) => {
                if how != SHUT_RD && !self.ent(i).shut_wr {
                    self.tcp.shutdown_write(&mut self.ifs, link, h);
                    self.ent_mut(i).shut_wr = true;
                }
                if how != SHUT_WR {
                    self.ent_mut(i).shut_rd = true;
                    self.note(link, i, EPOLLIN | EPOLLRDNORM | EPOLLRDHUP);
                }
                Ok(())
            }
            St::Dgram(Some(id)) if self.udp.iter().any(|u| u.id == id && u.peer.is_some()) => {
                let e = self.ent_mut(i);
                e.shut_rd |= how != SHUT_WR;
                e.shut_wr |= how != SHUT_RD;
                Ok(())
            }
            _ => Err(Errno::ENOTCONN),
        }
    }

    pub fn sk_close(&mut self, owner: usize, link: &mut dyn Link, s: Socket) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        let e = self.sk.socks[i].it.take().unwrap();
        self.sk.socks[i].generation = self.sk.socks[i].generation.wrapping_add(1);
        match e.st {
            St::Conn(h, _) => {
                self.sk.by_conn.remove(&h.to_raw());
                if e.linger0 {
                    self.tcp.abort(&mut self.ifs, link, h);
                } else {
                    self.tcp.close(&mut self.ifs, link, h);
                }
            }
            St::Listen(port) => {
                self.listeners.retain(|l| l.0 != port);
                self.tcp.unlisten(&mut self.ifs, link, port);
            }
            St::Dgram(Some(id)) => self.udp.retain(|u| u.id != id),
            St::Raw(id) => self.raw.retain(|r| r.id != id),
            _ => {}
        }
        for (o, set) in self.sk.epolls.iter_mut().filter_map(|e| e.it.as_mut()) {
            if *o == owner {
                set.forget(s.to_raw());
            }
        }
        Ok(())
    }

    pub fn sk_getsockname(&self, owner: usize, s: Socket) -> SockResult<SockAddr> {
        let i = self.idx(owner, s)?;
        let (ip, port) = match self.ent(i).st {
            St::Conn(h, _) => self.tcp.sock(h).map_or(self.ent(i).local, |k| (k.lip, k.lport)),
            _ => self.ent(i).local,
        };
        Ok(SockAddr::v4(ip, port))
    }

    pub fn sk_getpeername(&self, owner: usize, s: Socket) -> SockResult<SockAddr> {
        let i = self.idx(owner, s)?;
        match self.ent(i).st {
            St::Conn(h, false) => self.tcp.sock(h).map(|k| SockAddr::v4(k.rip, k.rport)).ok_or(Errno::ENOTCONN),
            St::Dgram(Some(id)) => self.udp.iter().find(|u| u.id == id).and_then(|u| u.peer).map(|p| SockAddr::v4(p.ip, p.port)).ok_or(Errno::ENOTCONN),
            _ => Err(Errno::ENOTCONN),
        }
    }

    pub fn sk_setsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &[u8]) -> SockResult<()> {
        let i = self.idx(owner, s)?;
        let stream = self.ent(i).ty == SOCK_STREAM;
        match (level, name) {
            (SOL_SOCKET, SO_BROADCAST) => self.ent_mut(i).broadcast = int(value)? != 0,
            (SOL_SOCKET, SO_LINGER) => {
                let (on, secs) = (int(value)?, int(value.get(4..).unwrap_or(&[]))?);
                self.ent_mut(i).linger0 = on != 0 && secs == 0;
            }
            // several sockets on one port: not yet (EADDRINUSE stays)
            (SOL_SOCKET, SO_REUSEPORT) => return Err(Errno::ENOPROTOOPT),
            (SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE | SO_RCVBUF | SO_SNDBUF | SO_RCVTIMEO | SO_SNDTIMEO | SO_BINDTODEVICE)
            | (IPPROTO_IP, IP_TOS | IP_TTL) => {}
            (IPPROTO_TCP, TCP_NODELAY | TCP_MAXSEG | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT) if stream => {}
            (IPPROTO_TCP, _) if !stream => return Err(Errno::EOPNOTSUPP),
            _ => return Err(Errno::ENOPROTOOPT),
        }
        if !matches!(name, SO_RCVTIMEO | SO_SNDTIMEO | SO_BINDTODEVICE) || level != SOL_SOCKET {
            int(value)?;
        }
        let e = self.ent_mut(i);
        e.kept.retain(|k| (k.0, k.1) != (level, name));
        if e.kept.len() < KEPT {
            e.kept.push((level, name, value.iter().copied().take(64).collect()));
        }
        Ok(())
    }

    pub fn sk_getsockopt(&mut self, owner: usize, s: Socket, level: i32, name: i32, value: &mut [u8]) -> SockResult<usize> {
        let i = self.idx(owner, s)?;
        let e = self.ent(i);
        let v: i32 = match (level, name) {
            (SOL_SOCKET, SO_TYPE) => e.ty,
            (SOL_SOCKET, SO_ERROR) => self.ent_mut(i).err.take().map_or(0, |e| e.0),
            (SOL_SOCKET, SO_ACCEPTCONN) => matches!(e.st, St::Listen(_)) as i32,
            (SOL_SOCKET, SO_PROTOCOL) => e.proto,
            (SOL_SOCKET, SO_DOMAIN) => AF_INET,
            (SOL_SOCKET, SO_BROADCAST) => e.broadcast as i32,
            (IPPROTO_TCP, TCP_MAXSEG) if e.ty == SOCK_STREAM => match e.st {
                St::Conn(h, _) => self.tcp.mss(h) as i32,
                _ => 536,
            },
            _ => {
                if let Some(k) = e.kept.iter().find(|k| (k.0, k.1) == (level, name)) {
                    let n = k.2.len().min(value.len());
                    value[..n].copy_from_slice(&k.2[..n]);
                    return Ok(n);
                }
                match (level, name) {
                    (SOL_SOCKET, SO_RCVBUF) => 32 * 1024,
                    (SOL_SOCKET, SO_SNDBUF) => 64 * 1024,
                    (IPPROTO_IP, IP_TTL) => 64,
                    (SOL_SOCKET, SO_LINGER | SO_RCVTIMEO | SO_SNDTIMEO) => {
                        let n = value.len().min(if name == SO_LINGER { 8 } else { 16 });
                        value[..n].fill(0);
                        return Ok(n);
                    }
                    (SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE) | (IPPROTO_IP, IP_TOS) => 0,
                    (IPPROTO_TCP, TCP_NODELAY | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT) if e.ty == SOCK_STREAM => 0,
                    _ => return Err(Errno::ENOPROTOOPT),
                }
            }
        };
        let b = v.to_ne_bytes();
        let n = value.len().min(4);
        value[..n].copy_from_slice(&b[..n]);
        Ok(n)
    }

    pub fn sk_ioctl(&mut self, owner: usize, s: Socket, request: u32, arg: u64) -> SockResult<u64> {
        let i = self.idx(owner, s)?;
        match request {
            FIONBIO => {
                let e = self.ent_mut(i);
                e.flags = if arg != 0 { e.flags | SOCK_NONBLOCK } else { e.flags & !SOCK_NONBLOCK };
                Ok(0)
            }
            FIONREAD | SIOCOUTQ => {
                let out = request == SIOCOUTQ;
                Ok(match self.ent(i).st {
                    St::Conn(h, _) => {
                        let (rx, tx) = self.tcp.queued(h);
                        if out { tx } else { rx }
                    }
                    St::Listen(_) => return Err(Errno::EINVAL),
                    St::Dgram(Some(id)) if !out => self.udp.iter().find(|u| u.id == id).and_then(|u| u.rx.front()).map_or(0, |d| d.1.len()),
                    St::Raw(id) if !out => self.raw.iter().find(|r| r.id == id).and_then(|r| r.rx.front()).map_or(0, |d| 20 + d.2.len()),
                    _ => 0,
                } as u64)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    pub fn sk_poll(&self, owner: usize, s: Socket) -> SockResult<(u32, u64)> {
        let i = self.idx(owner, s)?;
        Ok((self.mask(i), self.ent(i).seq))
    }

    // ---------------------------------------------------------------- epoll

    fn ep(&mut self, owner: usize, ep: Epoll) -> SockResult<usize> {
        let i = find(&self.sk.epolls, ep.to_raw()).ok_or(Errno::EBADF)?;
        if self.sk.epolls[i].it.as_ref().unwrap().0 != owner {
            return Err(Errno::EBADF);
        }
        Ok(i)
    }

    pub fn sk_epoll_create(&mut self, owner: usize) -> SockResult<Epoll> {
        Ok(Epoll::from_raw(put(&mut self.sk.epolls, (owner, EpollSet::new()))))
    }

    pub fn sk_epoll_ctl(&mut self, owner: usize, ep: Epoll, op: i32, s: Socket, events: u32, data: u64) -> SockResult<()> {
        let e = self.ep(owner, ep)?;
        let now = self.sk_poll(owner, s)?.0;
        self.sk.epolls[e].it.as_mut().unwrap().1.ctl(op, s.to_raw(), events, data, now)
    }

    pub fn sk_epoll_wait(&mut self, owner: usize, ep: Epoll, out: &mut [EpollEvent]) -> SockResult<usize> {
        let e = self.ep(owner, ep)?;
        let mut set = core::mem::take(&mut self.sk.epolls[e].it.as_mut().unwrap().1);
        let n = set.wait(out, |raw| self.sk_poll(owner, Socket::from_raw(raw)).ok().map(|p| p.0));
        self.sk.epolls[e].it.as_mut().unwrap().1 = set;
        Ok(n)
    }

    pub fn sk_epoll_close(&mut self, owner: usize, ep: Epoll) -> SockResult<()> {
        let e = self.ep(owner, ep)?;
        self.sk.epolls[e].it = None;
        self.sk.epolls[e].generation = self.sk.epolls[e].generation.wrapping_add(1);
        Ok(())
    }

    /// Everything `owner` holds goes (it was stopped or crashed).
    pub(crate) fn sk_release(&mut self, owner: usize, link: &mut dyn Link) {
        for i in 0..self.sk.socks.len() {
            if self.sk.socks[i].it.as_ref().is_some_and(|e| e.owner == owner) {
                let s = self.sock_of(i);
                self.ent_mut(i).linger0 = true;
                let _ = self.sk_close(owner, link, s);
            }
        }
        for e in self.sk.epolls.iter_mut() {
            if e.it.as_ref().is_some_and(|x| x.0 == owner) {
                e.it = None;
                e.generation = e.generation.wrapping_add(1);
            }
        }
    }
}
