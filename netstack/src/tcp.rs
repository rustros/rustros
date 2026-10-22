//! A small TCP: passive and active open, in-order receive, go-back-N retransmit.
//!
//! Applications poll it: [`Tcp::accept`] new connections or [`Tcp::connect`]
//! out, [`Tcp::recv`] / [`Tcp::send`] data and [`Tcp::close`] when done.

use alloc::vec::Vec;

use crate::iface::{Ifaces, IpPkt, PROTO_TCP};
use crate::Link;
use rustros_util::wire::{Ip, be16, be32, checksum, pseudo};

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const RX_CAP: usize = 32 * 1024;
const TX_CAP: usize = 64 * 1024;
const RTO_INIT: u64 = 1000;
const RTO_MAX: u64 = 16_000;
const MAX_RETRIES: u32 = 8;
/// SYN retransmissions before an outgoing connect gives up (~31 s).
const SYN_RETRIES: u32 = 5;
const TIME_WAIT_MS: u64 = 2000;
const FIN_WAIT2_MS: u64 = 60_000;
/// Connections per listening port that the application has not accepted yet.
const BACKLOG: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Identifies a connection; stale handles never alias a newer connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handle {
    idx: usize,
    generation: u32,
}

impl Handle {
    pub(crate) fn to_raw(self) -> u64 {
        (self.idx as u64) << 32 | self.generation as u64
    }
    pub(crate) fn from_raw(raw: u64) -> Handle {
        Handle { idx: (raw >> 32) as usize, generation: raw as u32 }
    }
}

pub struct Sock {
    pub state: State,
    /// our address: replies come from it (and go out of its WAN)
    pub lip: Ip,
    pub lport: u16,
    pub rip: Ip,
    pub rport: u16,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number ever sent (snd_nxt goes back on retransmit).
    snd_max: u32,
    snd_wnd: u32,
    rcv_nxt: u32,
    /// Bytes starting at `snd_una`: sent-but-unacked, then unsent.
    tx: Vec<u8>,
    rx: Vec<u8>,
    fin_queued: bool,
    rto: u64,
    rtx_at: u64,
    retries: u32,
    deadline: u64,
    mss: usize,
    accepted: bool,
    /// Application that accepted this connection.
    pub owner: usize,
    /// The application has closed its handle; the connection may still be
    /// finishing its FIN handshake.
    pub released: bool,
}

struct Slot {
    generation: u32,
    sock: Option<Sock>,
}

pub struct Tcp {
    slots: Vec<Slot>,
    listening: Vec<u16>,
    max_conns: usize,
}

/// Our MSS: what fits in one IP packet on the interface towards `rip`.
fn our_mss(iface: &Ifaces, rip: Ip) -> usize {
    iface.mtu_for(rip).saturating_sub(40).max(64)
}

/// MSS from a TCP options block (536 if absent), capped at `max`.
fn parse_mss(mut o: &[u8], max: usize) -> usize {
    let mut mss = 536;
    while let [kind, rest @ ..] = o {
        match kind {
            0 => break,
            1 => o = rest,
            _ => {
                let Some(&l) = rest.first() else { break };
                let l = l as usize;
                if l < 2 || l > o.len() {
                    break;
                }
                if *kind == 2 && l == 4 {
                    mss = be16(o, 2) as usize;
                }
                o = &o[l..];
            }
        }
    }
    mss.clamp(64, max)
}

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn le(a: u32, b: u32) -> bool {
    !lt(b, a)
}

#[allow(clippy::too_many_arguments)]
fn emit(iface: &mut Ifaces, link: &mut dyn Link, lip: Ip, lport: u16, rip: Ip, rport: u16, seq: u32, ack: u32, flags: u8, wnd: u16, data: &[u8]) {
    let mss = our_mss(iface, rip) as u16;
    let opt: &[u8] = if flags & SYN != 0 { &[2, 4, (mss >> 8) as u8, mss as u8] } else { &[] };
    let hl = 20 + opt.len();
    let mut s = Vec::with_capacity(hl + data.len());
    s.extend_from_slice(&lport.to_be_bytes());
    s.extend_from_slice(&rport.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push(((hl / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&wnd.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(opt);
    s.extend_from_slice(data);
    let c = checksum(&s, pseudo(iface.src_or(lip, rip), rip, PROTO_TCP, s.len()));
    s[16..18].copy_from_slice(&c.to_be_bytes());
    iface.send_ip_from(link, lip, rip, PROTO_TCP, &s);
}

impl Sock {
    fn wnd(&self) -> u16 {
        (RX_CAP - self.rx.len()).min(0xFFFF) as u16
    }

    fn seg(&self, iface: &mut Ifaces, link: &mut dyn Link, seq: u32, flags: u8, data: &[u8]) {
        emit(iface, link, self.lip, self.lport, self.rip, self.rport, seq, self.rcv_nxt, flags, self.wnd(), data);
    }

    fn syn_ack(&self, iface: &mut Ifaces, link: &mut dyn Link) {
        self.seg(iface, link, self.snd_una, SYN | ACK, &[]);
    }

    fn syn(&self, iface: &mut Ifaces, link: &mut dyn Link) {
        emit(iface, link, self.lip, self.lport, self.rip, self.rport, self.snd_una, 0, SYN, self.wnd(), &[]);
    }

    /// Data bytes sent (in the current pass) but not yet acknowledged.
    fn in_flight(&self) -> usize {
        (self.snd_nxt.wrapping_sub(self.snd_una) as usize).min(self.tx.len())
    }

    /// Our FIN has been sent in the current pass.
    fn fin_sent(&self) -> bool {
        self.fin_queued && self.snd_nxt.wrapping_sub(self.snd_una) as usize == self.tx.len() + 1
    }

    fn advance(&mut self, n: usize) {
        self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
        if lt(self.snd_max, self.snd_nxt) {
            self.snd_max = self.snd_nxt;
        }
    }

    /// Send whatever the window allows, then a FIN if one is queued.
    fn output(&mut self, iface: &mut Ifaces, link: &mut dyn Link) {
        if matches!(self.state, State::SynRcvd | State::SynSent) {
            return; // data and FIN wait until the handshake is done
        }
        loop {
            let flight = self.in_flight();
            let unsent = self.tx.len() - flight;
            let wnd = self.snd_wnd as usize;
            if unsent == 0 || flight >= wnd {
                break;
            }
            let n = unsent.min(self.mss).min(wnd - flight);
            let seq = self.snd_nxt;
            self.seg(iface, link, seq, ACK | PSH, &self.tx[flight..flight + n]);
            self.advance(n);
        }
        // once our FIN is acknowledged (FIN-WAIT-2, TIME-WAIT) it is never
        // sent again: `fin_sent` only sees one still in flight, and a new FIN
        // one further on would be taken by the peer and answered, for ever
        let fin_acked = matches!(self.state, State::FinWait2 | State::TimeWait);
        if self.fin_queued && !fin_acked && !self.fin_sent() && self.in_flight() == self.tx.len() {
            self.seg(iface, link, self.snd_nxt, FIN | ACK, &[]);
            self.advance(1);
            self.state = match self.state {
                State::Established => State::FinWait1,
                State::CloseWait => State::LastAck,
                s => s,
            };
        }
        let waiting = self.snd_una != self.snd_max || self.in_flight() < self.tx.len();
        if waiting && self.rtx_at == 0 {
            self.rtx_at = link.now_ms() + self.rto;
        }
    }
}

impl Tcp {
    pub fn new(max_conns: usize) -> Tcp {
        Tcp { slots: Vec::new(), listening: Vec::new(), max_conns }
    }

    pub fn listen(&mut self, port: u16) {
        if !self.listening.contains(&port) {
            self.listening.push(port);
        }
    }

    /// Stop listening and reset connections nobody has accepted yet.
    pub fn unlisten(&mut self, iface: &mut Ifaces, link: &mut dyn Link, port: u16) {
        self.listening.retain(|&p| p != port);
        for idx in 0..self.slots.len() {
            let generation = self.slots[idx].generation;
            if self.slots[idx].sock.as_ref().is_some_and(|s| s.lport == port && !s.accepted) {
                self.abort(iface, link, Handle { idx, generation });
            }
        }
    }

    /// Connections accepted or opened by `owner`.
    pub fn owned_by(&self, owner: usize) -> Vec<Handle> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sock.as_ref().is_some_and(|s| s.owner == owner && s.accepted))
            .map(|(idx, s)| Handle { idx, generation: s.generation })
            .collect()
    }

    pub fn is_listening(&self, port: u16) -> bool {
        self.listening.contains(&port)
    }

    fn get(&self, h: Handle) -> Option<&Sock> {
        let s = self.slots.get(h.idx)?;
        if s.generation != h.generation { None } else { s.sock.as_ref() }
    }

    fn get_mut(&mut self, h: Handle) -> Option<&mut Sock> {
        let s = self.slots.get_mut(h.idx)?;
        if s.generation != h.generation { None } else { s.sock.as_mut() }
    }

    fn free(&mut self, idx: usize) {
        self.slots[idx].sock = None;
        self.slots[idx].generation = self.slots[idx].generation.wrapping_add(1);
    }

    pub fn sock(&self, h: Handle) -> Option<&Sock> {
        self.get(h)
    }

    pub fn connections(&self) -> impl Iterator<Item = &Sock> {
        self.slots.iter().filter_map(|s| s.sock.as_ref())
    }

    /// A newly established connection on `port` the app has not seen yet.
    pub fn accept(&mut self, port: u16, owner: usize) -> Option<Handle> {
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if let Some(s) = slot.sock.as_mut() {
                if !s.accepted && s.lport == port && s.state != State::SynRcvd {
                    s.accepted = true;
                    s.owner = owner;
                    return Some(Handle { idx, generation: slot.generation });
                }
            }
        }
        None
    }

    /// Active open: send a SYN from `lport` to `rip:rport`. Data may be
    /// written right away; it goes out once the connection is established.
    /// `lip`: our address to connect from (0: the one towards `rip`).
    pub fn connect(&mut self, iface: &mut Ifaces, link: &mut dyn Link, lip: Ip, rip: Ip, rport: u16, lport: u16, owner: usize) -> Option<Handle> {
        if self.slots.iter().filter(|s| s.sock.is_some()).count() >= self.max_conns {
            return None;
        }
        let iss = link.random() as u32;
        let s = Sock {
            state: State::SynSent,
            lip: iface.src_or(lip, rip),
            lport,
            rip,
            rport,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_max: iss.wrapping_add(1),
            snd_wnd: 0,
            rcv_nxt: 0,
            tx: Vec::new(),
            rx: Vec::new(),
            fin_queued: false,
            rto: RTO_INIT,
            rtx_at: link.now_ms() + RTO_INIT,
            retries: 0,
            deadline: 0,
            mss: 536,
            accepted: true,
            owner,
            released: false,
        };
        s.syn(iface, link);
        let idx = self.insert(s);
        Some(Handle { idx, generation: self.slots[idx].generation })
    }

    fn insert(&mut self, s: Sock) -> usize {
        match self.slots.iter().position(|s| s.sock.is_none()) {
            Some(i) => {
                self.slots[i].sock = Some(s);
                i
            }
            None => {
                self.slots.push(Slot { generation: 0, sock: Some(s) });
                self.slots.len() - 1
            }
        }
    }

    /// Local ports in use by any connection.
    pub fn port_in_use(&self, port: u16) -> bool {
        self.listening.contains(&port) || self.connections().any(|s| s.lport == port)
    }

    /// Handshake finished (false while an outgoing connect is pending).
    pub fn is_established(&self, h: Handle) -> Option<bool> {
        self.get(h).map(|s| s.state != State::SynSent)
    }

    /// True once the connection is gone (closed, reset or timed out).
    pub fn is_closed(&self, h: Handle) -> bool {
        self.get(h).is_none()
    }

    /// The peer has sent FIN and all its data has been read.
    pub fn peer_done(&self, h: Handle) -> bool {
        self.get(h).is_none_or(|s| {
            s.rx.is_empty() && matches!(s.state, State::CloseWait | State::LastAck | State::Closing | State::TimeWait)
        })
    }

    /// Received data, not yet consumed.
    pub fn peek(&self, h: Handle) -> &[u8] {
        self.get(h).map_or(&[], |s| &s.rx)
    }

    /// Drop `n` bytes of received data; may send a window update.
    pub fn consume(&mut self, iface: &mut Ifaces, link: &mut dyn Link, h: Handle, n: usize) {
        let Some(s) = self.get_mut(h) else { return };
        let before = s.wnd() as usize;
        s.rx.drain(..n.min(s.rx.len()));
        if before < RX_CAP / 2 && s.wnd() as usize >= RX_CAP / 2 {
            s.seg(iface, link, s.snd_nxt, ACK, &[]);
        }
    }

    pub fn recv(&mut self, iface: &mut Ifaces, link: &mut dyn Link, h: Handle, buf: &mut [u8]) -> usize {
        let data = self.peek(h);
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.consume(iface, link, h, n);
        n
    }

    /// Free space in the send buffer.
    pub fn send_space(&self, h: Handle) -> usize {
        self.get(h).map_or(0, |s| if s.fin_queued { 0 } else { TX_CAP - s.tx.len() })
    }

    /// Queue data for sending; returns how many bytes were accepted.
    pub fn send(&mut self, iface: &mut Ifaces, link: &mut dyn Link, h: Handle, data: &[u8]) -> usize {
        let space = self.send_space(h);
        let Some(s) = self.get_mut(h) else { return 0 };
        let n = data.len().min(space);
        s.tx.extend_from_slice(&data[..n]);
        s.output(iface, link);
        n
    }

    /// Graceful close: FIN after all queued data.
    pub fn close(&mut self, iface: &mut Ifaces, link: &mut dyn Link, h: Handle) {
        let Some(s) = self.get_mut(h) else { return };
        s.released = true;
        if s.state == State::SynRcvd {
            s.seg(iface, link, s.snd_nxt, RST, &[]);
            self.free(h.idx);
            return;
        }
        s.fin_queued = true;
        s.output(iface, link);
    }

    /// Hard close with RST.
    pub fn abort(&mut self, iface: &mut Ifaces, link: &mut dyn Link, h: Handle) {
        let Some(s) = self.get_mut(h) else { return };
        s.seg(iface, link, s.snd_nxt, RST | ACK, &[]);
        self.free(h.idx);
    }

    fn reset_reply(iface: &mut Ifaces, link: &mut dyn Link, pkt: &IpPkt, seg: &[u8], dlen: usize) {
        let (sport, dport, seq, ack, flags) = (be16(seg, 0), be16(seg, 2), be32(seg, 4), be32(seg, 8), seg[13]);
        if flags & ACK != 0 {
            emit(iface, link, pkt.dst, dport, pkt.src, sport, ack, 0, RST, 0, &[]);
        } else {
            let len = dlen as u32 + (flags & SYN != 0) as u32 + (flags & FIN != 0) as u32;
            emit(iface, link, pkt.dst, dport, pkt.src, sport, 0, seq.wrapping_add(len), RST | ACK, 0, &[]);
        }
    }

    /// `open`: new connections and resets for unknown ones (an interface's
    /// own address); otherwise only existing connections (an extra address
    /// a connection was made from).
    pub fn input(&mut self, iface: &mut Ifaces, link: &mut dyn Link, pkt: &IpPkt, open: bool) {
        let seg = pkt.payload;
        if seg.len() < 20 || checksum(seg, pseudo(pkt.src, pkt.dst, PROTO_TCP, seg.len())) != 0 {
            return;
        }
        let hl = (seg[12] >> 4) as usize * 4;
        if hl < 20 || hl > seg.len() {
            return;
        }
        let (sport, dport) = (be16(seg, 0), be16(seg, 2));
        let (seq, ack, flags, wnd) = (be32(seg, 4), be32(seg, 8), seg[13], be16(seg, 14) as u32);
        let data = &seg[hl..];
        let now = link.now_ms();

        let found = self.slots.iter().position(|s| {
            s.sock.as_ref().is_some_and(|s| s.lport == dport && s.rport == sport && s.rip == pkt.src && s.lip == pkt.dst)
        });
        let Some(idx) = found else {
            if flags & RST != 0 || !open {
                return;
            }
            let live = self.slots.iter().filter(|s| s.sock.is_some()).count();
            let waiting = self.connections().filter(|s| s.lport == dport && !s.accepted).count();
            if flags & (SYN | ACK) == SYN && self.listening.contains(&dport) && (live >= self.max_conns || waiting >= BACKLOG) {
                // full: dropped, not refused, so the client tries again (as Linux does)
                return;
            }
            if flags & (SYN | ACK) == SYN && self.listening.contains(&dport) {
                let iss = link.random() as u32;
                let s = Sock {
                    state: State::SynRcvd,
                    lip: pkt.dst,
                    lport: dport,
                    rip: pkt.src,
                    rport: sport,
                    snd_una: iss,
                    snd_nxt: iss.wrapping_add(1),
                    snd_max: iss.wrapping_add(1),
                    snd_wnd: wnd,
                    rcv_nxt: seq.wrapping_add(1),
                    tx: Vec::new(),
                    rx: Vec::new(),
                    fin_queued: false,
                    rto: RTO_INIT,
                    rtx_at: now + RTO_INIT,
                    retries: 0,
                    deadline: 0,
                    mss: parse_mss(&seg[20..hl], our_mss(iface, pkt.src)),
                    accepted: false,
                    owner: usize::MAX,
                    released: false,
                };
                s.syn_ack(iface, link);
                self.insert(s);
            } else {
                Self::reset_reply(iface, link, pkt, seg, data.len());
            }
            return;
        };

        let s = self.slots[idx].sock.as_mut().unwrap();
        if s.state == State::SynSent {
            // only a SYN-ACK for our SYN (or a RST refusing it) is acceptable
            if flags & ACK != 0 && ack != s.snd_nxt {
                if flags & RST == 0 {
                    emit(iface, link, pkt.dst, dport, pkt.src, sport, ack, 0, RST, 0, &[]);
                }
                return;
            }
            if flags & RST != 0 {
                if flags & ACK != 0 {
                    self.free(idx); // connection refused
                }
                return;
            }
            if flags & (SYN | ACK) != SYN | ACK {
                return; // simultaneous open is not supported
            }
            s.state = State::Established;
            s.rcv_nxt = seq.wrapping_add(1);
            s.snd_una = ack;
            s.snd_wnd = wnd;
            s.mss = parse_mss(&seg[20..hl], our_mss(iface, pkt.src));
            s.rtx_at = 0;
            s.rto = RTO_INIT;
            s.retries = 0;
            s.seg(iface, link, s.snd_nxt, ACK, &[]);
            s.output(iface, link);
            return;
        }
        if flags & RST != 0 {
            let in_wnd = seq.wrapping_sub(s.rcv_nxt) <= s.wnd() as u32;
            if in_wnd {
                self.free(idx);
            }
            return;
        }
        if flags & SYN != 0 {
            if s.state == State::SynRcvd && seq.wrapping_add(1) == s.rcv_nxt {
                s.syn_ack(iface, link); // our SYN-ACK was lost
            } else {
                s.seg(iface, link, s.snd_nxt, ACK, &[]);
            }
            return;
        }
        if flags & ACK == 0 {
            return;
        }

        if s.state == State::SynRcvd {
            if ack != s.snd_nxt {
                emit(iface, link, pkt.dst, dport, pkt.src, sport, ack, 0, RST, 0, &[]);
                return;
            }
            s.state = State::Established;
            s.snd_una = ack;
            s.rtx_at = 0;
            s.rto = RTO_INIT;
            s.retries = 0;
        } else if lt(s.snd_una, ack) && le(ack, s.snd_max) {
            let n = ack.wrapping_sub(s.snd_una) as usize;
            let fin_acked = s.fin_queued && n == s.tx.len() + 1;
            s.tx.drain(..n.min(s.tx.len()));
            s.snd_una = ack;
            if lt(s.snd_nxt, ack) {
                s.snd_nxt = ack;
            }
            s.retries = 0;
            s.rto = RTO_INIT;
            s.rtx_at = if s.snd_una != s.snd_max { now + s.rto } else { 0 };
            if fin_acked {
                match s.state {
                    State::FinWait1 => {
                        s.state = State::FinWait2;
                        s.deadline = now + FIN_WAIT2_MS;
                    }
                    State::Closing => {
                        s.state = State::TimeWait;
                        s.deadline = now + TIME_WAIT_MS;
                    }
                    State::LastAck => {
                        self.free(idx);
                        return;
                    }
                    _ => {}
                }
            }
        }
        s.snd_wnd = wnd;

        let mut need_ack = false;
        if !data.is_empty() && matches!(s.state, State::Established | State::FinWait1 | State::FinWait2) {
            need_ack = true;
            let end = seq.wrapping_add(data.len() as u32);
            if le(seq, s.rcv_nxt) && lt(s.rcv_nxt, end) {
                let part = &data[s.rcv_nxt.wrapping_sub(seq) as usize..];
                let take = part.len().min(RX_CAP - s.rx.len());
                s.rx.extend_from_slice(&part[..take]);
                s.rcv_nxt = s.rcv_nxt.wrapping_add(take as u32);
            }
        }
        if flags & FIN != 0 {
            let fin_seq = seq.wrapping_add(data.len() as u32);
            if fin_seq == s.rcv_nxt && s.state != State::SynRcvd {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                s.state = match s.state {
                    State::Established => State::CloseWait,
                    State::FinWait1 if s.snd_una == s.snd_max => State::TimeWait,
                    State::FinWait1 => State::Closing,
                    State::FinWait2 => State::TimeWait,
                    st => st,
                };
                if s.state == State::TimeWait {
                    s.deadline = now + TIME_WAIT_MS;
                }
            }
            need_ack = true;
        }
        if need_ack {
            s.seg(iface, link, s.snd_nxt, ACK, &[]);
        }
        s.output(iface, link);
    }

    /// Retransmissions and timeouts; call regularly.
    pub fn poll(&mut self, iface: &mut Ifaces, link: &mut dyn Link) {
        let now = link.now_ms();
        for idx in 0..self.slots.len() {
            let Some(s) = self.slots[idx].sock.as_mut() else { continue };
            if matches!(s.state, State::TimeWait | State::FinWait2) && now >= s.deadline {
                self.free(idx);
                continue;
            }
            if s.rtx_at == 0 || now < s.rtx_at {
                continue;
            }
            s.retries += 1;
            if s.state == State::SynSent && s.retries > SYN_RETRIES {
                self.free(idx); // connect timed out
                continue;
            }
            if s.retries > MAX_RETRIES {
                s.seg(iface, link, s.snd_nxt, RST | ACK, &[]);
                self.free(idx);
                continue;
            }
            s.rto = (s.rto * 2).min(RTO_MAX);
            s.rtx_at = 0;
            if s.state == State::SynRcvd {
                s.syn_ack(iface, link);
                s.rtx_at = now + s.rto;
                continue;
            }
            if s.state == State::SynSent {
                s.syn(iface, link);
                s.rtx_at = now + s.rto;
                continue;
            }
            // go back N; a zero window gets a one-byte probe
            s.snd_nxt = s.snd_una;
            let wnd = s.snd_wnd;
            if wnd == 0 {
                s.snd_wnd = 1;
            }
            s.output(iface, link);
            s.snd_wnd = wnd;
            if s.rtx_at == 0 {
                s.rtx_at = now + s.rto;
            }
        }
    }
}
