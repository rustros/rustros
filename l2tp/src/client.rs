//! The L2TP client side (LAC): dial out to an L2TP server, bring up PPP
//! (LCP, PAP or CHAP-MD5, IPCP) and carry IPv4 through the tunnel. Like the
//! server, it only builds and parses packets; the caller moves them.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

const SCCCN: u16 = 3;
const HELLO: u16 = 6;
const PROTO_CHAP: u16 = 0xc223;
const AVP_BEARER_CAPS: u16 = 4;
const AVP_RECEIVE_WINDOW: u16 = 10;
const AVP_CALL_SERIAL: u16 = 15;
const AVP_FRAMING_TYPE: u16 = 19;
const AVP_TX_SPEED: u16 = 24;

/// Control messages are resent this often, this many times.
const RESEND_MS: u64 = 1000;
const RESENDS: u32 = 5;
/// A Hello after this long without hearing from the server.
const HELLO_MS: u64 = 60_000;
/// PPP must be up this long after the session is.
const PPP_MS: u64 = 30_000;

pub struct ClientConfig {
    pub user: String,
    pub password: String,
    pub host_name: String,
    /// our MRU (the tunnel's MTU)
    pub mru: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// PPP is up: our address, the server's, its DNS servers.
    Up { ip: Ip, peer: Ip, dns: [Ip; 2] },
    /// The tunnel is gone (and why); start again later.
    Down(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Auth {
    None,
    Pap,
    Chap,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// SCCRQ sent
    Tunnel,
    /// ICRQ sent
    Session,
    /// PPP negotiating
    Ppp,
    Up,
    Down,
}

pub struct Client {
    cfg: ClientConfig,
    state: State,
    /// our tunnel and session ids, the server's
    tid: u16,
    sid: u16,
    peer_tid: u16,
    peer_sid: u16,
    ns: u16,
    nr: u16,
    /// control messages not acknowledged yet: (Ns, message, last sent, sends)
    unacked: Vec<(u16, Vec<u8>, u64, u32)>,
    last_rx: u64,
    since: u64,
    lcp_id: u8,
    our_lcp_acked: bool,
    peer_lcp_acked: bool,
    auth: Auth,
    authed: bool,
    auth_sent: bool,
    ipcp_id: u8,
    ip: Ip,
    peer_ip: Ip,
    dns: [Ip; 2],
    /// IPCP options the server rejected (DNS)
    no_dns: bool,
    ipcp_acked: bool,
    peer_ipcp_acked: bool,
    naks: u32,
}

impl Client {
    /// A client with tunnel and session ids `tid` / `sid` (random, nonzero).
    pub fn new(cfg: ClientConfig, tid: u16, sid: u16) -> Client {
        Client {
            cfg,
            state: State::Down,
            tid: tid.max(1),
            sid: sid.max(1),
            peer_tid: 0,
            peer_sid: 0,
            ns: 0,
            nr: 0,
            unacked: Vec::new(),
            last_rx: 0,
            since: 0,
            lcp_id: 0,
            our_lcp_acked: false,
            peer_lcp_acked: false,
            auth: Auth::None,
            authed: false,
            auth_sent: false,
            ipcp_id: 0,
            ip: 0,
            peer_ip: 0,
            dns: [0; 2],
            no_dns: false,
            ipcp_acked: false,
            peer_ipcp_acked: false,
            naks: 0,
        }
    }

    pub fn is_up(&self) -> bool {
        self.state == State::Up
    }

    pub fn is_down(&self) -> bool {
        self.state == State::Down
    }

    /// Our address in the tunnel (0 until PPP is up).
    pub fn ip(&self) -> Ip {
        if self.is_up() { self.ip } else { 0 }
    }

    /// Where an IPv4 packet goes into the tunnel: the data header to put in front.
    pub fn data_header(&self) -> [u8; DATA_HEADER] {
        data_header(&Route { peer: (0, 0), tunnel: self.peer_tid, session: self.peer_sid })
    }

    /// Dial: the first control message. Any earlier tunnel is forgotten.
    pub fn start(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        let (tid, sid) = (self.tid.wrapping_add(1).max(1), self.sid.wrapping_add(1).max(1));
        let cfg = core::mem::replace(&mut self.cfg, ClientConfig { user: String::new(), password: String::new(), host_name: String::new(), mru: 0 });
        *self = Client::new(cfg, tid, sid);
        self.state = State::Tunnel;
        self.since = now;
        self.last_rx = now;
        let mut a = Vec::new();
        avp(&mut a, AVP_MESSAGE_TYPE, &SCCRQ.to_be_bytes());
        avp(&mut a, AVP_PROTOCOL_VERSION, &[1, 0]);
        avp(&mut a, AVP_HOST_NAME, self.cfg.host_name.as_bytes());
        avp(&mut a, AVP_FRAMING_CAPS, &3u32.to_be_bytes());
        avp(&mut a, AVP_BEARER_CAPS, &3u32.to_be_bytes());
        avp(&mut a, AVP_ASSIGNED_TUNNEL_ID, &self.tid.to_be_bytes());
        avp(&mut a, AVP_RECEIVE_WINDOW, &4u16.to_be_bytes());
        self.control(now, 0, &a, out);
    }

    /// Stop: tell the server and forget the tunnel.
    pub fn stop(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        if self.state != State::Down && self.peer_tid != 0 {
            let mut a = Vec::new();
            avp(&mut a, AVP_MESSAGE_TYPE, &STOPCCN.to_be_bytes());
            avp(&mut a, AVP_ASSIGNED_TUNNEL_ID, &self.tid.to_be_bytes());
            avp(&mut a, 1, &[0, 1]); // Result Code: general request to clear
            self.control(now, 0, &a, out);
        }
        self.state = State::Down;
    }

    fn control(&mut self, now: u64, session: u16, avps: &[u8], out: &mut Vec<Vec<u8>>) {
        let len = 12 + avps.len();
        let mut p = Vec::with_capacity(len);
        p.extend(0xC802u16.to_be_bytes());
        p.extend((len as u16).to_be_bytes());
        p.extend(self.peer_tid.to_be_bytes());
        p.extend(session.to_be_bytes());
        p.extend(self.ns.to_be_bytes());
        p.extend(self.nr.to_be_bytes());
        p.extend_from_slice(avps);
        if !avps.is_empty() {
            self.unacked.push((self.ns, p.clone(), now, 1));
            self.ns = self.ns.wrapping_add(1);
        }
        out.push(p);
    }

    fn ppp(&self, proto: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = self.data_header().to_vec();
        p[8..10].copy_from_slice(&proto.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn down(&mut self, why: &'static str, events: &mut Vec<ClientEvent>) {
        if self.state != State::Down {
            self.state = State::Down;
            events.push(ClientEvent::Down(why));
        }
    }

    /// If `pkt` (an L2TP packet from the server) carries an IPv4 packet for
    /// us, where it starts. Everything else goes to `handle`.
    pub fn data(&self, pkt: &[u8]) -> Option<usize> {
        let h = parse_header(pkt)?;
        if h.control || !self.is_up() || h.tunnel_id != self.tid || h.session_id != self.sid {
            return None;
        }
        let (proto, off) = ppp_proto(&pkt[h.payload..])?;
        (proto == PROTO_IP).then_some(h.payload + off)
    }

    /// A packet from the server (control, or PPP negotiation).
    pub fn handle(&mut self, now: u64, pkt: &[u8], out: &mut Vec<Vec<u8>>, events: &mut Vec<ClientEvent>) {
        let Some(h) = parse_header(pkt) else { return };
        if self.state == State::Down || h.tunnel_id != self.tid {
            return;
        }
        self.last_rx = now;
        if !h.control {
            if h.session_id == self.sid {
                self.ppp_control(now, &pkt[h.payload..], out, events);
            }
            return;
        }
        // acknowledgements: Nr says what the server got
        if let Some(nr) = be16(pkt, 10) {
            self.unacked.retain(|(ns, ..)| (nr.wrapping_sub(*ns) as i16) <= 0);
        }
        let avps = parse_avps(&pkt[h.payload..]);
        let get16 = |ty| avps.iter().find(|a| a.0 == ty).and_then(|a| be16(a.1, 0));
        let Some(msg) = get16(AVP_MESSAGE_TYPE) else { return }; // ZLB
        if h.ns != self.nr {
            self.control(now, 0, &[], out); // a repeat: acknowledge again
            return;
        }
        self.nr = self.nr.wrapping_add(1);
        let mut a = Vec::new();
        match msg {
            SCCRP if self.state == State::Tunnel => {
                self.peer_tid = get16(AVP_ASSIGNED_TUNNEL_ID).unwrap_or(0);
                avp(&mut a, AVP_MESSAGE_TYPE, &SCCCN.to_be_bytes());
                self.control(now, 0, &a, out);
                // and the call
                let mut c = Vec::new();
                avp(&mut c, AVP_MESSAGE_TYPE, &ICRQ.to_be_bytes());
                avp(&mut c, AVP_ASSIGNED_SESSION_ID, &self.sid.to_be_bytes());
                avp(&mut c, AVP_CALL_SERIAL, &(self.sid as u32).to_be_bytes());
                self.control(now, 0, &c, out);
                self.state = State::Session;
            }
            ICRP if self.state == State::Session => {
                self.peer_sid = get16(AVP_ASSIGNED_SESSION_ID).unwrap_or(0);
                avp(&mut a, AVP_MESSAGE_TYPE, &ICCN.to_be_bytes());
                avp(&mut a, AVP_TX_SPEED, &100_000_000u32.to_be_bytes());
                avp(&mut a, AVP_FRAMING_TYPE, &1u32.to_be_bytes());
                self.control(now, self.peer_sid, &a, out);
                self.state = State::Ppp;
                self.since = now;
                self.lcp_id = 1;
                out.push(self.ppp(PROTO_LCP, &self.lcp_request()));
            }
            STOPCCN => {
                self.control(now, 0, &[], out);
                self.down("the server closed the tunnel", events);
            }
            CDN => {
                self.control(now, 0, &[], out);
                self.down("the server closed the call", events);
            }
            _ => self.control(now, 0, &[], out), // Hello and the rest: acknowledge
        }
    }

    fn lcp_request(&self) -> Vec<u8> {
        let mut o = vec![1, 4];
        o.extend(self.cfg.mru.to_be_bytes());
        o.extend([5, 6]);
        o.extend((self.tid as u32 | (self.sid as u32) << 16).to_be_bytes()); // magic number
        cp(1, self.lcp_id, &o)
    }

    fn ipcp_request(&self) -> Vec<u8> {
        let mut o = vec![3, 6];
        o.extend(self.ip.to_be_bytes());
        if !self.no_dns {
            o.extend([129, 6]);
            o.extend(self.dns[0].to_be_bytes());
            o.extend([131, 6]);
            o.extend(self.dns[1].to_be_bytes());
        }
        cp(1, self.ipcp_id, &o)
    }

    /// The server's LCP options: what we accept, what we would rather have.
    fn lcp_answer(&mut self, id: u8, data: &[u8]) -> Vec<u8> {
        let (mut nak, mut rej) = (Vec::new(), Vec::new());
        let mut o = data;
        let mut auth = Auth::None;
        while o.len() >= 2 {
            let (opt, rest) = o.split_at((o[1] as usize).clamp(2, o.len()));
            match opt[0] {
                1 | 2 | 5 | 7 | 8 => {} // MRU, ACCM, magic, PFC, ACFC
                3 if opt.len() >= 4 && opt[2..4] == [0xc0, 0x23] => auth = Auth::Pap,
                3 if opt.len() >= 5 && opt[2..4] == [0xc2, 0x23] && opt[4] == 5 => auth = Auth::Chap,
                // MS-CHAP and the like: ask for CHAP-MD5 instead
                3 => nak.extend([3, 5, 0xc2, 0x23, 5]),
                _ => rej.extend_from_slice(opt),
            }
            o = rest;
        }
        if !rej.is_empty() {
            cp(4, id, &rej)
        } else if !nak.is_empty() {
            self.naks += 1;
            cp(3, id, &nak)
        } else {
            self.auth = auth;
            self.peer_lcp_acked = true;
            cp(2, id, data)
        }
    }

    /// LCP is up both ways: authenticate (or go on to IPCP).
    fn after_lcp(&mut self, out: &mut Vec<Vec<u8>>) {
        if !(self.our_lcp_acked && self.peer_lcp_acked) || self.auth_sent {
            return;
        }
        match self.auth {
            Auth::Pap => {
                self.auth_sent = true;
                let (u, p) = (self.cfg.user.as_bytes(), self.cfg.password.as_bytes());
                let mut d = vec![u.len() as u8];
                d.extend_from_slice(u);
                d.push(p.len() as u8);
                d.extend_from_slice(p);
                out.push(self.ppp(PROTO_PAP, &cp(1, 1, &d)));
            }
            Auth::Chap => {} // wait for the challenge
            Auth::None => {
                self.auth_sent = true;
                self.authed();
                out.push(self.ppp(PROTO_IPCP, &self.ipcp_request()));
            }
        }
    }

    fn authed(&mut self) {
        self.authed = true;
        self.ipcp_id = 1;
    }

    fn maybe_up(&mut self, events: &mut Vec<ClientEvent>) {
        if self.state == State::Ppp && self.ipcp_acked && self.peer_ipcp_acked && self.ip != 0 {
            self.state = State::Up;
            events.push(ClientEvent::Up { ip: self.ip, peer: self.peer_ip, dns: self.dns });
        }
    }

    fn ppp_control(&mut self, _now: u64, frame: &[u8], out: &mut Vec<Vec<u8>>, events: &mut Vec<ClientEvent>) {
        let Some((proto, off)) = ppp_proto(frame) else { return };
        let f = &frame[off..];
        if proto == PROTO_IP {
            return; // the caller's (`data`)
        }
        if !matches!(proto, PROTO_LCP | PROTO_PAP | PROTO_CHAP | PROTO_IPCP) {
            self.lcp_id = self.lcp_id.wrapping_add(1);
            let mut d = proto.to_be_bytes().to_vec();
            d.extend_from_slice(f);
            out.push(self.ppp(PROTO_LCP, &cp(8, self.lcp_id, &d))); // Protocol-Reject
            return;
        }
        if f.len() < 4 {
            return;
        }
        let (code, id) = (f[0], f[1]);
        let data = &f[4..(u16::from_be_bytes([f[2], f[3]]) as usize).clamp(4, f.len())];
        match (proto, code) {
            (PROTO_LCP, 1) => {
                let r = self.lcp_answer(id, data);
                out.push(self.ppp(PROTO_LCP, &r));
                if self.naks > 5 {
                    self.down("the server wants an authentication we do not speak (PAP or CHAP-MD5 only)", events);
                    return;
                }
                self.after_lcp(out);
            }
            (PROTO_LCP, 2) if id == self.lcp_id => {
                self.our_lcp_acked = true;
                self.after_lcp(out);
            }
            (PROTO_LCP, 3 | 4) => {
                // it does not like our MRU or magic: ask for the bare minimum
                self.lcp_id = self.lcp_id.wrapping_add(1);
                out.push(self.ppp(PROTO_LCP, &cp(1, self.lcp_id, &[])));
            }
            (PROTO_LCP, 5) => {
                out.push(self.ppp(PROTO_LCP, &cp(6, id, &[])));
                self.down("the server ended PPP", events);
            }
            (PROTO_LCP, 9) if data.len() >= 4 => {
                let mut d = (self.tid as u32 | (self.sid as u32) << 16).to_be_bytes().to_vec();
                d.extend_from_slice(&data[4..]);
                out.push(self.ppp(PROTO_LCP, &cp(10, id, &d)));
            }
            (PROTO_PAP, 2) => {
                self.authed();
                out.push(self.ppp(PROTO_IPCP, &self.ipcp_request()));
            }
            (PROTO_PAP, 3) | (PROTO_CHAP, 4) => self.down("wrong user name or password", events),
            (PROTO_CHAP, 1) if !data.is_empty() => {
                // Challenge: MD5(id, secret, challenge)
                let n = data[0] as usize;
                let Some(challenge) = data.get(1..1 + n) else { return };
                let mut m = vec![id];
                m.extend_from_slice(self.cfg.password.as_bytes());
                m.extend_from_slice(challenge);
                let mut d = vec![16];
                d.extend_from_slice(&md5(&m));
                d.extend_from_slice(self.cfg.user.as_bytes());
                self.auth_sent = true;
                out.push(self.ppp(PROTO_CHAP, &cp(2, id, &d)));
            }
            (PROTO_CHAP, 3) if !self.authed => {
                self.authed();
                out.push(self.ppp(PROTO_IPCP, &self.ipcp_request()));
            }
            (PROTO_IPCP, 1) => {
                // the server's request: its address; we accept it
                let mut o = data;
                while o.len() >= 6 {
                    let (opt, rest) = o.split_at((o[1] as usize).clamp(2, o.len()));
                    if opt[0] == 3 && opt.len() == 6 {
                        self.peer_ip = u32::from_be_bytes([opt[2], opt[3], opt[4], opt[5]]);
                    }
                    o = rest;
                }
                out.push(self.ppp(PROTO_IPCP, &cp(2, id, data)));
                self.peer_ipcp_acked = true;
                self.maybe_up(events);
            }
            (PROTO_IPCP, 2) if id == self.ipcp_id => {
                self.ipcp_acked = true;
                self.maybe_up(events);
            }
            (PROTO_IPCP, 3) => {
                // Nak: the address (and DNS) the server gives us
                let mut o = data;
                while o.len() >= 6 {
                    let (opt, rest) = o.split_at((o[1] as usize).clamp(2, o.len()));
                    let v = u32::from_be_bytes([opt[2], opt[3], opt[4], opt[5]]);
                    match opt[0] {
                        3 => self.ip = v,
                        129 => self.dns[0] = v,
                        131 => self.dns[1] = v,
                        _ => {}
                    }
                    o = rest;
                }
                self.ipcp_id = self.ipcp_id.wrapping_add(1);
                out.push(self.ppp(PROTO_IPCP, &self.ipcp_request()));
            }
            (PROTO_IPCP, 4) => {
                self.no_dns = true; // most likely DNS: ask without it
                self.ipcp_id = self.ipcp_id.wrapping_add(1);
                out.push(self.ppp(PROTO_IPCP, &self.ipcp_request()));
            }
            (PROTO_IPCP, 5) => {
                out.push(self.ppp(PROTO_IPCP, &cp(6, id, &[])));
                self.down("the server ended IPCP", events);
            }
            _ => {}
        }
    }

    /// Timers: resend control messages, keep the tunnel alive, give up.
    pub fn tick(&mut self, now: u64, out: &mut Vec<Vec<u8>>, events: &mut Vec<ClientEvent>) {
        if self.state == State::Down {
            return;
        }
        let mut gave_up = false;
        for (_, msg, sent, n) in self.unacked.iter_mut() {
            if now.saturating_sub(*sent) >= RESEND_MS << (*n - 1).min(4) {
                if *n > RESENDS {
                    gave_up = true;
                    break;
                }
                *n += 1;
                *sent = now;
                // the current Nr in the copy we resend
                msg[10..12].copy_from_slice(&self.nr.to_be_bytes());
                out.push(msg.clone());
            }
        }
        if gave_up {
            self.down("no answer from the server", events);
            return;
        }
        if self.state == State::Ppp && now.saturating_sub(self.since) > PPP_MS {
            self.stop(now, out);
            events.push(ClientEvent::Down("PPP did not come up"));
            return;
        }
        if self.state == State::Up && now.saturating_sub(self.last_rx) > HELLO_MS && self.unacked.is_empty() {
            let mut a = Vec::new();
            avp(&mut a, AVP_MESSAGE_TYPE, &HELLO.to_be_bytes());
            self.control(now, 0, &a, out);
            self.last_rx = now; // the Hello's acknowledgement (or its resends) decide
        }
    }
}

/// MD5 (RFC 1321), for CHAP.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16,
        23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Peer = (0x0A00_0202, 1701);

    fn server(pw: &str) -> Server {
        let accounts = vec![Account { user: String::from("ppp1"), password: String::from(pw), egress: None }];
        Server::new(Config { accounts, ..Config::default() })
    }

    fn client(pw: &str) -> Client {
        Client::new(ClientConfig { user: String::from("ppp1"), password: String::from(pw), host_name: String::from("t"), mru: 1400 }, 9, 3)
    }

    /// Let them talk until nothing is left to say; the client's events.
    fn run(c: &mut Client, s: &mut Server, mut to_s: Vec<Vec<u8>>, now: u64) -> Vec<ClientEvent> {
        let mut events = Vec::new();
        for _ in 0..50 {
            let mut to_c = Vec::new();
            let mut sev = Vec::new();
            for p in to_s.drain(..) {
                s.handle(now, PEER, &p, &mut to_c, &mut sev);
            }
            if to_c.is_empty() {
                break;
            }
            for (_, p) in to_c {
                c.handle(now, &p, &mut to_s, &mut events);
            }
        }
        events
    }

    #[test]
    fn md5_vectors() {
        let hex = |b: [u8; 16]| b.iter().map(|x| alloc::format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(md5(&[b'a'; 100])), "36a92cc94a9e0fa21f625f8bfb007adf");
    }

    #[test]
    fn against_our_server() {
        let (mut s, mut c) = (server("s3cr3t-pw"), client("s3cr3t-pw"));
        let mut out = Vec::new();
        c.start(0, &mut out);
        let ev = run(&mut c, &mut s, out, 1);
        assert!(c.is_up(), "{ev:?}");
        assert_eq!(ev, vec![ClientEvent::Up { ip: 0x0A00_0002, peer: 0x0A00_0001, dns: [0x0808_0808, 0x0101_0101] }]);
        // data both ways
        let mut pkt = c.data_header().to_vec();
        let ip_at = pkt.len();
        let mut ipv4 = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
        ipv4.extend(0x0A00_0002u32.to_be_bytes());
        ipv4.extend(0x0808_0808u32.to_be_bytes());
        pkt.extend(&ipv4);
        assert_eq!(s.classify(2, PEER, &pkt), Data::Ip { client: 0x0A00_0002, offset: ip_at });
        let r = s.route(0x0A00_0002).unwrap();
        let mut back = data_header(&r).to_vec();
        back.extend(&ipv4);
        assert_eq!(c.data(&back), Some(DATA_HEADER));
        // nothing to resend once everything was acknowledged
        let (mut o, mut e) = (Vec::new(), Vec::new());
        c.tick(1500, &mut o, &mut e);
        assert!(o.is_empty() && e.is_empty(), "{} resent", o.len());
    }

    #[test]
    fn wrong_password() {
        let (mut s, mut c) = (server("right"), client("wrong"));
        let mut out = Vec::new();
        c.start(0, &mut out);
        let ev = run(&mut c, &mut s, out, 1);
        assert_eq!(ev, vec![ClientEvent::Down("wrong user name or password")]);
        assert!(c.is_down());
    }

    #[test]
    fn no_answer() {
        let mut c = client("x");
        let (mut out, mut ev) = (Vec::new(), Vec::new());
        c.start(0, &mut out);
        let mut t = 0;
        while ev.is_empty() && t < 120_000 {
            t += 500;
            c.tick(t, &mut out, &mut ev);
        }
        assert_eq!(ev, vec![ClientEvent::Down("no answer from the server")]);
        assert!(out.len() > 3, "resent a few times first");
    }

    #[test]
    fn chap_md5() {
        let mut c = client("secret");
        c.state = State::Ppp;
        c.peer_tid = 1;
        c.peer_sid = 1;
        let (mut out, mut ev) = (Vec::new(), Vec::new());
        // the server asks for CHAP-MD5: accepted
        let r = c.lcp_answer(7, &[1, 4, 5, 0xdc, 3, 5, 0xc2, 0x23, 5]);
        assert_eq!(r[0], 2, "Configure-Ack");
        assert_eq!(c.auth, Auth::Chap);
        // a challenge
        let chal = [9u8; 16];
        let mut d = vec![16];
        d.extend(chal);
        d.extend(b"srv");
        let mut frame = vec![0xff, 0x03, 0xc2, 0x23];
        frame.extend(cp(1, 42, &d));
        c.ppp_control(0, &frame, &mut out, &mut ev);
        let resp = out.last().unwrap();
        let p = &resp[DATA_HEADER..];
        assert_eq!((p[0], p[1], p[4]), (2, 42, 16), "Response, same id, 16-byte value");
        let mut m = vec![42u8];
        m.extend(b"secret");
        m.extend(chal);
        assert_eq!(&p[5..21], &md5(&m));
        assert_eq!(&p[21..], b"ppp1");
        // MS-CHAPv2: we ask for CHAP-MD5 instead
        let r = c.lcp_answer(8, &[3, 5, 0xc2, 0x23, 0x81]);
        assert_eq!(r, cp(3, 8, &[3, 5, 0xc2, 0x23, 5]));
    }
}
