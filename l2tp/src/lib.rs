//! L2TPv2 (RFC 2661) server with PPP (LCP, PAP, IPCP), without IPsec and
//! without encryption, as in rust-l2tp: no_std, no OS dependencies. The
//! caller owns the UDP socket and the data path:
//!
//! * `handle`: control messages and PPP negotiation (the slow path); replies
//!   to send come back in `out`, sessions going up or down in `events`.
//! * `classify`: for every data packet, whether it carries an IPv4 packet
//!   from an authenticated client (and where it starts), so the caller can
//!   forward it in place; PPP control goes to `handle`.
//! * `route` + `data_header`: how to encapsulate a packet for a client.
//!
//! Clients get addresses from a /24 pool (the server is .1). Without
//! accounts anyone may connect; with accounts PAP is required and a user
//! may have their own egress address.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub type Ip = u32;
/// UDP address of a client (address, port).
pub type Peer = (Ip, u16);

// L2TP message types
const SCCRQ: u16 = 1;
const SCCRP: u16 = 2;
const STOPCCN: u16 = 4;
const ICRQ: u16 = 10;
const ICRP: u16 = 11;
const ICCN: u16 = 12;
const CDN: u16 = 14;

// L2TP AVP types
const AVP_MESSAGE_TYPE: u16 = 0;
const AVP_PROTOCOL_VERSION: u16 = 2;
const AVP_FRAMING_CAPS: u16 = 3;
const AVP_HOST_NAME: u16 = 7;
const AVP_ASSIGNED_TUNNEL_ID: u16 = 9;
const AVP_ASSIGNED_SESSION_ID: u16 = 14;

// PPP protocols
pub const PROTO_IP: u16 = 0x0021;
const PROTO_LCP: u16 = 0xc021;
const PROTO_PAP: u16 = 0xc023;
const PROTO_IPCP: u16 = 0x8021;

/// Bytes `data_header` puts in front of an IP packet.
pub const DATA_HEADER: usize = 10;

#[derive(Clone, Debug)]
pub struct Account {
    pub user: String,
    pub password: String,
    pub egress: Option<Ip>,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// The /24 the clients get addresses from; the server is `pool + 1`.
    pub pool: Ip,
    pub dns: [Ip; 2],
    /// MRU we ask for (the tunnel MTU).
    pub mru: u16,
    pub host_name: String,
    /// Empty: anyone may connect, without authentication.
    pub accounts: Vec<Account>,
    /// A tunnel silent this long is dropped (clients send HELLO every 60 s).
    pub idle_ms: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            pool: u32::from_be_bytes([10, 0, 0, 0]),
            dns: [u32::from_be_bytes([8, 8, 8, 8]), u32::from_be_bytes([1, 1, 1, 1])],
            mru: 1400,
            host_name: String::from("rustros"),
            accounts: Vec::new(),
            idle_ms: 300_000,
        }
    }
}

impl Config {
    pub fn server_ip(&self) -> Ip {
        self.pool | 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A client is authenticated and may send IP (`user` empty without accounts).
    Up { ip: Ip, peer: Peer, user: String, egress: Option<Ip> },
    /// Its session ended; the address is free again.
    Down { ip: Ip },
    /// Something worth a line in the log.
    AuthFailed { peer: Peer, user: String },
    NoPap { peer: Peer },
    PoolFull { peer: Peer },
}

/// How to reach a client: its UDP address and the peer's tunnel and session ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub peer: Peer,
    pub tunnel: u16,
    pub session: u16,
}

/// What a received L2TP packet is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    /// An IPv4 packet from the authenticated client `client`, starting at `offset`.
    Ip { client: Ip, offset: usize },
    /// Control or PPP negotiation: give it to `handle`.
    Control,
    /// Unknown tunnel or session, not authenticated, spoofed source, ...
    Drop,
}

struct Session {
    peer_sid: u16,
    ip: Ip,
    user: String,
    lcp_id: u8,
    /// our LCP request was accepted
    lcp_acked: bool,
    /// our LCP request asks for PAP
    pap: bool,
    ipcp_sent: bool,
    authed: bool,
}

struct Tunnel {
    peer: Peer,
    peer_id: u16,
    ns: u16,
    nr: u16,
    next_session: u16,
    sessions: BTreeMap<u16, Session>,
    last_rx: u64,
}

pub struct Server {
    cfg: Config,
    /// by our tunnel id
    tunnels: BTreeMap<u16, Tunnel>,
    by_peer: BTreeMap<Peer, u16>,
    /// client address -> (tunnel id, session id), ours
    by_ip: BTreeMap<Ip, (u16, u16)>,
    next_id: u16,
}

struct Header {
    control: bool,
    tunnel_id: u16,
    session_id: u16,
    ns: u16,
    payload: usize,
}

fn be16(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

fn be32(p: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*p.get(i)?, *p.get(i + 1)?, *p.get(i + 2)?, *p.get(i + 3)?]))
}

fn parse_header(p: &[u8]) -> Option<Header> {
    let flags = be16(p, 0)?;
    if flags & 0x000f != 2 {
        return None;
    }
    let mut i = 2;
    if flags & 0x4000 != 0 {
        i += 2; // Length
    }
    let tunnel_id = be16(p, i)?;
    let session_id = be16(p, i + 2)?;
    i += 4;
    let mut ns = 0;
    if flags & 0x0800 != 0 {
        ns = be16(p, i)?;
        i += 4; // Ns + Nr
    }
    if flags & 0x0200 != 0 {
        i += 2 + be16(p, i)? as usize; // Offset Size + padding
    }
    if i > p.len() {
        return None;
    }
    Some(Header { control: flags & 0x8000 != 0, tunnel_id, session_id, ns, payload: i })
}

fn parse_avps(mut p: &[u8]) -> Vec<(u16, &[u8])> {
    let mut avps = Vec::new();
    while p.len() >= 6 {
        let len = (u16::from_be_bytes([p[0], p[1]]) & 0x03ff) as usize;
        if len < 6 || len > p.len() {
            break;
        }
        if p[2..4] == [0, 0] {
            avps.push((u16::from_be_bytes([p[4], p[5]]), &p[6..len]));
        }
        p = &p[len..];
    }
    avps
}

fn avp(out: &mut Vec<u8>, ty: u16, val: &[u8]) {
    out.extend((0x8000 | (6 + val.len() as u16)).to_be_bytes()); // M bit + length
    out.extend(0u16.to_be_bytes()); // vendor
    out.extend(ty.to_be_bytes());
    out.extend_from_slice(val);
}

/// A control message (a ZLB acknowledgement when `avps` is empty).
fn control(t: &mut Tunnel, session_id: u16, avps: &[u8]) -> Vec<u8> {
    let len = 12 + avps.len();
    let mut p = Vec::with_capacity(len);
    p.extend(0xC802u16.to_be_bytes()); // T=1 L=1 S=1, Ver=2
    p.extend((len as u16).to_be_bytes());
    p.extend(t.peer_id.to_be_bytes());
    p.extend(session_id.to_be_bytes());
    p.extend(t.ns.to_be_bytes());
    p.extend(t.nr.to_be_bytes());
    p.extend_from_slice(avps);
    if !avps.is_empty() {
        t.ns = t.ns.wrapping_add(1);
    }
    p
}

/// L2TP data header + PPP header for an IPv4 packet to `r`.
pub fn data_header(r: &Route) -> [u8; DATA_HEADER] {
    let [t0, t1] = r.tunnel.to_be_bytes();
    let [s0, s1] = r.session.to_be_bytes();
    [0x00, 0x02, t0, t1, s0, s1, 0xff, 0x03, 0x00, 0x21]
}

/// A PPP frame in an L2TP data packet.
fn ppp(r: &Route, proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = data_header(r).to_vec();
    p[8..10].copy_from_slice(&proto.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// LCP/PAP/IPCP packet: code, identifier, length, data.
fn cp(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut p = vec![code, id];
    p.extend((4 + data.len() as u16).to_be_bytes());
    p.extend_from_slice(data);
    p
}

/// PPP protocol and payload of a frame (address/control and protocol
/// field compression allowed).
fn ppp_proto(frame: &[u8]) -> Option<(u16, usize)> {
    let off = if frame.starts_with(&[0xff, 0x03]) { 2 } else { 0 };
    match frame.get(off) {
        Some(&b) if b & 1 == 1 => Some((b as u16, off + 1)), // compressed
        Some(_) => Some((be16(frame, off)?, off + 2)),
        None => None,
    }
}

impl Session {
    fn lcp_request(&self, mru: u16) -> Vec<u8> {
        let mut o = vec![1, 4];
        o.extend(mru.to_be_bytes());
        if self.pap {
            o.extend([3, 4, 0xc0, 0x23]);
        }
        cp(1, self.lcp_id, &o)
    }

    /// Answer the client's IPCP request: its address and DNS, nothing else.
    fn ipcp_reply(&self, cfg: &Config, id: u8, data: &[u8]) -> Vec<u8> {
        let (mut nak, mut rej) = (Vec::new(), Vec::new());
        let mut o = data;
        while o.len() >= 2 {
            let (opt, rest) = o.split_at((o[1] as usize).clamp(2, o.len()));
            let want = match opt[0] {
                3 => Some(self.ip),
                129 => Some(cfg.dns[0]),
                131 => Some(cfg.dns[1]),
                _ => None,
            };
            match want {
                Some(ip) if opt.len() == 6 => {
                    if opt[2..] != ip.to_be_bytes() {
                        nak.extend([opt[0], 6]);
                        nak.extend(ip.to_be_bytes());
                    }
                }
                _ => rej.extend_from_slice(opt),
            }
            o = rest;
        }
        if !rej.is_empty() {
            cp(4, id, &rej)
        } else if !nak.is_empty() {
            cp(3, id, &nak)
        } else {
            cp(2, id, data)
        }
    }
}

/// Answer the client's LCP request: accept what we support, reject the
/// rest (callback, multilink, asking us to authenticate, ...), or Windows
/// goes into callback negotiation and fails.
fn lcp_reply(id: u8, data: &[u8]) -> Vec<u8> {
    let mut rej = Vec::new();
    let mut o = data;
    while o.len() >= 2 {
        let (opt, rest) = o.split_at((o[1] as usize).clamp(2, o.len()));
        // MRU, ACCM, magic number, PFC, ACFC
        if !matches!(opt[0], 1 | 2 | 5 | 7 | 8) {
            rej.extend_from_slice(opt);
        }
        o = rest;
    }
    if rej.is_empty() { cp(2, id, data) } else { cp(4, id, &rej) }
}

impl Server {
    pub fn new(cfg: Config) -> Server {
        Server { cfg, tunnels: BTreeMap::new(), by_peer: BTreeMap::new(), by_ip: BTreeMap::new(), next_id: 1 }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// New accounts or DNS take effect for sessions authenticating from now on.
    pub fn set_config(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    /// How to reach client `ip` (authenticated sessions only).
    pub fn route(&self, ip: Ip) -> Option<Route> {
        let &(tid, sid) = self.by_ip.get(&ip)?;
        let t = self.tunnels.get(&tid)?;
        let s = t.sessions.get(&sid)?;
        s.authed.then_some(Route { peer: t.peer, tunnel: t.peer_id, session: s.peer_sid })
    }

    /// Live sessions: (client address, UDP peer, user, authenticated).
    pub fn sessions(&self) -> impl Iterator<Item = (Ip, Peer, &str, bool)> + '_ {
        self.tunnels.values().flat_map(|t| t.sessions.values().map(move |s| (s.ip, t.peer, s.user.as_str(), s.authed)))
    }

    /// Fast path: what the L2TP packet `pkt` from `peer` is.
    pub fn classify(&mut self, now: u64, peer: Peer, pkt: &[u8]) -> Data {
        let Some(h) = parse_header(pkt) else { return Data::Drop };
        if h.control {
            return Data::Control;
        }
        let Some(t) = self.tunnels.get_mut(&h.tunnel_id) else { return Data::Drop };
        if t.peer != peer {
            return Data::Drop;
        }
        t.last_rx = now;
        let Some(s) = t.sessions.get(&h.session_id) else { return Data::Drop };
        let frame = &pkt[h.payload..];
        match ppp_proto(frame) {
            Some((PROTO_IP, off)) => {
                let ip = h.payload + off;
                // only authenticated clients, and only from their own address
                if !s.authed || be32(pkt, ip + 12) != Some(s.ip) || pkt[ip] >> 4 != 4 {
                    return Data::Drop;
                }
                Data::Ip { client: s.ip, offset: ip }
            }
            Some(_) => Data::Control,
            None => Data::Drop,
        }
    }

    fn free_ip(&self) -> Option<Ip> {
        (2..=254).map(|i| self.cfg.pool | i).find(|ip| !self.by_ip.contains_key(ip))
    }

    fn drop_tunnel(&mut self, tid: u16, events: &mut Vec<Event>) {
        if let Some(t) = self.tunnels.remove(&tid) {
            self.by_peer.remove(&t.peer);
            for s in t.sessions.values() {
                self.by_ip.remove(&s.ip);
                events.push(Event::Down { ip: s.ip });
            }
        }
    }

    /// Drop tunnels that went silent.
    pub fn tick(&mut self, now: u64, events: &mut Vec<Event>) {
        let idle = self.cfg.idle_ms;
        let dead: Vec<u16> = self.tunnels.iter().filter(|(_, t)| now.saturating_sub(t.last_rx) > idle).map(|(&id, _)| id).collect();
        for tid in dead {
            self.drop_tunnel(tid, events);
        }
    }

    /// Slow path: a control message, or PPP negotiation in a data packet.
    pub fn handle(&mut self, now: u64, peer: Peer, pkt: &[u8], out: &mut Vec<(Peer, Vec<u8>)>, events: &mut Vec<Event>) {
        let Some(h) = parse_header(pkt) else { return };
        if !h.control {
            let Some(t) = self.tunnels.get_mut(&h.tunnel_id) else { return };
            if t.peer != peer {
                return;
            }
            t.last_rx = now;
            let tunnel = t.peer_id;
            let Some(s) = t.sessions.get_mut(&h.session_id) else { return };
            let r = Route { peer, tunnel, session: s.peer_sid };
            let was = s.authed;
            ppp_control(&self.cfg, &r, s, &pkt[h.payload..], out, events);
            if s.authed && !was {
                let egress = self.cfg.accounts.iter().find(|a| a.user == s.user).and_then(|a| a.egress);
                events.push(Event::Up { ip: s.ip, peer, user: s.user.clone(), egress });
            }
            return;
        }

        let avps = parse_avps(&pkt[h.payload..]);
        let get16 = |ty| avps.iter().find(|a| a.0 == ty).and_then(|a| be16(a.1, 0));
        let Some(msg) = get16(AVP_MESSAGE_TYPE) else {
            // ZLB: nothing to do but note the tunnel is alive
            if let Some(&tid) = self.by_peer.get(&peer) {
                if let Some(t) = self.tunnels.get_mut(&tid) {
                    t.last_rx = now;
                }
            }
            return;
        };

        if msg == SCCRQ {
            let peer_id = get16(AVP_ASSIGNED_TUNNEL_ID).unwrap_or(0);
            // a new tunnel, or the client reconnected with a new tunnel id
            let known = self.by_peer.get(&peer).and_then(|tid| self.tunnels.get(tid));
            if known.is_none_or(|t| t.peer_id != peer_id) {
                if let Some(&old) = self.by_peer.get(&peer) {
                    self.drop_tunnel(old, events);
                }
                let mut id = self.next_id;
                while self.tunnels.contains_key(&id) || id == 0 {
                    id = id.wrapping_add(1);
                }
                self.next_id = id.wrapping_add(1);
                let t = Tunnel { peer, peer_id, ns: 0, nr: 0, next_session: 1, sessions: BTreeMap::new(), last_rx: now };
                self.tunnels.insert(id, t);
                self.by_peer.insert(peer, id);
            }
        }
        let Some(&tid) = self.by_peer.get(&peer) else { return };
        let free_ip = self.free_ip();
        let t = self.tunnels.get_mut(&tid).unwrap();
        t.last_rx = now;

        if h.ns != t.nr {
            // retransmission or out of order: just acknowledge
            out.push((peer, control(t, 0, &[])));
            return;
        }
        t.nr = t.nr.wrapping_add(1);

        let mut avps_out = Vec::new();
        let reply = match msg {
            SCCRQ => {
                avp(&mut avps_out, AVP_MESSAGE_TYPE, &SCCRP.to_be_bytes());
                avp(&mut avps_out, AVP_PROTOCOL_VERSION, &[1, 0]);
                avp(&mut avps_out, AVP_HOST_NAME, self.cfg.host_name.as_bytes());
                avp(&mut avps_out, AVP_FRAMING_CAPS, &3u32.to_be_bytes());
                avp(&mut avps_out, AVP_ASSIGNED_TUNNEL_ID, &tid.to_be_bytes());
                control(t, 0, &avps_out)
            }
            ICRQ => {
                let peer_sid = get16(AVP_ASSIGNED_SESSION_ID).unwrap_or(0);
                match free_ip {
                    Some(ip) => {
                        let mut sid = t.next_session;
                        while t.sessions.contains_key(&sid) || sid == 0 {
                            sid = sid.wrapping_add(1);
                        }
                        t.next_session = sid.wrapping_add(1);
                        let open = self.cfg.accounts.is_empty();
                        t.sessions.insert(
                            sid,
                            Session { peer_sid, ip, user: String::new(), lcp_id: 1, lcp_acked: false, pap: true, ipcp_sent: false, authed: open },
                        );
                        self.by_ip.insert(ip, (tid, sid));
                        avp(&mut avps_out, AVP_MESSAGE_TYPE, &ICRP.to_be_bytes());
                        avp(&mut avps_out, AVP_ASSIGNED_SESSION_ID, &sid.to_be_bytes());
                        let r = control(t, peer_sid, &avps_out);
                        if open {
                            events.push(Event::Up { ip, peer, user: String::new(), egress: None });
                        }
                        r
                    }
                    None => {
                        events.push(Event::PoolFull { peer });
                        control(t, 0, &[])
                    }
                }
            }
            ICCN => {
                // the session is up: start PPP
                if let Some(s) = t.sessions.get(&h.session_id) {
                    let r = Route { peer, tunnel: t.peer_id, session: s.peer_sid };
                    out.push((peer, ppp(&r, PROTO_LCP, &s.lcp_request(self.cfg.mru))));
                }
                control(t, 0, &[])
            }
            CDN => {
                if let Some(s) = t.sessions.remove(&h.session_id) {
                    self.by_ip.remove(&s.ip);
                    events.push(Event::Down { ip: s.ip });
                }
                control(t, 0, &[])
            }
            // SCCCN, HELLO, StopCCN, ...: acknowledge
            _ => control(t, 0, &[]),
        };
        out.push((peer, reply));
        if msg == STOPCCN {
            self.drop_tunnel(tid, events);
        }
    }
}

/// PPP negotiation for one session.
fn ppp_control(cfg: &Config, r: &Route, s: &mut Session, frame: &[u8], out: &mut Vec<(Peer, Vec<u8>)>, events: &mut Vec<Event>) {
    let Some((proto, off)) = ppp_proto(frame) else { return };
    let f = &frame[off..];
    let mut send = |proto: u16, p: Vec<u8>| out.push((r.peer, ppp(r, proto, &p)));
    if proto == PROTO_IP {
        return; // the fast path's business
    }
    if !matches!(proto, PROTO_LCP | PROTO_PAP | PROTO_IPCP) {
        // CCP, IPv6CP, ...: LCP Protocol-Reject
        s.lcp_id = s.lcp_id.wrapping_add(1);
        let mut d = proto.to_be_bytes().to_vec();
        d.extend_from_slice(f);
        send(PROTO_LCP, cp(8, s.lcp_id, &d));
        return;
    }
    if f.len() < 4 {
        return;
    }
    let (code, id) = (f[0], f[1]);
    let data = &f[4..(u16::from_be_bytes([f[2], f[3]]) as usize).clamp(4, f.len())];
    match (proto, code) {
        (PROTO_LCP, 1) => {
            send(PROTO_LCP, lcp_reply(id, data));
            // our request may have gone out before the client's PPP was up
            if !s.lcp_acked {
                s.lcp_id = s.lcp_id.wrapping_add(1);
                send(PROTO_LCP, s.lcp_request(cfg.mru));
            }
        }
        (PROTO_LCP, 2) => s.lcp_acked = true,
        (PROTO_LCP, 3 | 4) => {
            // the client does not like our options (most likely PAP)
            s.lcp_id = s.lcp_id.wrapping_add(1);
            if cfg.accounts.is_empty() {
                s.pap = false;
                send(PROTO_LCP, s.lcp_request(cfg.mru));
            } else {
                events.push(Event::NoPap { peer: r.peer });
                send(PROTO_LCP, cp(5, s.lcp_id, &[]));
            }
        }
        (PROTO_LCP, 5) => send(PROTO_LCP, cp(6, id, &[])),
        (PROTO_LCP, 9) if data.len() >= 4 => {
            let mut d = vec![0; 4]; // our magic number is 0
            d.extend_from_slice(&data[4..]);
            send(PROTO_LCP, cp(10, id, &d));
        }
        (PROTO_PAP, 1) => {
            let ulen = *data.first().unwrap_or(&0) as usize;
            let plen = *data.get(1 + ulen).unwrap_or(&0) as usize;
            let user = String::from_utf8_lossy(data.get(1..1 + ulen).unwrap_or(&[])).into_owned();
            let pass = data.get(2 + ulen..2 + ulen + plen).unwrap_or(&[]);
            let ok = cfg.accounts.is_empty() || cfg.accounts.iter().any(|a| a.user == user && ct_eq(a.password.as_bytes(), pass));
            if !ok {
                events.push(Event::AuthFailed { peer: r.peer, user });
                send(PROTO_PAP, cp(3, id, &[0])); // Authenticate-Nak
                return;
            }
            s.user = user;
            s.authed = true;
            send(PROTO_PAP, cp(2, id, &[0]));
        }
        (PROTO_IPCP, 1) if s.authed => {
            if !s.ipcp_sent {
                s.ipcp_sent = true;
                let mut o = vec![3, 6];
                o.extend(cfg.server_ip().to_be_bytes());
                send(PROTO_IPCP, cp(1, 1, &o));
            }
            send(PROTO_IPCP, s.ipcp_reply(cfg, id, data));
        }
        (PROTO_IPCP, 5) => send(PROTO_IPCP, cp(6, id, &[])),
        _ => {}
    }
}

/// Constant-time comparison (passwords).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod tests;
