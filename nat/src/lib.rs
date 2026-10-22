//! Packet-level NAPT for IPv4 (RFC 3022 / RFC 4787 / RFC 5382), no_std and
//! free of OS dependencies: the caller hands in IPv4 packets and sends them on.
//!
//! * `outbound`: a packet from an inside host. Source address and port become
//!   the host's egress address and an external port; TTL is decremented.
//! * `inbound`: a packet from outside. If it belongs to a session it is
//!   rewritten back and the caller learns the inside host and the `tag` it
//!   gave when the session was created (an L2TP session, a LAN port, ...).
//!   Anything else is `NotOurs`, for the caller's own stack.
//!
//! Mapping is endpoint-independent (one external port per inside address and
//! port, whatever the destination), filtering is address- and
//! port-dependent (only the remote endpoints the host talked to get in).
//! TCP, UDP and ICMP echo are translated, ICMP errors have their inner packet
//! translated too (path MTU discovery keeps working), IP fragments follow
//! their first fragment. Checksums are updated incrementally (RFC 1624).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::hash::{BuildHasher, Hasher};

use hashbrown::HashMap;

pub type Ip = u32;

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Fragments waiting for their companions are remembered this long.
const FRAG_MS: u64 = 30_000;
const MAX_FRAGS: usize = 4096;
const RST_MS: u64 = 10_000;

#[derive(Clone, Debug)]
pub struct Config {
    /// External ports (and ICMP identifiers) handed out, inclusive. Keep it
    /// clear of the ports the local stack uses.
    pub ports: (u16, u16),
    pub max_sessions: usize,
    /// Sessions one inside host may hold.
    pub max_per_host: usize,
    /// Clamp the MSS of TCP SYNs in both directions (tunnels with a small MTU).
    pub mss: Option<u16>,
    pub tcp_established_ms: u64,
    /// SYN sent but not answered, or both sides closed.
    pub tcp_transitory_ms: u64,
    /// UDP before the remote side answered, and after.
    pub udp_ms: u64,
    pub udp_stream_ms: u64,
    pub icmp_ms: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ports: (10_000, 49_151),
            max_sessions: 1 << 18,
            max_per_host: 8192,
            mss: None,
            tcp_established_ms: 7440_000,
            tcp_transitory_ms: 240_000,
            udp_ms: 30_000,
            udp_stream_ms: 180_000,
            icmp_ms: 30_000,
        }
    }
}

/// Why a packet was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    Malformed,
    /// A protocol (or ICMP type) that is not translated.
    Unsupported,
    /// The caller should answer with ICMP time exceeded (see `icmp_error`).
    TtlExceeded,
    /// No egress address for this host.
    NoEgress,
    /// TCP that is not a SYN and matches no session, or a fragment whose first
    /// fragment was not seen.
    NoSession,
    PortsExhausted,
    HostLimit,
    TableFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// Rewritten for inside host `to`; `tag` is what `outbound` was given.
    Forward { to: Ip, tag: u32 },
    /// Not a NAT session: for the local stack.
    NotOurs,
    Drop(Drop),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sessions: usize,
    pub created: u64,
    pub expired: u64,
    pub out_packets: u64,
    pub in_packets: u64,
    pub dropped: u64,
}

/// What `sessions` reports per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub proto: u8,
    pub inside: (Ip, u16),
    pub external: (Ip, u16),
    pub remote: (Ip, u16),
    pub tag: u32,
    /// ms until it expires
    pub idle_left: u64,
}

// ------------------------------------------------------------------ hashing

/// Seeded multiply-rotate hash: fast on the small integer keys used here,
/// and the per-instance seed keeps outsiders from steering collisions.
#[derive(Clone, Copy)]
struct Seed(u64);

struct Fx(u64);

impl Hasher for Fx {
    fn write(&mut self, b: &[u8]) {
        for c in b.chunks(8) {
            let mut a = [0u8; 8];
            a[..c.len()].copy_from_slice(c);
            self.write_u64(u64::from_le_bytes(a));
        }
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0.rotate_left(5) ^ v).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    fn write_u128(&mut self, v: u128) {
        self.write_u64(v as u64);
        self.write_u64((v >> 64) as u64);
    }
    fn write_u32(&mut self, v: u32) {
        self.write_u64(v as u64);
    }
    fn finish(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^ (h >> 33)
    }
}

impl BuildHasher for Seed {
    type Hasher = Fx;
    fn build_hasher(&self) -> Fx {
        Fx(self.0)
    }
}

type Map<K, V> = HashMap<K, V, Seed>;

fn key(proto: u8, a: Ip, ap: u16, b: Ip, bp: u16) -> u128 {
    (proto as u128) << 96 | (a as u128) << 64 | (ap as u128) << 48 | (b as u128) << 16 | bp as u128
}

// ------------------------------------------------------------------ packets

fn get16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}
fn set16(p: &mut [u8], o: usize, v: u16) {
    p[o..o + 2].copy_from_slice(&v.to_be_bytes());
}
fn get32(p: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
}
fn set32(p: &mut [u8], o: usize, v: u32) {
    p[o..o + 4].copy_from_slice(&v.to_be_bytes());
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s as u16
}

/// RFC 1624: checksum `c` after a 16-bit word changed from `old` to `new`.
fn adj16(c: u16, old: u16, new: u16) -> u16 {
    !fold((!c) as u32 + (!old) as u32 + new as u32)
}

fn adj32(c: u16, old: u32, new: u32) -> u16 {
    adj16(adj16(c, (old >> 16) as u16, (new >> 16) as u16), old as u16, new as u16)
}

/// Internet checksum over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut c = data.chunks_exact(2);
    for w in &mut c {
        s += u16::from_be_bytes([w[0], w[1]]) as u32;
        s = (s & 0xFFFF) + (s >> 16);
    }
    if let [b] = c.remainder() {
        s += (*b as u32) << 8;
    }
    !fold(s)
}

/// A checked IPv4 header.
#[derive(Clone, Copy)]
struct V4 {
    ihl: usize,
    total: usize,
    proto: u8,
    src: Ip,
    dst: Ip,
    id: u16,
    /// fragment offset (in 8-byte units) and more-fragments flag
    offset: u16,
    more: bool,
}

fn parse(p: &[u8]) -> Option<V4> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 15) as usize * 4;
    let total = get16(p, 2) as usize;
    if ihl < 20 || total < ihl || total > p.len() {
        return None;
    }
    let frag = get16(p, 6);
    Some(V4 {
        ihl,
        total,
        proto: p[9],
        src: get32(p, 12),
        dst: get32(p, 16),
        id: get16(p, 4),
        offset: frag & 0x1FFF,
        more: frag & 0x2000 != 0,
    })
}

/// Rewrite the address at `o` (12 = source, 16 = destination) and fix the header checksum.
fn set_addr(p: &mut [u8], o: usize, new: Ip) {
    let old = get32(p, o);
    set32(p, o, new);
    let c = adj32(get16(p, 10), old, new);
    set16(p, 10, c);
}

fn dec_ttl(p: &mut [u8]) {
    let old = get16(p, 8);
    p[8] -= 1;
    let c = adj16(get16(p, 10), old, get16(p, 8));
    set16(p, 10, c);
}

/// Offset of the L4 checksum, and whether 0 means "none" (UDP).
fn csum_at(proto: u8) -> (usize, bool) {
    match proto {
        TCP => (16, false),
        UDP => (6, true),
        _ => (2, false), // ICMP
    }
}

/// Port (or ICMP identifier) change in the L4 header at `l4`, plus an
/// address change the pseudo header sees (not for ICMP). `port_at` is the
/// offset of the port in the L4 header. The checksum is only touched if it
/// is inside `p` (ICMP errors quote just 8 bytes). `partial`: the checksum
/// holds only the pseudo-header sum (offloads): ports are not in it, an
/// address change adjusts it as a sum.
fn set_port(p: &mut [u8], l4: usize, proto: u8, port_at: usize, new_port: u16, addr: Option<(Ip, Ip)>, partial: bool) {
    let old_port = get16(p, l4 + port_at);
    set16(p, l4 + port_at, new_port);
    let (c_at, optional) = csum_at(proto);
    if l4 + c_at + 2 > p.len() {
        return;
    }
    let mut c = get16(p, l4 + c_at);
    if partial && proto != ICMP {
        if let Some((old, new)) = addr {
            set16(p, l4 + c_at, !adj32(!c, old, new));
        }
        return;
    }
    if optional && c == 0 {
        return;
    }
    c = adj16(c, old_port, new_port);
    if let (Some((old, new)), true) = (addr, proto != ICMP) {
        c = adj32(c, old, new);
    }
    if optional && c == 0 {
        c = 0xFFFF;
    }
    set16(p, l4 + c_at, c);
}

/// Static (1:1) NAT, stateless: rewrite the source (`src`) or destination
/// address of an IPv4 packet to `new`, protocols and ports untouched. TCP
/// and UDP checksums follow the pseudo header; an ICMP error has the address
/// in its quoted packet (which went the other way) rewritten back to match.
/// Returns the old address, or None if `p` is not an IPv4 packet.
pub fn rewrite(p: &mut [u8], src: bool, new: Ip, partial: bool) -> Option<Ip> {
    let h = parse(p)?;
    let o = if src { 12 } else { 16 };
    let old = get32(p, o);
    set_addr(p, o, new);
    if h.offset != 0 {
        return Some(old); // a later fragment: no L4 header
    }
    let (l4, end) = (h.ihl, h.total);
    match h.proto {
        TCP | UDP => fix_l4(p, l4, end, h.proto, old, new, partial),
        ICMP if end >= l4 + 8 && matches!(p[l4], 3 | 11 | 12) => {
            let q = l4 + 8;
            if let Some(qh) = parse_quoted(&p[q..end]) {
                let qo = if src { 16 } else { 12 };
                if get32(p, q + qo) == old {
                    set_addr(&mut p[q..end], qo, new);
                    if matches!(qh.proto, TCP | UDP) {
                        fix_l4(p, q + qh.ihl, end, qh.proto, old, new, false);
                    }
                    fix_icmp(p, l4, end);
                }
            }
        }
        _ => {}
    }
    Some(old)
}

/// The TCP/UDP checksum at `l4` after a pseudo-header address change, if it
/// is within `end` (a quoted packet may be cut short).
fn fix_l4(p: &mut [u8], l4: usize, end: usize, proto: u8, old: Ip, new: Ip, partial: bool) {
    let (c_at, optional) = csum_at(proto);
    if l4 + c_at + 2 > end {
        return;
    }
    let c = get16(p, l4 + c_at);
    if partial {
        set16(p, l4 + c_at, !adj32(!c, old, new));
        return;
    }
    if optional && c == 0 {
        return;
    }
    let mut c = adj32(c, old, new);
    if optional && c == 0 {
        c = 0xFFFF;
    }
    set16(p, l4 + c_at, c);
}

/// Lower the MSS option of a SYN to `mss`.
fn clamp_mss(p: &mut [u8], l4: usize, mss: u16, partial: bool) {
    let doff = (p[l4 + 12] >> 4) as usize * 4;
    if doff < 20 || l4 + doff > p.len() {
        return;
    }
    let mut o = l4 + 20;
    while o < l4 + doff {
        match p[o] {
            0 => break,
            1 => o += 1,
            kind => {
                let Some(&len) = p.get(o + 1) else { break };
                if len < 2 || o + len as usize > l4 + doff {
                    break;
                }
                if kind == 2 && len == 4 {
                    let old = get16(p, o + 2);
                    if old > mss {
                        set16(p, o + 2, mss);
                        if !partial {
                            let c = adj16(get16(p, l4 + 16), old, mss);
                            set16(p, l4 + 16, c);
                        }
                    }
                    return;
                }
                o += len as usize;
            }
        }
    }
}

/// The "port" used to tell sessions apart: TCP/UDP source port, ICMP echo identifier.
fn l4_ports(p: &[u8], h: &V4, src_side: bool) -> Option<(u16, u16)> {
    let l4 = h.ihl;
    match h.proto {
        TCP | UDP => {
            if h.total < l4 + if h.proto == TCP { 20 } else { 8 } {
                return None;
            }
            let (s, d) = (get16(p, l4), get16(p, l4 + 2));
            Some(if src_side { (s, d) } else { (d, s) })
        }
        _ => None,
    }
}

/// Build an ICMP error about `orig` (an IPv4 packet), sent from `src`:
/// time exceeded is (11, 0), fragmentation needed is (3, 4) with `mtu`.
pub fn icmp_error(src: Ip, orig: &[u8], typ: u8, code: u8, mtu: u16) -> Option<Vec<u8>> {
    let h = parse(orig)?;
    if h.proto == ICMP && orig.get(h.ihl).is_some_and(|&t| !matches!(t, 0 | 8)) {
        return None; // never about an ICMP error
    }
    let quote = &orig[..h.total.min(h.ihl + 8)];
    let len = 20 + 8 + quote.len();
    let mut p = alloc::vec![0u8; len];
    p[0] = 0x45;
    set16(&mut p, 2, len as u16);
    p[8] = 64;
    p[9] = ICMP;
    set32(&mut p, 12, src);
    set32(&mut p, 16, h.src);
    let c = checksum(&p[..20]);
    set16(&mut p, 10, c);
    p[20] = typ;
    p[21] = code;
    if typ == 3 && code == 4 {
        set16(&mut p, 26, mtu);
    }
    p[28..].copy_from_slice(quote);
    let c = checksum(&p[20..]);
    set16(&mut p, 22, c);
    Some(p)
}

// ------------------------------------------------------------------ table

#[derive(Clone, Copy, Default)]
struct Session {
    /// 0 = free slot
    proto: u8,
    in_ip: Ip,
    in_port: u16,
    ext_ip: Ip,
    ext_port: u16,
    rem_ip: Ip,
    rem_port: u16,
    tag: u32,
    expires: u64,
    /// bumped when the slot is reused (fragment entries point at slots)
    generation: u32,
    seen_in: bool,
    fin_out: bool,
    fin_in: bool,
    rst: bool,
}

impl Session {
    fn in_key(&self) -> u128 {
        key(self.proto, self.in_ip, self.in_port, self.rem_ip, self.rem_port)
    }
    fn out_key(&self) -> u128 {
        key(self.proto, self.ext_ip, self.ext_port, self.rem_ip, self.rem_port)
    }
    fn timeout(&self, c: &Config) -> u64 {
        match self.proto {
            TCP if self.rst => RST_MS,
            TCP if self.fin_out && self.fin_in => c.tcp_transitory_ms,
            TCP if self.seen_in => c.tcp_established_ms,
            TCP => c.tcp_transitory_ms,
            UDP if self.seen_in => c.udp_stream_ms,
            UDP => c.udp_ms,
            _ => c.icmp_ms,
        }
    }
    fn tcp_flags(&mut self, flags: u8, inbound: bool) {
        if flags & RST != 0 {
            self.rst = true;
        }
        if flags & FIN != 0 {
            if inbound {
                self.fin_in = true;
            } else {
                self.fin_out = true;
            }
        }
        if flags & SYN != 0 && flags & ACK == 0 && !inbound {
            // a new connection reusing the 4-tuple
            (self.rst, self.fin_in, self.fin_out) = (false, false, false);
        }
    }
}

pub struct Nat {
    cfg: Config,
    seed: u64,
    sessions: Vec<Session>,
    free: Vec<u32>,
    /// inside view -> session
    by_in: Map<u128, u32>,
    /// outside view -> session
    by_out: Map<u128, u32>,
    /// endpoint-independent mappings: (proto, inside ip, port, egress) -> (external port, sessions using it)
    mappings: Map<u128, (u16, u32)>,
    /// (proto, egress, external port) in use
    ports: Map<u64, ()>,
    per_host: Map<Ip, u32>,
    egress: Map<Ip, Ip>,
    default_egress: Ip,
    /// (direction, proto, src, dst, id) -> (session, its generation, expires)
    frags: Map<u128, (u32, u32, u64)>,
    sweep: usize,
    stats: Stats,
}

impl Nat {
    /// `seed` should be random (it keys the hash tables and port choice).
    pub fn new(cfg: Config, seed: u64) -> Nat {
        let s = Seed(seed | 1);
        Nat {
            cfg,
            seed,
            sessions: Vec::new(),
            free: Vec::new(),
            by_in: Map::with_hasher(s),
            by_out: Map::with_hasher(Seed(s.0.rotate_left(17))),
            mappings: Map::with_hasher(Seed(s.0.rotate_left(29))),
            ports: Map::with_hasher(Seed(s.0.rotate_left(41))),
            per_host: Map::with_hasher(s),
            egress: Map::with_hasher(s),
            default_egress: 0,
            frags: Map::with_hasher(Seed(s.0.rotate_left(53))),
            sweep: 0,
            stats: Stats::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Egress address for hosts without their own (0: none).
    pub fn set_default_egress(&mut self, ip: Ip) {
        self.default_egress = ip;
    }

    /// Give one inside host its own egress address (None: back to the
    /// default). Existing sessions keep the address they started with.
    pub fn set_egress(&mut self, host: Ip, ip: Option<Ip>) {
        match ip {
            Some(ip) => self.egress.insert(host, ip),
            None => self.egress.remove(&host),
        };
    }

    pub fn egress_of(&self, host: Ip) -> Ip {
        self.egress.get(&host).copied().unwrap_or(self.default_egress)
    }

    pub fn stats(&self) -> Stats {
        Stats { sessions: self.by_in.len(), ..self.stats }
    }

    /// Live sessions (for listings).
    pub fn sessions(&self, now: u64) -> impl Iterator<Item = SessionInfo> + '_ {
        self.sessions.iter().filter(move |s| s.proto != 0 && s.expires > now).map(move |s| SessionInfo {
            proto: s.proto,
            inside: (s.in_ip, s.in_port),
            external: (s.ext_ip, s.ext_port),
            remote: (s.rem_ip, s.rem_port),
            tag: s.tag,
            idle_left: s.expires - now,
        })
    }

    fn remove(&mut self, i: u32) {
        let s = self.sessions[i as usize];
        if s.proto == 0 {
            return;
        }
        self.by_in.remove(&s.in_key());
        self.by_out.remove(&s.out_key());
        let mk = key(s.proto, s.in_ip, s.in_port, s.ext_ip, 0);
        if let Some(m) = self.mappings.get_mut(&mk) {
            m.1 -= 1;
            if m.1 == 0 {
                self.mappings.remove(&mk);
                self.ports.remove(&port_key(s.proto, s.ext_ip, s.ext_port));
            }
        }
        if let Some(n) = self.per_host.get_mut(&s.in_ip) {
            *n -= 1;
            if *n == 0 {
                self.per_host.remove(&s.in_ip);
            }
        }
        self.sessions[i as usize].proto = 0;
        self.free.push(i);
    }

    /// Drop every session of an inside host (its tunnel went away).
    pub fn remove_host(&mut self, host: Ip) {
        for i in 0..self.sessions.len() {
            if self.sessions[i].proto != 0 && self.sessions[i].in_ip == host {
                self.remove(i as u32);
            }
        }
        self.frags.retain(|_, (i, g, _)| self.sessions[*i as usize].proto != 0 && self.sessions[*i as usize].generation == *g);
    }

    /// Expire idle sessions, looking at no more than `budget` slots (call it
    /// regularly; lookups also notice expired sessions).
    pub fn expire(&mut self, now: u64, budget: usize) {
        let n = self.sessions.len();
        for _ in 0..budget.min(n) {
            self.sweep = (self.sweep + 1) % n;
            let s = &self.sessions[self.sweep];
            if s.proto != 0 && s.expires <= now {
                self.remove(self.sweep as u32);
                self.stats.expired += 1;
            }
        }
        if self.frags.len() > MAX_FRAGS / 2 {
            self.frags.retain(|_, (_, _, t)| *t > now);
        }
    }

    fn live(&mut self, i: u32, now: u64) -> bool {
        if self.sessions[i as usize].expires > now {
            return true;
        }
        self.remove(i);
        self.stats.expired += 1;
        false
    }

    fn alloc_port(&self, proto: u8, in_ip: Ip, in_port: u16, ext_ip: Ip) -> Option<u16> {
        let (lo, hi) = self.cfg.ports;
        let free = |p: u16| !self.ports.contains_key(&port_key(proto, ext_ip, p));
        // keep the inside port when we can (some protocols like it)
        if (lo..=hi).contains(&in_port) && free(in_port) {
            return Some(in_port);
        }
        let n = (hi - lo) as u32 + 1;
        let mut h = Seed(self.seed).build_hasher();
        h.write_u64((in_ip as u64) << 16 | in_port as u64);
        let start = (h.finish() % n as u64) as u32;
        (0..n).map(|k| lo + ((start + k) % n) as u16).find(|&p| free(p))
    }

    fn create(&mut self, now: u64, proto: u8, in_ip: Ip, in_port: u16, rem_ip: Ip, rem_port: u16, tag: u32) -> Result<u32, Drop> {
        if self.by_in.len() >= self.cfg.max_sessions {
            return Err(Drop::TableFull);
        }
        if self.per_host.get(&in_ip).copied().unwrap_or(0) as usize >= self.cfg.max_per_host {
            return Err(Drop::HostLimit);
        }
        let ext_ip = self.egress_of(in_ip);
        if ext_ip == 0 {
            return Err(Drop::NoEgress);
        }
        let mk = key(proto, in_ip, in_port, ext_ip, 0);
        let ext_port = match self.mappings.get_mut(&mk) {
            Some(m) => {
                m.1 += 1;
                m.0
            }
            None => {
                let p = self.alloc_port(proto, in_ip, in_port, ext_ip).ok_or(Drop::PortsExhausted)?;
                self.mappings.insert(mk, (p, 1));
                self.ports.insert(port_key(proto, ext_ip, p), ());
                p
            }
        };
        let mut s = Session { proto, in_ip, in_port, ext_ip, ext_port, rem_ip, rem_port, tag, expires: now, ..Session::default() };
        let i = match self.free.pop() {
            Some(i) => {
                s.generation = self.sessions[i as usize].generation.wrapping_add(1);
                self.sessions[i as usize] = s;
                i
            }
            None => {
                self.sessions.push(s);
                self.sessions.len() as u32 - 1
            }
        };
        self.by_in.insert(s.in_key(), i);
        self.by_out.insert(s.out_key(), i);
        *self.per_host.entry(in_ip).or_insert(0) += 1;
        self.stats.created += 1;
        Ok(i)
    }

    fn touch(&mut self, i: u32, now: u64) {
        let s = &mut self.sessions[i as usize];
        s.expires = now + s.timeout(&self.cfg);
    }

    fn remember_frag(&mut self, inbound: bool, h: &V4, i: u32, now: u64) {
        if h.more && self.frags.len() < MAX_FRAGS {
            let g = self.sessions[i as usize].generation;
            self.frags.insert(frag_key(inbound, h), (i, g, now + FRAG_MS));
        }
    }

    fn frag_session(&mut self, inbound: bool, h: &V4, now: u64) -> Option<u32> {
        let k = frag_key(inbound, h);
        let (i, g, t) = *self.frags.get(&k)?;
        if !h.more {
            self.frags.remove(&k); // the last one
        }
        let s = &self.sessions[i as usize];
        (t > now && s.proto != 0 && s.generation == g).then_some(i)
    }

    /// Translate a packet from inside host (its source address) for `tag`.
    /// Returns the egress address it now carries.
    /// `partial`: the packet's TCP/UDP checksum is partial (offloads).
    pub fn outbound(&mut self, now: u64, p: &mut [u8], tag: u32, partial: bool) -> Result<Ip, Drop> {
        let r = self.outbound_inner(now, p, tag, partial);
        match r {
            Ok(_) => self.stats.out_packets += 1,
            Err(_) => self.stats.dropped += 1,
        }
        r
    }

    fn outbound_inner(&mut self, now: u64, p: &mut [u8], tag: u32, partial: bool) -> Result<Ip, Drop> {
        let h = parse(p).ok_or(Drop::Malformed)?;
        if p[8] <= 1 {
            return Err(Drop::TtlExceeded);
        }
        if h.offset != 0 {
            let i = self.frag_session(false, &h, now).ok_or(Drop::NoSession)?;
            let ext = self.sessions[i as usize].ext_ip;
            dec_ttl(p);
            set_addr(p, 12, ext);
            return Ok(ext);
        }
        let l4 = h.ihl;
        let (in_port, rem_port, port_at) = match h.proto {
            TCP | UDP => {
                let (s, d) = l4_ports(p, &h, true).ok_or(Drop::Malformed)?;
                (s, d, 0)
            }
            ICMP => {
                if h.total < l4 + 8 {
                    return Err(Drop::Malformed);
                }
                match p[l4] {
                    8 => (get16(p, l4 + 4), 0, 4),
                    3 | 4 | 11 | 12 => return self.icmp_error_out(now, p, &h),
                    _ => return Err(Drop::Unsupported),
                }
            }
            _ => return Err(Drop::Unsupported),
        };
        let flags = if h.proto == TCP { p[l4 + 13] } else { 0 };
        let ik = key(h.proto, h.src, in_port, h.dst, rem_port);
        let i = match self.by_in.get(&ik).copied() {
            Some(i) if self.live(i, now) => i,
            _ => {
                if h.proto == TCP && flags & (SYN | ACK | RST) != SYN {
                    return Err(Drop::NoSession);
                }
                self.create(now, h.proto, h.src, in_port, h.dst, rem_port, tag)?
            }
        };
        let s = &mut self.sessions[i as usize];
        s.tag = tag;
        if h.proto == TCP {
            s.tcp_flags(flags, false);
        }
        let (ext_ip, ext_port) = (s.ext_ip, s.ext_port);
        self.touch(i, now);
        let end = h.total;
        dec_ttl(p);
        set_addr(p, 12, ext_ip);
        set_port(&mut p[..end], l4, h.proto, port_at, ext_port, Some((h.src, ext_ip)), partial);
        if let (TCP, Some(mss)) = (h.proto, self.cfg.mss) {
            if flags & SYN != 0 {
                clamp_mss(&mut p[..end], l4, mss, partial);
            }
        }
        self.remember_frag(false, &h, i, now);
        Ok(ext_ip)
    }

    /// An ICMP error from an inside host about a packet that came in through
    /// a session (inner packet: remote -> inside).
    fn icmp_error_out(&mut self, now: u64, p: &mut [u8], h: &V4) -> Result<Ip, Drop> {
        let o = h.ihl + 8;
        let inner = parse_quoted(&p[o..h.total]).ok_or(Drop::Malformed)?;
        if inner.src != h.dst || inner.dst != h.src || !matches!(inner.proto, TCP | UDP) {
            return Err(Drop::Unsupported);
        }
        let il4 = o + inner.ihl;
        let (rem_port, in_port) = (get16(p, il4), get16(p, il4 + 2));
        let i = self.by_in.get(&key(inner.proto, inner.dst, in_port, inner.src, rem_port)).copied().ok_or(Drop::NoSession)?;
        if !self.live(i, now) {
            return Err(Drop::NoSession);
        }
        let s = self.sessions[i as usize];
        let end = h.total;
        // inner packet: destination becomes the external endpoint
        set_addr(&mut p[o..end], 16, s.ext_ip);
        set_port(&mut p[o..end], inner.ihl, inner.proto, 2, s.ext_port, Some((inner.dst, s.ext_ip)), false);
        dec_ttl(p);
        set_addr(p, 12, s.ext_ip);
        fix_icmp(p, h.ihl, end);
        Ok(s.ext_ip)
    }

    /// Translate a packet from outside. `NotOurs` leaves it untouched.
    pub fn inbound(&mut self, now: u64, p: &mut [u8], partial: bool) -> Inbound {
        let r = self.inbound_inner(now, p, partial);
        match r {
            Inbound::Forward { .. } => self.stats.in_packets += 1,
            Inbound::Drop(_) => self.stats.dropped += 1,
            Inbound::NotOurs => {}
        }
        r
    }

/// Would `inbound` take this TCP/UDP packet (a session's reply)? Looks
    /// without changing anything (to settle offloads first).
    pub fn owns_inbound(&self, now: u64, p: &[u8]) -> bool {
        let Some(h) = parse(p) else { return false };
        if h.offset != 0 || !matches!(h.proto, TCP | UDP) {
            return false;
        }
        let Some((ext_port, rem_port)) = l4_ports(p, &h, false) else { return false };
        self.by_out.get(&key(h.proto, h.dst, ext_port, h.src, rem_port)).is_some_and(|&i| self.sessions[i as usize].expires > now)
    }

    fn inbound_inner(&mut self, now: u64, p: &mut [u8], partial: bool) -> Inbound {
        let Some(h) = parse(p) else { return Inbound::NotOurs };
        if h.offset != 0 {
            let Some(i) = self.frag_session(true, &h, now) else { return Inbound::NotOurs };
            if p[8] <= 1 {
                return Inbound::Drop(Drop::TtlExceeded);
            }
            let s = self.sessions[i as usize];
            dec_ttl(p);
            set_addr(p, 16, s.in_ip);
            return Inbound::Forward { to: s.in_ip, tag: s.tag };
        }
        let l4 = h.ihl;
        let (ext_port, rem_port, port_at) = match h.proto {
            TCP | UDP => match l4_ports(p, &h, false) {
                Some((d, s)) => (d, s, 2),
                None => return Inbound::NotOurs,
            },
            ICMP if h.total >= l4 + 8 => match p[l4] {
                0 => (get16(p, l4 + 4), 0, 4),
                3 | 4 | 11 | 12 => return self.icmp_error_in(now, p, &h),
                _ => return Inbound::NotOurs,
            },
            _ => return Inbound::NotOurs,
        };
        let Some(i) = self.by_out.get(&key(h.proto, h.dst, ext_port, h.src, rem_port)).copied() else {
            return Inbound::NotOurs;
        };
        if !self.live(i, now) {
            return Inbound::NotOurs;
        }
        if p[8] <= 1 {
            return Inbound::Drop(Drop::TtlExceeded);
        }
        let flags = if h.proto == TCP { p[l4 + 13] } else { 0 };
        let s = &mut self.sessions[i as usize];
        s.seen_in = true;
        if h.proto == TCP {
            s.tcp_flags(flags, true);
        }
        let (in_ip, in_port, tag) = (s.in_ip, s.in_port, s.tag);
        self.touch(i, now);
        let end = h.total;
        dec_ttl(p);
        set_addr(p, 16, in_ip);
        set_port(&mut p[..end], l4, h.proto, port_at, in_port, Some((h.dst, in_ip)), partial);
        if let (TCP, Some(mss)) = (h.proto, self.cfg.mss) {
            if flags & SYN != 0 {
                clamp_mss(&mut p[..end], l4, mss, partial);
            }
        }
        self.remember_frag(true, &h, i, now);
        Inbound::Forward { to: in_ip, tag }
    }

    /// An ICMP error from outside about a packet we sent (inner packet:
    /// external endpoint -> remote).
    fn icmp_error_in(&mut self, now: u64, p: &mut [u8], h: &V4) -> Inbound {
        let o = h.ihl + 8;
        let Some(inner) = parse_quoted(&p[o..h.total]) else { return Inbound::NotOurs };
        if inner.src != h.dst {
            return Inbound::NotOurs;
        }
        let il4 = o + inner.ihl;
        let (ext_port, rem_port, port_at) = match inner.proto {
            TCP | UDP => (get16(p, il4), get16(p, il4 + 2), 0),
            ICMP if p[il4] == 8 => (get16(p, il4 + 4), 0, 4),
            _ => return Inbound::NotOurs,
        };
        let Some(i) = self.by_out.get(&key(inner.proto, inner.src, ext_port, inner.dst, rem_port)).copied() else {
            return Inbound::NotOurs;
        };
        if !self.live(i, now) {
            return Inbound::NotOurs;
        }
        if p[8] <= 1 {
            return Inbound::Drop(Drop::TtlExceeded);
        }
        let s = self.sessions[i as usize];
        let end = h.total;
        set_addr(&mut p[o..end], 12, s.in_ip);
        set_port(&mut p[o..end], inner.ihl, inner.proto, port_at, s.in_port, Some((inner.src, s.in_ip)), false);
        dec_ttl(p);
        set_addr(p, 16, s.in_ip);
        fix_icmp(p, h.ihl, end);
        Inbound::Forward { to: s.in_ip, tag: s.tag }
    }
}

fn port_key(proto: u8, ip: Ip, port: u16) -> u64 {
    (proto as u64) << 48 | (ip as u64) << 16 | port as u64
}

fn frag_key(inbound: bool, h: &V4) -> u128 {
    (inbound as u128) << 120 | key(h.proto, h.src, h.id, h.dst, 0)
}

/// The packet quoted in an ICMP error: a header and at least 8 bytes of L4.
fn parse_quoted(q: &[u8]) -> Option<V4> {
    if q.len() < 20 || q[0] >> 4 != 4 {
        return None;
    }
    let ihl = (q[0] & 15) as usize * 4;
    if ihl < 20 || q.len() < ihl + 8 || get16(q, 6) & 0x1FFF != 0 {
        return None;
    }
    Some(V4 { ihl, total: q.len(), proto: q[9], src: get32(q, 12), dst: get32(q, 16), id: 0, offset: 0, more: false })
}

/// Recompute an ICMP message's checksum (inner rewrites touch too much for
/// an incremental update to be simpler).
fn fix_icmp(p: &mut [u8], l4: usize, end: usize) {
    set16(p, l4 + 2, 0);
    let c = checksum(&p[l4..end]);
    set16(p, l4 + 2, c);
}

mod static_nat;
pub use static_nat::{PortForward, StaticNat, StaticStats};

#[cfg(test)]
mod tests;
