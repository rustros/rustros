//! Static (1:1) NAT with connection tracking: addresses change, ports and
//! protocols do not.
//!
//! * srcnat `host -> public`: what the host starts towards the outside leaves
//!   from `public`; the replies to `public` come back to the host.
//! * dstnat `public -> host`: what arrives for `public` goes to the host; the
//!   host's replies leave from that `public` again. Several public addresses
//!   (on several WANs) may lead to the same host: each connection answers
//!   from the address it came in on, and so (routed by source) out of the
//!   WAN it came in on.
//!
//! Connections are remembered by their inside tuple and by their public one;
//! replies follow their connection before any rule. Changing the rules does
//! not touch the connections in progress: they keep their translation until
//! they end (or time out), and the new rules apply to new connections only. ICMP errors follow the
//! connection of the packet they quote; later fragments follow their first.
//! A packet a rule names that cannot be tracked (table full) is still
//! translated by the rule.

use super::*;

const TCP_MS: u64 = 2 * 3600 * 1000;
const TCP_FIN_MS: u64 = 240_000;
const TCP_RST_MS: u64 = 10_000;
const UDP_MS: u64 = 300_000;
const ICMP_MS: u64 = 30_000;
const OTHER_MS: u64 = 600_000;
const MAX_CONNS: usize = 1 << 18;

#[derive(Clone, Copy, Default)]
struct Conn {
    proto: u8,
    host: Ip,
    public: Ip,
    /// the host's port, and the public one (they differ for a port
    /// forward that changes the port)
    hport: u16,
    pport: u16,
    remote: Ip,
    rport: u16,
    expires: u64,
    fin: bool,
    rst: bool,
}

impl Conn {
    fn in_key(&self) -> u128 {
        key(self.proto, self.host, self.hport, self.remote, self.rport)
    }
    fn pub_key(&self) -> u128 {
        key(self.proto, self.public, self.pport, self.remote, self.rport)
    }
    fn timeout(&self) -> u64 {
        match self.proto {
            TCP if self.rst => TCP_RST_MS,
            TCP if self.fin => TCP_FIN_MS,
            TCP => TCP_MS,
            UDP => UDP_MS,
            ICMP => ICMP_MS,
            _ => OTHER_MS,
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct StaticStats {
    /// connections tracked now
    pub conns: usize,
    /// packets translated
    pub packets: u64,
    /// connections that did not fit the table (translated by rule alone)
    pub untracked: u64,
}

/// A port forward: `proto` to `public` ports `ports.0..=ports.1` goes to
/// `host`, from port `hport` on (the same offset into the range).
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct PortForward {
    pub proto: u8,
    pub public: Ip,
    pub ports: (u16, u16),
    pub host: Ip,
    pub hport: u16,
}

pub struct StaticNat {
    /// (host, public) and (public, host), sorted by the first
    snat: Vec<(Ip, Ip)>,
    dnat: Vec<(Ip, Ip)>,
    /// port forwards (before `dnat`)
    fwd: Vec<PortForward>,
    conns: Vec<Conn>,
    free: Vec<u32>,
    by_in: Map<u128, u32>,
    by_pub: Map<u128, u32>,
    /// first fragments' translations, for the later ones: key -> (new address, source side, until)
    frags: Map<u128, (Ip, bool, u64)>,
    sweep: usize,
    pub stats: StaticStats,
}

/// Rewrite the destination (`src` false) or source address and port of a
/// TCP/UDP packet.
fn translate(p: &mut [u8], h: &V4, src: bool, addr: Ip, port: u16, partial: bool) {
    let (ao, po) = if src { (12, 0) } else { (16, 2) };
    let old = get32(p, ao);
    if get16(p, h.ihl + po) == port || h.offset != 0 || !matches!(h.proto, TCP | UDP) {
        rewrite(p, src, addr, partial);
        return;
    }
    set_addr(p, ao, addr);
    set_port(&mut p[..h.total], h.ihl, h.proto, po, port, Some((old, addr)), partial);
}

/// In an ICMP error at `h` (quoted packet at `q`), the quoted packet's
/// source (`src_side`) or destination port becomes `port`.
fn quoted_port(p: &mut [u8], h: &V4, q: usize, src_side: bool, port: u16) {
    let Some(qh) = parse_quoted(&p[q..h.total]) else { return };
    if matches!(qh.proto, TCP | UDP) {
        set_port(&mut p[q..h.total], qh.ihl, qh.proto, if src_side { 0 } else { 2 }, port, None, false);
        fix_icmp(p, h.ihl, h.total);
    }
}

fn find(rules: &[(Ip, Ip)], a: Ip) -> Option<Ip> {
    rules.binary_search_by_key(&a, |r| r.0).ok().map(|i| rules[i].1)
}

/// Ports of a TCP/UDP packet, or the identifier of an ICMP echo (as both).
fn ports(p: &[u8], h: &V4) -> Option<(u16, u16)> {
    let l4 = h.ihl;
    match h.proto {
        TCP | UDP if h.total >= l4 + 4 => Some((get16(p, l4), get16(p, l4 + 2))),
        ICMP if h.total >= l4 + 8 && matches!(p[l4], 0 | 8) => Some((get16(p, l4 + 4), get16(p, l4 + 4))),
        TCP | UDP | ICMP => None,
        _ => Some((0, 0)),
    }
}

impl StaticNat {
    pub fn new(seed: u64) -> StaticNat {
        let s = Seed(seed | 1);
        StaticNat {
            snat: Vec::new(),
            dnat: Vec::new(),
            fwd: Vec::new(),
            conns: Vec::new(),
            free: Vec::new(),
            by_in: Map::with_hasher(s),
            by_pub: Map::with_hasher(Seed(s.0.rotate_left(23))),
            frags: Map::with_hasher(Seed(s.0.rotate_left(37))),
            sweep: 0,
            stats: StaticStats::default(),
        }
    }

    /// New rules (srcnat, dstnat, port forwards), for new connections; those
    /// in progress keep their translation.
    pub fn set_all(&mut self, mut snat: Vec<(Ip, Ip)>, mut dnat: Vec<(Ip, Ip)>, mut fwd: Vec<PortForward>) {
        snat.sort_unstable();
        dnat.sort_unstable();
        fwd.sort_unstable();
        if snat == self.snat && dnat == self.dnat && fwd == self.fwd {
            return;
        }
        // the tracked connections stay: a removed or changed rule only
        // stops new connections; the ones in progress end by themselves
        (self.snat, self.dnat, self.fwd) = (snat, dnat, fwd);
    }

    pub fn is_empty(&self) -> bool {
        self.snat.is_empty() && self.dnat.is_empty() && self.fwd.is_empty()
    }

    /// Nothing to do: no rules, and no connections left from earlier ones
    /// (those go on after their rule is removed, until they end).
    pub fn idle(&self) -> bool {
        self.is_empty() && self.stats.conns == 0
    }

    pub fn forwards(&self) -> &[PortForward] {
        &self.fwd
    }

    pub fn rules(&self) -> (&[(Ip, Ip)], &[(Ip, Ip)]) {
        (&self.snat, &self.dnat)
    }

    fn lookup(&mut self, by_pub: bool, k: u128, now: u64) -> Option<u32> {
        let i = *if by_pub { self.by_pub.get(&k) } else { self.by_in.get(&k) }?;
        if self.conns[i as usize].expires > now {
            return Some(i);
        }
        self.remove(i);
        None
    }

    fn remove(&mut self, i: u32) {
        let c = self.conns[i as usize];
        self.by_in.remove(&c.in_key());
        self.by_pub.remove(&c.pub_key());
        self.conns[i as usize].proto = 0;
        self.free.push(i);
        self.stats.conns -= 1;
    }

    fn track(&mut self, now: u64, c: Conn) -> Option<u32> {
        if let Some(&i) = self.by_in.get(&c.in_key()) {
            // the same inside tuple through another public address: the newest wins
            self.remove(i);
        }
        if let Some(&i) = self.by_pub.get(&c.pub_key()) {
            self.remove(i);
        }
        if self.stats.conns >= MAX_CONNS {
            self.stats.untracked += 1;
            return None;
        }
        let i = match self.free.pop() {
            Some(i) => i,
            None => {
                self.conns.push(Conn::default());
                (self.conns.len() - 1) as u32
            }
        };
        self.conns[i as usize] = Conn { expires: now + c.timeout(), ..c };
        self.by_in.insert(c.in_key(), i);
        self.by_pub.insert(c.pub_key(), i);
        self.stats.conns += 1;
        Some(i)
    }

    /// A packet went through connection `i`: TCP state, idle timer.
    fn touch(&mut self, i: u32, now: u64, p: &[u8], h: &V4) {
        let c = &mut self.conns[i as usize];
        if c.proto == TCP && h.offset == 0 && h.total >= h.ihl + 14 {
            let flags = p[h.ihl + 13];
            c.fin |= flags & FIN != 0;
            c.rst |= flags & RST != 0;
        }
        c.expires = now + c.timeout();
    }

    /// Expire idle connections, looking at no more than `budget` of them.
    pub fn expire(&mut self, now: u64, budget: usize) {
        let n = self.conns.len();
        for _ in 0..budget.min(n) {
            self.sweep = (self.sweep + 1) % n;
            let c = &self.conns[self.sweep];
            if c.proto != 0 && c.expires <= now {
                self.remove(self.sweep as u32);
            }
        }
        if self.frags.len() > MAX_FRAGS / 2 {
            self.frags.retain(|_, f| f.2 > now);
        }
    }

    /// Translate an IPv4 packet if a connection or rule names it. `local`
    /// tells our own addresses: a host's traffic with us keeps its address.
    /// True if the packet was rewritten.
    /// `partial`: the TCP/UDP checksum is partial (offloads).
    pub fn process(&mut self, now: u64, p: &mut [u8], local: &dyn Fn(Ip) -> bool, partial: bool) -> bool {
        let Some(h) = parse(p) else { return false };
        let done = if h.offset != 0 {
            self.later_fragment(now, p, &h)
        } else if h.proto == ICMP && h.total >= h.ihl + 8 && matches!(p[h.ihl], 3 | 11 | 12) {
            self.icmp_error(now, p, &h)
        } else {
            self.packet(now, p, &h, local, partial)
        };
        if done {
            self.stats.packets += 1;
        }
        done
    }

    fn packet(&mut self, now: u64, p: &mut [u8], h: &V4, local: &dyn Fn(Ip) -> bool, partial: bool) -> bool {
        let Some((sp, dp)) = ports(p, h) else { return false };
        let (src, dst) = (h.src, h.dst);
        // towards a public address on a connection in progress: it keeps its
        // translation, whatever the rules say now (they may have changed)
        if let Some(i) = self.lookup(true, key(h.proto, dst, dp, src, sp), now) {
            self.touch(i, now, p, h);
            let c = self.conns[i as usize];
            if c.host == dst {
                return false; // a connection to the host's own address: as it is
            }
            translate(p, h, false, c.host, c.hport, partial);
            self.remember_fragment(now, h, c.host, false);
            return true;
        }
        // a port forward (a new connection)
        if let Some(f) = self.fwd.iter().find(|f| f.proto == h.proto && f.public == dst && (f.ports.0..=f.ports.1).contains(&dp)).copied() {
            let hp = f.hport.wrapping_add(dp - f.ports.0);
            let c = Conn { proto: h.proto, host: f.host, public: dst, hport: hp, pport: dp, remote: src, rport: sp, ..Conn::default() };
            if let Some(i) = self.track(now, c) {
                self.touch(i, now, p, h);
            }
            translate(p, h, false, f.host, hp, partial);
            self.remember_fragment(now, h, f.host, false);
            return true;
        }
        // a reply on a forwarded connection that changed the port
        if let Some(i) = self.lookup(false, key(h.proto, src, sp, dst, dp), now).filter(|&i| self.conns[i as usize].pport != sp) {
            self.touch(i, now, p, h);
            let c = self.conns[i as usize];
            translate(p, h, true, c.public, c.pport, partial);
            self.remember_fragment(now, h, c.public, true);
            return true;
        }
        // towards a public address with a dstnat rule (a new connection; a
        // reply to a srcnat connection was found above)
        if let Some(host) = find(&self.dnat, dst) {
            let c = Conn { proto: h.proto, host, public: dst, hport: dp, pport: dp, remote: src, rport: sp, ..Conn::default() };
            if let Some(i) = self.track(now, c) {
                self.touch(i, now, p, h);
            }
            if host == dst {
                return false; // a connection to the host's own address: as it is
            }
            rewrite(p, false, host, partial);
            self.remember_fragment(now, h, host, false);
            return true;
        }
        // someone reaching a srcnat host at its own address (routed, not by
        // a dstnat): the replies must come from that address, so remember
        // the connection as one not to translate
        if find(&self.snat, dst).is_some() {
            let c = Conn { proto: h.proto, host: dst, public: dst, hport: dp, pport: dp, remote: src, rport: sp, ..Conn::default() };
            if let Some(i) = self.track(now, c) {
                self.touch(i, now, p, h);
            }
            return false;
        }
        // from a host: a reply on a connection, or a srcnat rule
        let from = match self.lookup(false, key(h.proto, src, sp, dst, dp), now) {
            Some(i) => {
                self.touch(i, now, p, h);
                Some(self.conns[i as usize].public)
            }
            None => find(&self.snat, src).filter(|_| !local(dst)).inspect(|&public| {
                let c = Conn { proto: h.proto, host: src, public, hport: sp, pport: sp, remote: dst, rport: dp, ..Conn::default() };
                if let Some(i) = self.track(now, c) {
                    self.touch(i, now, p, h);
                }
            }),
        };
        if let Some(public) = from {
            if public == src {
                return false; // a reply on a connection made to the host's own address
            }
            rewrite(p, true, public, partial);
            self.remember_fragment(now, h, public, true);
            return true;
        }
        false
    }

    /// An ICMP error follows the connection of the packet it quotes.
    fn icmp_error(&mut self, now: u64, p: &mut [u8], h: &V4) -> bool {
        let q = h.ihl + 8;
        let quoted = parse_quoted(&p[q..h.total]).and_then(|qh| Some((qh, ports(&p[q..h.total], &qh)?)));
        if let Some((qh, (qsp, qdp))) = quoted {
            // about a packet that left from a public address: back to its host
            if let Some(i) = self.lookup(true, key(qh.proto, qh.src, qsp, qh.dst, qdp), now).filter(|_| h.dst == qh.src) {
                let c = self.conns[i as usize];
                rewrite(p, false, c.host, false);
                if c.hport != c.pport {
                    quoted_port(p, h, q, true, c.hport);
                }
                return true;
            }
            // a host's error about a packet it got: from the public address
            if let Some(i) = self.lookup(false, key(qh.proto, qh.dst, qdp, qh.src, qsp), now).filter(|_| h.src == qh.dst) {
                let c = self.conns[i as usize];
                rewrite(p, true, c.public, false);
                if c.hport != c.pport {
                    quoted_port(p, h, q, false, c.pport);
                }
                return true;
            }
        }
        if let Some(host) = find(&self.dnat, h.dst) {
            rewrite(p, false, host, false);
            return true;
        }
        if let Some(public) = find(&self.snat, h.src) {
            rewrite(p, true, public, false);
            return true;
        }
        false
    }

    fn frag_key(h: &V4) -> u128 {
        key(h.proto, h.src, h.id, h.dst, 0)
    }

    fn remember_fragment(&mut self, now: u64, h: &V4, new: Ip, src_side: bool) {
        if h.more && self.frags.len() < MAX_FRAGS {
            self.frags.insert(Self::frag_key(h), (new, src_side, now + FRAG_MS));
        }
    }

    fn later_fragment(&mut self, now: u64, p: &mut [u8], h: &V4) -> bool {
        let Some(&(new, src_side, until)) = self.frags.get(&Self::frag_key(h)) else { return false };
        if until <= now {
            return false;
        }
        rewrite(p, src_side, new, false);
        true
    }
}
