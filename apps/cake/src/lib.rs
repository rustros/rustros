//! CAKE-style shaping for an interface's egress and ingress: a shaper at a
//! set rate (so the queue builds here, not in the provider's equipment),
//! flow queueing with DRR++ (new flows first, then fair shares), and CoDel
//! on every flow (marks ECN-capable packets, drops the others) to keep the
//! queueing delay near 5 ms.
//!
//! Egress takes frames in the egress hook and sends them when their time
//! comes; ingress takes frames first thing on the packet path and puts them
//! back (for NAT, tunnels, the router) at the shaped rate.
//!
//! Settings (`cfg cake <key> <value>`):
//!
//! ```text
//! egress.<if>    100mbit     shape what leaves <if> (nic1: the NIC and its VLANs)
//! ingress.<if>   200mbit     shape what arrives on <if>
//! overhead       0           bytes added per packet for the rate (link framing)
//! limit          4194304     queue bytes per shaper
//! ```
//!
//! Not shaped: ARP and anything else not IPv4, and TCP port 9000 (the
//! updater: the way in stays open whatever happens here).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Frame, Module, Param, Sys, Verdict, say};

const ETH: usize = 14;
const FLOWS: usize = 1024;
const QUANTUM: i32 = 1514;
const TARGET_NS: u64 = 5_000_000;
const INTERVAL_NS: u64 = 100_000_000;
const RELOAD_MS: u64 = 2000;
/// Place on the packet path: before NAT, tunnels and the router.
const ORDER: i32 = -100;
const UPDATER_PORT: u16 = 9000;

pub struct Pkt {
    pub data: Vec<u8>,
    /// offloads still pending on it (a big segment counts with all its bytes)
    pub offload: rustros_api::Offload,
    /// the interface it goes out of (egress) or came in on (ingress)
    pub nic: u8,
    enq_ns: u64,
}

#[derive(Default)]
struct Codel {
    count: u32,
    dropping: bool,
    first_above: u64,
    drop_next: u64,
}

fn isqrt(n: u32) -> u32 {
    let mut x = n.max(1);
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x.max(1)
}

impl Codel {
    fn control_law(&self, t: u64) -> u64 {
        t + INTERVAL_NS / isqrt(self.count) as u64
    }

    /// RFC 8289: whether this packet, `sojourn` ns old, should go.
    fn verdict(&mut self, now: u64, sojourn: u64, backlog: u32) -> bool {
        let above = if sojourn < TARGET_NS || backlog <= QUANTUM as u32 {
            self.first_above = 0;
            false
        } else if self.first_above == 0 {
            self.first_above = now + INTERVAL_NS;
            false
        } else {
            now >= self.first_above
        };
        if self.dropping {
            if !above {
                self.dropping = false;
                return false;
            }
            if now >= self.drop_next {
                self.count += 1;
                self.drop_next = self.control_law(self.drop_next);
                return true;
            }
            false
        } else if above {
            self.dropping = true;
            self.count = if self.count > 2 && now.saturating_sub(self.drop_next) < 16 * INTERVAL_NS { self.count - 2 } else { 1 };
            self.drop_next = self.control_law(now);
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Flow {
    q: VecDeque<Pkt>,
    backlog: u32,
    deficit: i32,
    /// 0 idle, 1 in new_flows, 2 in old_flows
    list: u8,
    codel: Codel,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub sent_bytes: u64,
    pub aqm_drops: u64,
    pub marks: u64,
    pub overflow_drops: u64,
}

/// One shaper: rate, flows, the clock.
pub struct Shaper {
    rate_bps: u64,
    overhead: u32,
    limit: u32,
    flows: Vec<Flow>,
    new_flows: VecDeque<u16>,
    old_flows: VecDeque<u16>,
    backlog: u32,
    next_ns: u64,
    pub stats: Stats,
}

/// Flow of an Ethernet frame carrying IPv4: addresses, protocol, ports.
fn flow_of(f: &[u8]) -> usize {
    if f.len() < ETH + 20 {
        return 0;
    }
    let rd = |i: usize| u32::from_be_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]);
    let mut h = rd(ETH + 12) ^ rd(ETH + 16).rotate_left(13) ^ (f[ETH + 9] as u32).rotate_left(26);
    let l4 = ETH + (f[ETH] & 15) as usize * 4;
    if matches!(f[ETH + 9], 6 | 17) && f.len() >= l4 + 4 {
        h ^= rd(l4).rotate_left(7);
    }
    h ^= h >> 15;
    h = h.wrapping_mul(0x2c1b_3c6d);
    h ^= h >> 12;
    h as usize % FLOWS
}

/// Mark Congestion Experienced if the packet is ECN-capable; false if not.
fn mark_ce(f: &mut [u8]) -> bool {
    if f.len() < ETH + 20 || f[ETH + 1] & 3 == 0 {
        return false;
    }
    if f[ETH + 1] & 3 == 3 {
        return true; // already marked
    }
    let old = u16::from_be_bytes([f[ETH], f[ETH + 1]]);
    f[ETH + 1] |= 3;
    let new = u16::from_be_bytes([f[ETH], f[ETH + 1]]);
    let c = u16::from_be_bytes([f[ETH + 10], f[ETH + 11]]);
    let mut s = (!c) as u32 + (!old) as u32 + new as u32;
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    f[ETH + 10..ETH + 12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    true
}

impl Shaper {
    pub fn new(rate_bps: u64, overhead: u32, limit: u32) -> Shaper {
        Shaper {
            rate_bps: rate_bps.max(64_000),
            overhead,
            limit,
            flows: (0..FLOWS).map(|_| Flow::default()).collect(),
            new_flows: VecDeque::new(),
            old_flows: VecDeque::new(),
            backlog: 0,
            next_ns: 0,
            stats: Stats::default(),
        }
    }

    pub fn set(&mut self, rate_bps: u64, overhead: u32, limit: u32) {
        self.rate_bps = rate_bps.max(64_000);
        self.overhead = overhead;
        self.limit = limit;
    }

    pub fn rate(&self) -> u64 {
        self.rate_bps
    }

    pub fn backlog(&self) -> u32 {
        self.backlog
    }

    pub fn active_flows(&self) -> usize {
        self.new_flows.len() + self.old_flows.len()
    }

    pub fn enqueue(&mut self, now: u64, data: Vec<u8>, offload: rustros_api::Offload, nic: u8) {
        let i = flow_of(&data);
        let len = data.len() as u32;
        let f = &mut self.flows[i];
        f.q.push_back(Pkt { data, offload, nic, enq_ns: now });
        f.backlog += len;
        self.backlog += len;
        if f.list == 0 {
            f.list = 1;
            f.deficit = QUANTUM;
            self.new_flows.push_back(i as u16);
        }
        // over the limit: the fattest flow pays
        while self.backlog > self.limit {
            let Some(&fat) = self.new_flows.iter().chain(self.old_flows.iter()).max_by_key(|&&j| self.flows[j as usize].backlog) else { break };
            let f = &mut self.flows[fat as usize];
            let Some(p) = f.q.pop_front() else { break };
            f.backlog -= p.data.len() as u32;
            self.backlog -= p.data.len() as u32;
            self.stats.overflow_drops += 1;
        }
    }

    /// DRR++ with CoDel: the next packet to send (dropped ones are gone).
    fn dequeue(&mut self, now: u64) -> Option<Pkt> {
        loop {
            let (i, from_new) = match self.new_flows.front() {
                Some(&i) => (i, true),
                None => (*self.old_flows.front()?, false),
            };
            let f = &mut self.flows[i as usize];
            if f.deficit <= 0 {
                f.deficit += QUANTUM;
                f.list = 2;
                if from_new {
                    self.new_flows.pop_front();
                } else {
                    self.old_flows.pop_front();
                }
                self.old_flows.push_back(i);
                continue;
            }
            let Some(mut p) = f.q.pop_front() else {
                // empty: a new flow gets a turn among the old ones first
                if from_new {
                    self.new_flows.pop_front();
                    if self.old_flows.is_empty() {
                        f.list = 0;
                    } else {
                        f.list = 2;
                        self.old_flows.push_back(i);
                    }
                } else {
                    self.old_flows.pop_front();
                    f.list = 0;
                }
                continue;
            };
            let len = p.data.len() as u32;
            f.backlog -= len;
            self.backlog -= len;
            if f.codel.verdict(now, now.saturating_sub(p.enq_ns), f.backlog + len) {
                if mark_ce(&mut p.data) {
                    self.stats.marks += 1;
                } else {
                    self.stats.aqm_drops += 1;
                    continue;
                }
            }
            f.deficit -= len as i32;
            return Some(p);
        }
    }

    /// The packets whose time has come at `now` (ns).
    pub fn release(&mut self, now: u64, out: &mut Vec<Pkt>) {
        // no credit saved up while idle: at most a packet's worth of burst
        if self.next_ns + 1_000_000 < now {
            self.next_ns = now;
        }
        while self.next_ns <= now {
            let Some(p) = self.dequeue(now) else { break };
            let bits = (p.data.len() as u64 + self.overhead as u64) * 8;
            self.next_ns += bits * 1_000_000_000 / self.rate_bps;
            self.stats.sent += 1;
            self.stats.sent_bytes += p.data.len() as u64;
            out.push(p);
        }
    }
}

/// "100mbit", "100M", "1.5gbit", "512kbit", "100000000" -> bits per second.
pub fn parse_rate(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let s = s.trim_end_matches("bit").trim_end_matches("bps").trim_end_matches("/s");
    let (num, mul) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1_000),
        'm' => (&s[..s.len() - 1], 1_000_000),
        'g' => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s, 1),
    };
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    let mut v = int.parse::<u64>().ok()? * mul;
    if !frac.is_empty() {
        let digits = frac.len().min(6) as u32;
        v += frac[..digits as usize].parse::<u64>().ok()? * mul / 10u64.pow(digits);
    }
    (v >= 64_000).then_some(v)
}

fn fmt_rate(bps: u64) -> String {
    if bps >= 1_000_000_000 && bps % 1_000_000 == 0 {
        format!("{}.{}Gbit", bps / 1_000_000_000, bps / 100_000_000 % 10)
    } else {
        format!("{}Mbit", bps / 1_000_000)
    }
}

/// Frames that are never shaped: not IPv4, or the updater's TCP port.
fn exempt(f: &[u8]) -> bool {
    if f.len() < ETH + 20 || f[12..14] != [8, 0] {
        return true;
    }
    let l4 = ETH + (f[ETH] & 15) as usize * 4;
    f[ETH + 9] == 6 && f.len() >= l4 + 4 && (u16::from_be_bytes([f[l4], f[l4 + 1]]) == UPDATER_PORT || u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]) == UPDATER_PORT)
}

struct Instance {
    /// "nic1" (the NIC and its VLANs) or "nic1.109"
    iface: String,
    egress: bool,
    shaper: Shaper,
}

#[derive(Default)]
pub struct Cake {
    instances: Vec<Instance>,
    /// by interface: instance for egress, for ingress
    egress_of: Vec<Option<usize>>,
    ingress_of: Vec<Option<usize>>,
    applied: String,
    reload_at: u64,
    /// ingress frames the kernel would not take back
    inject_drops: u64,
    out: Vec<Pkt>,
}

impl Cake {
    pub fn new() -> Cake {
        Cake::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        let names: Vec<String> = sys.net().map(|n| (0..n.nic_count()).map(|i| n.nic_name(i)).collect()).unwrap_or_default();
        let Some(kv) = sys.kv() else { return };
        let mut settings: Vec<(String, String)> = kv
            .keys("cfg/")
            .into_iter()
            .filter_map(|k| {
                let v = kv.get(&k)?;
                Some((String::from(&k[4..]), String::from_utf8_lossy(&v).into_owned()))
            })
            .collect();
        settings.sort();
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).chain(names.iter().map(|n| format!("{n};"))).collect();
        if text == self.applied {
            return;
        }
        let get = |k: &str| settings.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());
        let overhead = get("overhead").and_then(|v| v.parse().ok()).unwrap_or(0u32).min(256);
        let limit = get("limit").and_then(|v| v.parse().ok()).unwrap_or(4u32 << 20).clamp(64 << 10, 64 << 20);
        let mut keep: Vec<Instance> = Vec::new();
        for (k, v) in &settings {
            let (egress, iface) = match k.split_once('.') {
                Some(("egress", i)) => (true, i),
                Some(("ingress", i)) => (false, i),
                _ => continue,
            };
            let Some(rate) = parse_rate(v) else {
                say!(sys, "cake: {}: bad rate '{}' (e.g. 100mbit)\n", k, v);
                continue;
            };
            // keep a running shaper (and its queue) when only numbers change
            let mut shaper = match self.instances.iter().position(|x| x.iface == iface && x.egress == egress) {
                Some(p) => self.instances.swap_remove(p).shaper,
                None => Shaper::new(rate, overhead, limit),
            };
            shaper.set(rate, overhead, limit);
            keep.push(Instance { iface: String::from(iface), egress, shaper });
        }
        self.instances = keep;
        // which interfaces each one covers
        let covers = |want: &str, name: &str| name == want || (name.starts_with(want) && name[want.len()..].starts_with('.'));
        self.egress_of = names.iter().map(|n| self.instances.iter().position(|x| x.egress && covers(&x.iface, n))).collect();
        self.ingress_of = names.iter().map(|n| self.instances.iter().position(|x| !x.egress && covers(&x.iface, n))).collect();
        for x in &self.instances {
            say!(sys, "cake: {} {} {}\n", x.iface, if x.egress { "egress" } else { "ingress" }, fmt_rate(x.shaper.rate()));
        }
        if self.instances.is_empty() {
            say!(sys, "cake: nothing to shape (cfg cake egress.nic1 100mbit)\n");
        }
        self.applied = text;
    }

    /// Send what is due.
    fn release(&mut self, sys: &mut dyn Sys) {
        if self.instances.is_empty() {
            return;
        }
        let now = sys.now_us() * 1000;
        let Some(pk) = sys.packet() else { return };
        let mut out = core::mem::take(&mut self.out);
        for x in self.instances.iter_mut() {
            x.shaper.release(now, &mut out);
            for p in out.drain(..) {
                if x.egress {
                    pk.send_frame_offload(p.nic as usize, &p.data, p.offload);
                } else if !pk.inject(p.nic as usize, &p.data, p.offload, ORDER) {
                    self.inject_drops += 1;
                }
            }
        }
        self.out = out;
    }

    fn take(&mut self, now: u64, f: &mut Frame, which: Option<usize>) {
        let Some(i) = which else { return };
        if exempt(f.data()) {
            return;
        }
        self.instances[i].shaper.enqueue(now, f.data().to_vec(), f.offload, f.nic);
        f.verdict = Verdict::Consumed;
    }
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "overhead", kind: "number", default: "0", help: "bytes added per packet for the rate (link framing)" },
    Param { key: "limit", kind: "number", default: "4194304", help: "queue bytes per shaper" },
    Param { key: "egress.<if>", kind: "text", default: "", help: "shape what leaves the interface, e.g. 100mbit" },
    Param { key: "ingress.<if>", kind: "text", default: "", help: "shape what arrives on the interface, e.g. 200mbit" },
];

impl Module for Cake {
    fn name(&self) -> &'static str {
        "cake"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::PACKET
    }

    fn order(&self) -> i32 {
        ORDER
    }

    /// Big segments are shaped by their bytes and sent on as they are.
    fn offloads(&self) -> bool {
        true
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        self.release(sys);
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.ingress_of.iter().all(Option::is_none) {
            return;
        }
        let now = sys.now_us() * 1000;
        for f in frames.iter_mut() {
            let which = self.ingress_of.get(f.nic as usize).copied().flatten();
            self.take(now, f, which);
        }
        self.release(sys);
    }

    fn on_egress(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        if self.egress_of.iter().all(Option::is_none) {
            return;
        }
        let now = sys.now_us() * 1000;
        for f in frames.iter_mut() {
            let which = self.egress_of.get(f.nic as usize).copied().flatten();
            self.take(now, f, which);
        }
        self.release(sys);
    }

    fn status(&self) -> String {
        if self.instances.is_empty() {
            return String::from("idle (cfg cake egress.nic1 100mbit)");
        }
        let mut s: Vec<String> = self
            .instances
            .iter()
            .map(|x| {
                let st = x.shaper.stats;
                format!(
                    "{} {} {}: {} KB queued, {} flows, sent {}, dropped {}+{}, marked {}",
                    x.iface,
                    if x.egress { "out" } else { "in" },
                    fmt_rate(x.shaper.rate()),
                    x.shaper.backlog() / 1024,
                    x.shaper.active_flows(),
                    st.sent,
                    st.aqm_drops,
                    st.overflow_drops,
                    st.marks
                )
            })
            .collect();
        if self.inject_drops > 0 {
            s.push(format!("{} ingress frames not taken back", self.inject_drops));
        }
        s.join("; ")
    }
}

#[cfg(test)]
mod tests;
