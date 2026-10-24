//! Built-in DHCPv4 client (RFC 2131). It only acts when the system came up
//! without any address (on no interface: none in the image, none saved with
//! `save`): then it
//! obtains one, renews the lease at T1 (unicast) and T2 (broadcast), and
//! starts over when the lease runs out or the server says NAK. If someone
//! sets an address by hand meanwhile, it steps aside for good.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use rustros_api::socket::{SockAddr, Socket};
use rustros_api::{Admin, Caps, IfConf, Module, Sys, say};
use rustros_util::wire::{BROADCAST, Ip, IpFmt};

const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
const MAGIC: [u8; 4] = [99, 130, 83, 99];

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

/// Retransmission: 4, 8, 16, 32, 32 ... seconds (plus up to 1 s jitter).
const RETRY_MIN_MS: u64 = 4000;
const RETRY_MAX_MS: u64 = 32_000;
/// No reply to a REQUEST within this long: start over with DISCOVER.
const REQUEST_TIMEOUT_MS: u64 = 20_000;

/// What a server said.
/// Change NIC 0's settings in the configuration in effect (the rest stays).
fn set_nic0(admin: &mut dyn Admin, f: impl FnOnce(&mut IfConf)) {
    let mut conf = admin.net_running();
    if let Some(c) = conf.ifs.get_mut(0) {
        f(c);
    }
    let _ = admin.net_set_running(&conf);
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Reply {
    pub kind: u8,
    pub xid: u32,
    pub yiaddr: Ip,
    pub server: Ip,
    pub mask: Ip,
    pub router: Ip,
    pub dns: Vec<Ip>,
    pub mtu: u16,
    /// seconds
    pub lease: u32,
    pub t1: u32,
    pub t2: u32,
}

/// Build a client message. `requested`/`server` are 0 when not sent;
/// `ciaddr` is our address when renewing.
pub fn build(kind: u8, xid: u32, mac: [u8; 6], ciaddr: Ip, requested: Ip, server: Ip, hostname: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![0u8; 240];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    if ciaddr == 0 {
        p[10] = 0x80; // broadcast flag: we cannot receive unicast yet
    }
    p[12..16].copy_from_slice(&ciaddr.to_be_bytes());
    p[28..34].copy_from_slice(&mac);
    p[236..240].copy_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, kind]);
    // client identifier: hardware type + MAC
    p.extend_from_slice(&[61, 7, 1]);
    p.extend_from_slice(&mac);
    if requested != 0 {
        p.extend_from_slice(&[50, 4]);
        p.extend_from_slice(&requested.to_be_bytes());
    }
    if server != 0 {
        p.extend_from_slice(&[54, 4]);
        p.extend_from_slice(&server.to_be_bytes());
    }
    if !hostname.is_empty() {
        p.push(12);
        p.push(hostname.len().min(63) as u8);
        p.extend_from_slice(&hostname[..hostname.len().min(63)]);
    }
    // parameter request list: mask, router, DNS, MTU, lease, server, T1, T2
    p.extend_from_slice(&[55, 8, 1, 3, 6, 26, 51, 54, 58, 59]);
    p.push(255);
    p.resize(p.len().max(300), 0);
    p
}

fn ip_at(b: &[u8]) -> Ip {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse a server message addressed to us (`xid`, `mac`); None for anything else.
pub fn parse(p: &[u8], xid: u32, mac: [u8; 6]) -> Option<Reply> {
    if p.len() < 240 || p[0] != 2 || p[1] != 1 || p[2] != 6 || p[236..240] != MAGIC {
        return None;
    }
    if ip_at(&p[4..8]) != xid || p[28..34] != mac {
        return None;
    }
    let mut r = Reply { xid, yiaddr: ip_at(&p[16..20]), ..Reply::default() };
    let mut o = &p[240..];
    while let [code, rest @ ..] = o {
        match code {
            0 => o = rest,
            255 => break,
            _ => {
                let (&len, rest) = rest.split_first()?;
                let v = rest.get(..len as usize)?;
                match (code, len) {
                    (53, 1) => r.kind = v[0],
                    (1, 4) => r.mask = ip_at(v),
                    (3, l) if l >= 4 => r.router = ip_at(v),
                    (6, l) if l >= 4 => r.dns = v.chunks_exact(4).map(ip_at).collect(),
                    (26, 2) => r.mtu = u16::from_be_bytes([v[0], v[1]]),
                    (51, 4) => r.lease = ip_at(v),
                    (54, 4) => r.server = ip_at(v),
                    (58, 4) => r.t1 = ip_at(v),
                    (59, 4) => r.t2 = ip_at(v),
                    _ => {}
                }
                o = &rest[len as usize..];
            }
        }
    }
    (r.kind != 0).then_some(r)
}

/// Renewal times (ms after the lease was granted): (T1, T2, expiry).
pub fn timers(r: &Reply) -> (u64, u64, u64) {
    let lease = (r.lease.max(60) as u64) * 1000; // treat absurdly short leases as a minute
    let t1 = if r.t1 != 0 { r.t1 as u64 * 1000 } else { lease / 2 };
    let t2 = if r.t2 != 0 { r.t2 as u64 * 1000 } else { lease / 8 * 7 };
    (t1.min(lease), t2.clamp(t1.min(lease), lease), lease)
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Address configured by someone else: nothing to do.
    Off,
    Selecting { retry_at: u64, backoff: u64 },
    Requesting { offer: Reply, sent_at: u64, retry_at: u64 },
    Bound { lease: Reply, at: u64, next: u64 },
}

pub struct Dhcp {
    sock: Option<Socket>,
    state: State,
    xid: u32,
    mac: [u8; 6],
    hostname: Vec<u8>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Dhcp {
    pub fn new() -> Dhcp {
        Dhcp { sock: None, state: State::Off, xid: 0, mac: [0; 6], hostname: Vec::new() }
    }

    fn send(&mut self, sys: &mut dyn Sys, to: Ip, kind: u8, ciaddr: Ip, requested: Ip, server: Ip) {
        let pkt = build(kind, self.xid, self.mac, ciaddr, requested, server, &self.hostname);
        let (Some(sock), Some(net)) = (self.sock, sys.net()) else { return };
        let _ = net.sendto(sock, &pkt, 0, Some(&SockAddr::v4(to, SERVER_PORT)));
    }

    fn discover(&mut self, sys: &mut dyn Sys, backoff: u64) {
        self.xid = sys.random() as u32;
        self.send(sys, BROADCAST, DISCOVER, 0, 0, 0);
        let now = sys.now_ms();
        let jitter = sys.random() % 1000;
        self.state = State::Selecting { retry_at: now + backoff + jitter, backoff: (backoff * 2).min(RETRY_MAX_MS) };
    }

    fn apply(&mut self, sys: &mut dyn Sys, r: &Reply) {
        let Some(admin) = sys.admin() else { return };
        set_nic0(admin, |c| {
            (c.ip, c.mask, c.gw) = (r.yiaddr, r.mask, r.router);
            if r.mtu >= 576 {
                c.mtu = r.mtu.min(1500);
            }
        });
    }

    fn handle(&mut self, sys: &mut dyn Sys, r: Reply) {
        let now = sys.now_ms();
        match (&self.state, r.kind) {
            (State::Selecting { .. }, OFFER) if r.yiaddr != 0 => {
                self.send(sys, BROADCAST, REQUEST, 0, r.yiaddr, r.server);
                self.state = State::Requesting { offer: r, sent_at: now, retry_at: now + RETRY_MIN_MS };
            }
            (State::Requesting { .. } | State::Bound { .. }, ACK) if r.yiaddr != 0 => {
                let fresh = !matches!(&self.state, State::Bound { lease, .. } if lease.yiaddr == r.yiaddr);
                self.apply(sys, &r);
                if fresh {
                    say!(
                        sys,
                        "dhcp: {}/{} gw {} from {}, lease {} s\n",
                        IpFmt(r.yiaddr),
                        r.mask.count_ones(),
                        IpFmt(r.router),
                        IpFmt(r.server),
                        r.lease
                    );
                }
                let (t1, _, _) = timers(&r);
                self.state = State::Bound { lease: r, at: now, next: now + t1 };
            }
            (State::Requesting { .. } | State::Bound { .. }, NAK) => {
                say!(sys, "dhcp: NAK from {}, starting over\n", IpFmt(r.server));
                if let Some(a) = sys.admin() {
                    set_nic0(a, |c| (c.ip, c.mask, c.gw) = (0, 0, 0));
                }
                self.discover(sys, RETRY_MIN_MS);
            }
            _ => {}
        }
    }

    fn tick(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        match &self.state {
            State::Off => {}
            State::Selecting { retry_at, backoff } if now >= *retry_at => {
                let b = *backoff;
                self.discover(sys, b);
            }
            State::Requesting { offer, sent_at, retry_at } if now >= *retry_at => {
                if now - sent_at > REQUEST_TIMEOUT_MS {
                    self.discover(sys, RETRY_MIN_MS);
                } else {
                    let (ip, server) = (offer.yiaddr, offer.server);
                    self.send(sys, BROADCAST, REQUEST, 0, ip, server);
                    if let State::Requesting { retry_at, .. } = &mut self.state {
                        *retry_at = now + RETRY_MIN_MS;
                    }
                }
            }
            State::Bound { lease, at, next } if now >= *next => {
                let (_, t2, expiry) = timers(lease);
                let elapsed = now - at;
                let (ip, server) = (lease.yiaddr, lease.server);
                if elapsed >= expiry {
                    say!(sys, "dhcp: lease on {} expired, starting over\n", IpFmt(ip));
                    if let Some(a) = sys.admin() {
                        set_nic0(a, |c| (c.ip, c.mask, c.gw) = (0, 0, 0));
                    }
                    self.discover(sys, RETRY_MIN_MS);
                    return;
                }
                // renewing (unicast to the server) until T2, then rebinding (broadcast)
                let to = if elapsed < t2 { server } else { BROADCAST };
                self.send(sys, to, REQUEST, ip, 0, 0);
                // retry at half the remaining time to the next deadline, at least a minute apart
                let deadline = if elapsed < t2 { t2 } else { expiry };
                let left = deadline - elapsed;
                let wait = (left / 2).max(60_000).min(left);
                if let State::Bound { next, .. } = &mut self.state {
                    *next = now + wait;
                }
            }
            _ => {}
        }
    }
}

impl Module for Dhcp {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::ADMIN
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        let info = net.net_info();
        // static configuration somewhere (e.g. only on a VLAN): leave it be
        if (0..net.nic_count()).any(|i| net.nic_info(i).is_some_and(|n| n.ip != 0)) {
            return;
        }
        self.mac = info.mac;
        self.hostname = alloc::format!("rustros-{:02x}{:02x}{:02x}", info.mac[3], info.mac[4], info.mac[5]).into_bytes();
        match rustros_util::sock::udp_bind(net, CLIENT_PORT) {
            Ok(s) => self.sock = Some(s),
            Err(e) => {
                say!(sys, "dhcp: cannot bind port {}: {:?}\n", CLIENT_PORT, e);
                return;
            }
        }
        say!(sys, "dhcp: no address configured, asking for one\n");
        self.discover(sys, RETRY_MIN_MS);
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        if self.state == State::Off {
            return;
        }
        // someone configured the address by hand: step aside
        let current = sys.net().map_or(0, |n| n.net_info().ip);
        let ours = match &self.state {
            State::Bound { lease, .. } => lease.yiaddr,
            _ => 0,
        };
        if current != 0 && current != ours {
            say!(sys, "dhcp: address set by hand ({}), stopping\n", IpFmt(current));
            if let (Some(s), Some(net)) = (self.sock.take(), sys.net()) {
                let _ = net.close(s);
            }
            self.state = State::Off;
            return;
        }
        let mut buf = [0u8; 1500];
        while let (Some(sock), Some(net)) = (self.sock, sys.net()) {
            let Ok((n, from)) = net.recvfrom(sock, &mut buf, 0) else { break };
            if from.map(|a| a.port()) != Some(SERVER_PORT) {
                continue;
            }
            if let Some(r) = parse(&buf[..n], self.xid, self.mac) {
                self.handle(sys, r);
            }
        }
        self.tick(sys);
    }
}

#[cfg(test)]
mod tests;
