//! IPv4 router: forwards packets between interfaces (NICs and VLANs) by the
//! system's routes (connected networks, `ip route`, gateways), in place on
//! the packet path: TTL down, checksum adjusted, Ethernet header rewritten.
//! Answers with ICMP when it cannot: time exceeded, fragmentation needed
//! (it does not fragment), network unreachable.
//!
//! It runs after the translating modules (NAT, L2TP), so their traffic is
//! theirs; what they leave and is not for us is routed here.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Frame, Module, Packet, Sys, Verdict};
use rustros_util::wire::{Ip, checksum};
use nat_core::icmp_error;

const ETH: usize = 14;
const RELOAD_MS: u64 = 2000;

#[derive(Clone, Copy, Default)]
struct Nic {
    mac: [u8; 6],
    ip: Ip,
    mask: Ip,
    mtu: usize,
}

#[derive(Default)]
pub struct Router {
    nics: Vec<Nic>,
    /// our addresses, sorted: traffic to them is not forwarded
    local: Vec<Ip>,
    reload_at: u64,
    forwarded: u64,
    dropped: u64,
    icmp: u64,
}

fn be16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

fn ip_at(p: &[u8], o: usize) -> Ip {
    u32::from_be_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
}

impl Router {
    pub fn new() -> Router {
        Router::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        self.nics = (0..net.nic_count())
            .filter_map(|i| net.nic_info(i))
            .map(|n| Nic { mac: n.mac, ip: n.ip, mask: n.mask, mtu: n.mtu })
            .collect();
        self.local = (0..net.nic_count()).flat_map(|i| net.extra_addrs(i)).chain(self.nics.iter().map(|n| n.ip)).filter(|&a| a != 0).collect();
        self.local.sort_unstable();
    }

    /// ICMP error about the packet in `f`, from our address on the NIC it came in on.
    fn icmp(&mut self, pk: &mut dyn Packet, f: &mut Frame, typ: u8, code: u8, mtu: u16) {
        let from = self.nics.get(f.nic as usize).map_or(0, |n| n.ip);
        if from != 0 {
            if let Some(e) = icmp_error(from, &f.data()[ETH..], typ, code, mtu) {
                pk.send_packet(&e);
                self.icmp += 1;
            }
        }
        f.verdict = Verdict::Drop;
        self.dropped += 1;
    }

    fn frame(&mut self, pk: &mut dyn Packet, f: &mut Frame) {
        let Some(me) = self.nics.get(f.nic as usize).copied() else { return };
        let d = f.data();
        // unicast IPv4 to our MAC, with a sound header
        if d.len() < ETH + 20 || d[12..14] != [8, 0] || d[..6] != me.mac || d[ETH] >> 4 != 4 {
            return;
        }
        let ihl = (d[ETH] & 15) as usize * 4;
        let total = be16(d, ETH + 2) as usize;
        if ihl < 20 || total < ihl || ETH + total > d.len() || checksum(&d[ETH..ETH + ihl], 0) != 0 {
            return;
        }
        let (src, dst) = (ip_at(d, ETH + 12), ip_at(d, ETH + 16));
        // for us, broadcast or multicast: not routed
        if self.local.binary_search(&dst).is_ok() || dst >= 0xE000_0000 || src == 0 {
            return;
        }
        if self.nics.iter().any(|n| n.ip != 0 && n.mask != !0 && dst == n.ip | !n.mask) {
            return;
        }
        // by source too: a public address leaves through its own WAN
        let Some((out, hop)) = pk.route_from(src, dst) else {
            return self.icmp(pk, f, 3, 0, 0); // network unreachable
        };
        let Some(nic) = self.nics.get(out).copied() else { return };
        if d[ETH + 8] <= 1 {
            return self.icmp(pk, f, 11, 0, 0); // time exceeded
        }
        if total > nic.mtu {
            if be16(d, ETH + 6) & 0x4000 != 0 {
                return self.icmp(pk, f, 3, 4, nic.mtu as u16); // fragmentation needed
            }
            f.verdict = Verdict::Drop; // we do not fragment
            self.dropped += 1;
            return;
        }
        // TTL down, checksum adjusted (RFC 1624)
        let p = f.data_mut();
        let old = be16(p, ETH + 8);
        p[ETH + 8] -= 1;
        let new = be16(p, ETH + 8);
        let mut sum = (!be16(p, ETH + 10)) as u32 + (!old) as u32 + new as u32;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        p[ETH + 10..ETH + 12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        match pk.neighbor(out, hop) {
            Some(mac) => {
                let p = f.data_mut();
                p[..6].copy_from_slice(&mac);
                p[6..12].copy_from_slice(&nic.mac);
                f.set_len(ETH + total);
                f.nic = out as u8;
                f.verdict = Verdict::Transmit;
            }
            None => {
                // the next hop is not resolved yet: the system queues it
                pk.send_packet(&f.data()[ETH..ETH + total]);
                f.verdict = Verdict::Consumed;
            }
        }
        self.forwarded += 1;
    }
}

impl Module for Router {
    fn name(&self) -> &'static str {
        "router"
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::PACKET
    }

    fn order(&self) -> i32 {
        100 // after NAT and tunnels
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
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        let Some(pk) = sys.packet() else { return };
        for f in frames.iter_mut() {
            self.frame(pk, f);
        }
    }

    fn status(&self) -> String {
        format!("{} forwarded, {} dropped, {} ICMP errors sent", self.forwarded, self.dropped, self.icmp)
    }
}
