//! Byte-level helpers shared by the protocol modules.

use core::fmt;
use core::fmt::Write;

pub use rustros_api::Ip;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const BROADCAST: Ip = 0xFFFF_FFFF;

pub fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

pub fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// One's-complement sum folded and inverted. `init` is a partial sum.
pub fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init as u64;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u64) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Partial sum of the TCP/UDP pseudo header.
pub fn pseudo(src: Ip, dst: Ip, proto: u8, len: usize) -> u32 {
    (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF) + proto as u32 + len as u32
}

/// Display adapter: `IpFmt(ip)` prints dotted quad.
pub struct IpFmt(pub Ip);

impl fmt::Display for IpFmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

pub struct MacFmt(pub [u8; 6]);

impl fmt::Display for MacFmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

pub fn parse_ip(s: &str) -> Option<Ip> {
    let mut r: u32 = 0;
    let mut n = 0;
    for part in s.split('.') {
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        r = r << 8 | part.parse::<u8>().ok()? as u32;
        n += 1;
    }
    (n == 4).then_some(r)
}

/// Addresses, comma separated, each "a.b.c.d", "a.b.c.d-a.b.c.e" or
/// "a.b.c.d-e" (last octet); sorted, without duplicates. None if malformed
/// or more than 4096.
pub fn parse_ip_list(s: &str) -> Option<alloc::vec::Vec<Ip>> {
    let mut out = alloc::vec::Vec::new();
    for item in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        let (a, b) = match item.split_once('-') {
            None => (parse_ip(item)?, parse_ip(item)?),
            Some((a, b)) => {
                let a = parse_ip(a.trim())?;
                let b = b.trim();
                let b = if b.contains('.') { parse_ip(b)? } else { (a & !0xFF) | b.parse::<u8>().ok()? as u32 };
                (a, b)
            }
        };
        if b < a || (b - a) as usize + out.len() >= 4096 {
            return None;
        }
        out.extend(a..=b);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Sorted addresses as compact ranges: "a.b.c.d-a.b.c.e,a.b.c.f".
pub fn fmt_ip_list(ips: &[Ip]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    let mut i = 0;
    while i < ips.len() {
        let mut j = i;
        while j + 1 < ips.len() && ips[j + 1] == ips[j].wrapping_add(1) {
            j += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        let _ = if j > i { write!(out, "{}-{}", IpFmt(ips[i]), IpFmt(ips[j])) } else { write!(out, "{}", IpFmt(ips[i])) };
        i = j + 1;
    }
    out
}

/// "a.b.c.d/nn" -> (ip, mask)
pub fn parse_cidr(s: &str) -> Option<(Ip, Ip)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    let prefix: u32 = prefix.parse().ok().filter(|&p| p <= 32)?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((parse_ip(ip)?, mask))
}

/// A network for a list of who or what (allow, hosts, allowed IPs):
/// "a.b.c.d/n", or "a.b.c.d" alone for that one address (not a /24, as
/// `parse_cidr` assumes for an interface's address).
pub fn parse_net(s: &str) -> Option<(Ip, Ip)> {
    if s.contains('/') { parse_cidr(s) } else { parse_ip(s).map(|a| (a, !0)) }
}

/// Look up `key=value` in a whitespace-separated command line.
pub fn cmdline_get<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

#[cfg(test)]
mod net_tests {
    use super::*;

    #[test]
    fn one_address_is_one_address() {
        assert_eq!(parse_net("10.0.0.7"), Some((0x0A00_0007, !0)));
        assert_eq!(parse_net("10.0.0.0/8"), Some((0x0A00_0000, 0xFF00_0000)));
        assert_eq!(parse_net("0.0.0.0/0"), Some((0, 0)));
        assert_eq!(parse_net("nic0"), None);
    }
}
