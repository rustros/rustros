//! Offloads done in software, for where the hardware does not: complete a
//! partial TCP/UDP checksum, cut a big TCP segment (GRO/TSO) into packets.
//! Frames are Ethernet (untagged) with IPv4 inside.

use alloc::vec::Vec;

use crate::wire::{checksum, pseudo};

const ETH: usize = 14;

/// (IP header length, L4 protocol, IP total length) of an untagged IPv4 frame.
fn ipv4(f: &[u8]) -> Option<(usize, u8, usize)> {
    if f.len() < ETH + 20 || f[12..14] != [8, 0] || f[ETH] >> 4 != 4 {
        return None;
    }
    let ihl = (f[ETH] & 15) as usize * 4;
    let total = u16::from_be_bytes([f[ETH + 2], f[ETH + 3]]) as usize;
    (ihl >= 20 && total >= ihl && ETH + total <= f.len()).then_some((ihl, f[ETH + 9], total))
}

/// Where the checksum is, for `virtio_net_hdr`: (start of the L4 header,
/// offset of its checksum, length of all headers for TCP), counted from the
/// start of the frame (`eth`: its Ethernet header length, 14 or 18).
pub fn csum_layout(f: &[u8], eth: usize) -> Option<(u16, u16, u16)> {
    if f.len() < eth + 20 || f[eth] >> 4 != 4 {
        return None;
    }
    let l4 = eth + (f[eth] & 15) as usize * 4;
    match f[eth + 9] {
        6 if f.len() >= l4 + 20 => Some((l4 as u16, 16, (l4 + (f[l4 + 12] >> 4) as usize * 4) as u16)),
        17 if f.len() >= l4 + 8 => Some((l4 as u16, 6, (l4 + 8) as u16)),
        _ => None,
    }
}

/// Compute a TCP/UDP checksum completely (in place). False if the frame is
/// not IPv4 TCP/UDP.
pub fn complete_csum(f: &mut [u8]) -> bool {
    let Some((ihl, proto, total)) = ipv4(f) else { return false };
    let l4 = ETH + ihl;
    let end = ETH + total;
    let at = match proto {
        6 if end >= l4 + 20 => l4 + 16,
        17 if end >= l4 + 8 => l4 + 6,
        _ => return false,
    };
    let src = u32::from_be_bytes([f[ETH + 12], f[ETH + 13], f[ETH + 14], f[ETH + 15]]);
    let dst = u32::from_be_bytes([f[ETH + 16], f[ETH + 17], f[ETH + 18], f[ETH + 19]]);
    f[at..at + 2].fill(0);
    let mut c = checksum(&f[l4..end], pseudo(src, dst, proto, end - l4));
    if proto == 17 && c == 0 {
        c = 0xFFFF;
    }
    f[at..at + 2].copy_from_slice(&c.to_be_bytes());
    true
}

/// Cut a big TCP segment into packets of at most `mss` bytes of payload,
/// each with complete checksums. None if it is not IPv4 TCP.
pub fn segment(f: &[u8], mss: usize) -> Option<Vec<Vec<u8>>> {
    let (ihl, proto, total) = ipv4(f)?;
    let l4 = ETH + ihl;
    if proto != 6 || mss == 0 || ETH + total < l4 + 20 {
        return None;
    }
    let thl = (f[l4 + 12] >> 4) as usize * 4;
    let head = l4 + thl;
    if thl < 20 || head > ETH + total {
        return None;
    }
    let payload = &f[head..ETH + total];
    let seq0 = u32::from_be_bytes([f[l4 + 4], f[l4 + 5], f[l4 + 6], f[l4 + 7]]);
    let id0 = u16::from_be_bytes([f[ETH + 4], f[ETH + 5]]);
    let flags = f[l4 + 13];
    let n = payload.len().div_ceil(mss).max(1);
    let mut out = Vec::with_capacity(n);
    let chunks: Vec<&[u8]> = if payload.is_empty() { alloc::vec![payload] } else { payload.chunks(mss).collect() };
    for (i, chunk) in chunks.into_iter().enumerate() {
        let mut p = Vec::with_capacity(head + chunk.len());
        p.extend_from_slice(&f[..head]);
        p.extend_from_slice(chunk);
        let tot = (ihl + thl + chunk.len()) as u16;
        p[ETH + 2..ETH + 4].copy_from_slice(&tot.to_be_bytes());
        p[ETH + 4..ETH + 6].copy_from_slice(&id0.wrapping_add(i as u16).to_be_bytes());
        p[ETH + 10..ETH + 12].fill(0);
        let c = checksum(&p[ETH..l4], 0);
        p[ETH + 10..ETH + 12].copy_from_slice(&c.to_be_bytes());
        p[l4 + 4..l4 + 8].copy_from_slice(&seq0.wrapping_add((i * mss) as u32).to_be_bytes());
        // FIN and PSH only on the last packet, CWR only on the first
        let last = i + 1 == n;
        p[l4 + 13] = flags & if last { 0xFF } else { !0x09 } & if i == 0 { 0xFF } else { !0x80 };
        complete_csum(&mut p);
        out.push(p);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP frame with `len` payload bytes and a partial (pseudo-only) checksum.
    fn frame(len: usize, flags: u8) -> Vec<u8> {
        let mut f = alloc::vec![0u8; ETH + 20 + 20 + len];
        f[12..14].copy_from_slice(&[8, 0]);
        f[ETH] = 0x45;
        f[ETH + 2..ETH + 4].copy_from_slice(&((40 + len) as u16).to_be_bytes());
        f[ETH + 4..ETH + 6].copy_from_slice(&0x1000u16.to_be_bytes());
        f[ETH + 6] = 0x40;
        f[ETH + 8] = 64;
        f[ETH + 9] = 6;
        f[ETH + 12..ETH + 16].copy_from_slice(&[10, 0, 0, 1]);
        f[ETH + 16..ETH + 20].copy_from_slice(&[10, 0, 0, 2]);
        let c = checksum(&f[ETH..ETH + 20], 0);
        f[ETH + 10..ETH + 12].copy_from_slice(&c.to_be_bytes());
        let t = ETH + 20;
        f[t..t + 2].copy_from_slice(&5000u16.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&80u16.to_be_bytes());
        f[t + 4..t + 8].copy_from_slice(&1_000_000u32.to_be_bytes());
        f[t + 12] = 5 << 4;
        f[t + 13] = flags;
        for (i, b) in f[t + 20..].iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        f
    }

    fn tcp_ok(p: &[u8]) -> bool {
        let total = u16::from_be_bytes([p[ETH + 2], p[ETH + 3]]) as usize;
        checksum(&p[ETH..ETH + 20], 0) == 0 && checksum(&p[ETH + 20..ETH + total], pseudo(0x0A00_0001, 0x0A00_0002, 6, total - 20)) == 0
    }

    #[test]
    fn completes_a_checksum() {
        let mut f = frame(1000, 0x18);
        assert!(!tcp_ok(&f));
        assert!(complete_csum(&mut f));
        assert!(tcp_ok(&f));
        assert_eq!(csum_layout(&f, ETH), Some((34, 16, 54)));
    }

    #[test]
    fn cuts_a_segment() {
        let big = frame(10_000, 0x18 | 0x01 | 0x80); // PSH ACK FIN CWR
        let segs = segment(&big, 1448).unwrap();
        assert_eq!(segs.len(), 7);
        let mut payload = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(tcp_ok(s), "segment {i} checksums");
            let seq = u32::from_be_bytes([s[38], s[39], s[40], s[41]]);
            assert_eq!(seq as usize, 1_000_000 + i * 1448);
            let fl = s[ETH + 20 + 13];
            assert_eq!(fl & 0x80 != 0, i == 0, "CWR only first");
            assert_eq!(fl & 0x09 != 0, i == 6, "FIN/PSH only last");
            assert_eq!(u16::from_be_bytes([s[18], s[19]]), 0x1000 + i as u16);
            payload.extend_from_slice(&s[ETH + 40..]);
        }
        assert_eq!(payload, big[ETH + 40..]);
        assert!(segment(&frame(0, 0x10), 1448).unwrap().len() == 1, "a bare ACK stays one");
    }
}
