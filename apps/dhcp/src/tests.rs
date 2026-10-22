use super::*;

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
    u32::from_be_bytes([a, b, c, d])
}

/// A server reply as dnsmasq would send it.
fn reply(kind: u8, xid: u32, opts: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 2;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[16..20].copy_from_slice(&ip(10, 0, 2, 15).to_be_bytes());
    p[28..34].copy_from_slice(&MAC);
    p[236..240].copy_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, kind]);
    p.extend_from_slice(opts);
    p.push(255);
    p
}

#[test]
fn discover_layout() {
    let p = build(DISCOVER, 0x1234_5678, MAC, 0, 0, 0, b"rustros-123456");
    assert!(p.len() >= 300);
    assert_eq!((p[0], p[1], p[2]), (1, 1, 6));
    assert_eq!(&p[4..8], &0x1234_5678u32.to_be_bytes());
    assert_eq!(p[10], 0x80, "broadcast flag while unconfigured");
    assert_eq!(&p[28..34], &MAC);
    assert_eq!(&p[236..243], &[99, 130, 83, 99, 53, 1, DISCOVER]);
    let renew = build(REQUEST, 1, MAC, ip(10, 0, 2, 15), 0, 0, b"");
    assert_eq!(renew[10], 0, "no broadcast flag when renewing");
    assert_eq!(&renew[12..16], &ip(10, 0, 2, 15).to_be_bytes());
}

#[test]
fn request_carries_requested_ip_and_server() {
    let p = build(REQUEST, 7, MAC, 0, ip(10, 0, 2, 15), ip(10, 0, 2, 2), b"h");
    let o = &p[240..];
    let find = |code: u8| {
        let mut i = 0;
        while i < o.len() && o[i] != 255 {
            if o[i] == code {
                return Some(o[i + 2..i + 2 + o[i + 1] as usize].to_vec());
            }
            i += 2 + o[i + 1] as usize;
        }
        None
    };
    assert_eq!(find(50).unwrap(), ip(10, 0, 2, 15).to_be_bytes());
    assert_eq!(find(54).unwrap(), ip(10, 0, 2, 2).to_be_bytes());
    assert_eq!(find(12).unwrap(), b"h");
    assert_eq!(find(61).unwrap(), [1, 0x52, 0x54, 0, 0x12, 0x34, 0x56]);
}

#[test]
fn parse_offer() {
    let mut opts = vec![1, 4, 255, 255, 255, 0, 3, 8, 10, 0, 2, 2, 10, 0, 2, 99, 6, 8, 8, 8, 8, 8, 1, 1, 1, 1];
    opts.extend_from_slice(&[0, 0]); // pad options
    opts.extend_from_slice(&[26, 2, 0x05, 0xAA, 51, 4, 0, 0, 0x0E, 0x10, 54, 4, 10, 0, 2, 2, 99, 3, 1, 2, 3]);
    let r = parse(&reply(OFFER, 42, &opts), 42, MAC).unwrap();
    assert_eq!(r.kind, OFFER);
    assert_eq!(r.yiaddr, ip(10, 0, 2, 15));
    assert_eq!(r.mask, ip(255, 255, 255, 0));
    assert_eq!(r.router, ip(10, 0, 2, 2), "first router");
    assert_eq!(r.dns, vec![ip(8, 8, 8, 8), ip(1, 1, 1, 1)]);
    assert_eq!(r.mtu, 1450);
    assert_eq!(r.lease, 3600);
    assert_eq!(r.server, ip(10, 0, 2, 2));
}

#[test]
fn parse_rejects_others() {
    let ok = reply(ACK, 42, &[]);
    assert!(parse(&ok, 42, MAC).is_some());
    assert!(parse(&ok, 43, MAC).is_none(), "other transaction");
    assert!(parse(&ok, 42, [1; 6]).is_none(), "other client");
    let mut req = ok.clone();
    req[0] = 1;
    assert!(parse(&req, 42, MAC).is_none(), "a request, not a reply");
    assert!(parse(&ok[..200], 42, MAC).is_none(), "truncated");
    let no_type = {
        let mut p = ok.clone();
        p.truncate(240);
        p.push(255);
        p
    };
    assert!(parse(&no_type, 42, MAC).is_none(), "BOOTP without message type");
    // option running past the end: no panic
    let mut bad = ok.clone();
    bad.truncate(bad.len() - 1);
    bad.extend_from_slice(&[51, 200, 1]);
    assert!(parse(&bad, 42, MAC).is_none());
}

#[test]
fn renewal_timers() {
    let r = Reply { lease: 3600, ..Reply::default() };
    assert_eq!(timers(&r), (1_800_000, 3_150_000, 3_600_000));
    let r = Reply { lease: 3600, t1: 1000, t2: 2000, ..Reply::default() };
    assert_eq!(timers(&r), (1_000_000, 2_000_000, 3_600_000));
    // bogus server values stay ordered and inside the lease
    let r = Reply { lease: 100, t1: 500, t2: 50, ..Reply::default() };
    let (t1, t2, end) = timers(&r);
    assert!(t1 <= t2 && t2 <= end && end == 100_000);
    let r = Reply { lease: 5, ..Reply::default() };
    assert_eq!(timers(&r).2, 60_000);
}
