use super::*;

const fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
    u32::from_be_bytes([a, b, c, d])
}

const HOST: Ip = ip(10, 0, 0, 2);
const HOST2: Ip = ip(10, 0, 0, 3);
const PUB: Ip = ip(203, 0, 113, 1);
const PUB2: Ip = ip(203, 0, 113, 2);
const REMOTE: Ip = ip(198, 51, 100, 7);
const ROUTER: Ip = ip(198, 51, 100, 1);

fn ipv4(src: Ip, dst: Ip, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    set16(&mut p, 2, (20 + payload.len()) as u16);
    set16(&mut p, 4, 0x1234);
    p[8] = 64;
    p[9] = proto;
    set32(&mut p, 12, src);
    set32(&mut p, 16, dst);
    let c = checksum(&p);
    set16(&mut p, 10, c);
    p.extend_from_slice(payload);
    p
}

fn pseudo_sum(src: Ip, dst: Ip, proto: u8, l4: &[u8]) -> u16 {
    let mut b = Vec::new();
    b.extend_from_slice(&src.to_be_bytes());
    b.extend_from_slice(&dst.to_be_bytes());
    b.extend_from_slice(&[0, proto]);
    b.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    b.extend_from_slice(l4);
    checksum(&b)
}

fn tcp(src: Ip, sp: u16, dst: Ip, dp: u16, flags: u8, opts: &[u8], data: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    set16(&mut t, 0, sp);
    set16(&mut t, 2, dp);
    set32(&mut t, 4, 1000);
    t[12] = ((20 + opts.len()) / 4 << 4) as u8;
    t[13] = flags;
    set16(&mut t, 14, 65535);
    t.extend_from_slice(opts);
    t.extend_from_slice(data);
    let c = pseudo_sum(src, dst, TCP, &t);
    set16(&mut t, 16, c);
    ipv4(src, dst, TCP, &t)
}

fn udp(src: Ip, sp: u16, dst: Ip, dp: u16, data: &[u8]) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    set16(&mut u, 0, sp);
    set16(&mut u, 2, dp);
    set16(&mut u, 4, (8 + data.len()) as u16);
    u.extend_from_slice(data);
    let mut c = pseudo_sum(src, dst, UDP, &u);
    if c == 0 {
        c = 0xFFFF;
    }
    set16(&mut u, 6, c);
    ipv4(src, dst, UDP, &u)
}

fn echo(src: Ip, dst: Ip, typ: u8, id: u16) -> Vec<u8> {
    let mut m = vec![typ, 0, 0, 0, 0, 0, 0, 1];
    set16(&mut m, 4, id);
    m.extend_from_slice(b"ping data");
    let c = checksum(&m);
    set16(&mut m, 2, c);
    ipv4(src, dst, ICMP, &m)
}

/// Header and L4 checksums of a whole (unfragmented) packet are right.
fn assert_valid(p: &[u8]) {
    let h = parse(p).expect("parses");
    assert_eq!(checksum(&p[..20]), 0, "IP header checksum");
    let l4 = &p[h.ihl..h.total];
    match h.proto {
        TCP => assert_eq!(pseudo_sum(h.src, h.dst, TCP, l4), 0, "TCP checksum"),
        UDP if get16(l4, 6) != 0 => assert_eq!(pseudo_sum(h.src, h.dst, UDP, l4), 0, "UDP checksum"),
        ICMP => assert_eq!(checksum(l4), 0, "ICMP checksum"),
        _ => {}
    }
}

fn src_of(p: &[u8]) -> (Ip, u16) {
    (get32(p, 12), get16(p, 20))
}

fn dst_of(p: &[u8]) -> (Ip, u16) {
    (get32(p, 16), get16(p, 22))
}

fn nat() -> Nat {
    let mut n = Nat::new(Config::default(), 0x1234_5678);
    n.set_default_egress(PUB);
    n
}

#[test]
fn tcp_round_trip() {
    let mut n = nat();
    let mut syn = tcp(HOST, 40000, REMOTE, 443, SYN, &[], &[]);
    assert_eq!(n.outbound(0, &mut syn, 7, false), Ok(PUB));
    assert_valid(&syn);
    let (ext_ip, ext_port) = src_of(&syn);
    assert_eq!(ext_ip, PUB);
    assert!((10_000..=49_151).contains(&ext_port));
    assert_eq!(syn[8], 63, "TTL decremented");
    assert_eq!(dst_of(&syn), (REMOTE, 443));

    let mut synack = tcp(REMOTE, 443, PUB, ext_port, SYN | ACK, &[], &[]);
    assert_eq!(n.inbound(5, &mut synack, false), Inbound::Forward { to: HOST, tag: 7 });
    assert_valid(&synack);
    assert_eq!(dst_of(&synack), (HOST, 40000));

    let mut data = tcp(HOST, 40000, REMOTE, 443, ACK, &[], b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(n.outbound(10, &mut data, 7, false), Ok(PUB));
    assert_valid(&data);
    assert_eq!(src_of(&data), (PUB, ext_port));
    assert_eq!(n.stats().sessions, 1);
}

#[test]
fn inside_port_kept_when_free() {
    let mut n = nat();
    let mut a = udp(HOST, 20000, REMOTE, 53, b"q");
    n.outbound(0, &mut a, 0, false).unwrap();
    assert_eq!(src_of(&a), (PUB, 20000));
    // another host with the same port gets a different one
    let mut b = udp(HOST2, 20000, REMOTE, 53, b"q");
    n.outbound(0, &mut b, 0, false).unwrap();
    assert_ne!(src_of(&b).1, 20000);
    assert_valid(&b);
}

#[test]
fn endpoint_independent_mapping_dependent_filtering() {
    let mut n = nat();
    let mut a = udp(HOST, 5000, REMOTE, 3478, b"stun");
    n.outbound(0, &mut a, 0, false).unwrap();
    let ext = src_of(&a).1;
    let mut b = udp(HOST, 5000, ROUTER, 9999, b"x");
    n.outbound(0, &mut b, 0, false).unwrap();
    assert_eq!(src_of(&b).1, ext, "same external port for every destination");
    // a reply from the contacted endpoint comes in ...
    let mut r = udp(ROUTER, 9999, PUB, ext, b"y");
    assert_eq!(n.inbound(1, &mut r, false), Inbound::Forward { to: HOST, tag: 0 });
    // ... a stranger, or another port of a contacted host, does not
    let mut s = udp(ip(192, 0, 2, 9), 9999, PUB, ext, b"z");
    assert_eq!(n.inbound(1, &mut s, false), Inbound::NotOurs);
    let mut s = udp(REMOTE, 1234, PUB, ext, b"z");
    assert_eq!(n.inbound(1, &mut s, false), Inbound::NotOurs);
}

#[test]
fn not_ours_is_untouched() {
    let mut n = nat();
    let mut p = tcp(REMOTE, 5555, PUB, 9000, SYN, &[], &[]);
    let before = p.clone();
    assert_eq!(n.inbound(0, &mut p, false), Inbound::NotOurs);
    assert_eq!(p, before);
}

#[test]
fn udp_without_checksum() {
    let mut n = nat();
    let mut p = udp(HOST, 30000, REMOTE, 9, b"x");
    set16(&mut p, 26, 0);
    n.outbound(0, &mut p, 0, false).unwrap();
    assert_eq!(get16(&p, 26), 0, "stays without checksum");
    assert_eq!(checksum(&p[..20]), 0);
}

#[test]
fn icmp_echo() {
    let mut n = nat();
    let mut req = echo(HOST, REMOTE, 8, 0x0042);
    assert_eq!(n.outbound(0, &mut req, 3, false), Ok(PUB));
    assert_valid(&req);
    let id = get16(&req, 24);
    let mut rep = echo(REMOTE, PUB, 0, id);
    assert_eq!(n.inbound(1, &mut rep, false), Inbound::Forward { to: HOST, tag: 3 });
    assert_valid(&rep);
    assert_eq!(get16(&rep, 24), 0x0042);
    assert_eq!(get32(&rep, 16), HOST);
    // a ping to the NAT itself is not a session
    let mut own = echo(REMOTE, PUB, 8, 7);
    assert_eq!(n.inbound(1, &mut own, false), Inbound::NotOurs);
}

#[test]
fn icmp_error_from_outside_reaches_the_host() {
    let mut cfg = Config::default();
    cfg.ports = (40000, 40000);
    let mut n = Nat::new(cfg, 1);
    n.set_default_egress(PUB);
    let mut out = udp(HOST, 1111, REMOTE, 53, &[0u8; 1400]);
    n.outbound(0, &mut out, 9, false).unwrap();
    assert_eq!(src_of(&out), (PUB, 40000));
    // the router says: fragmentation needed, MTU 1280
    let mut err = icmp_error(ROUTER, &out, 3, 4, 1280).unwrap();
    assert_eq!(err.len(), 20 + 8 + 28);
    assert_eq!(n.inbound(1, &mut err, false), Inbound::Forward { to: HOST, tag: 9 });
    assert_valid(&err);
    assert_eq!(get32(&err, 16), HOST);
    let inner = &err[28..];
    assert_eq!(checksum(&inner[..20]), 0, "inner header checksum");
    assert_eq!((get32(inner, 12), get16(inner, 20)), (HOST, 1111), "inner source back to the host");
    assert_eq!(get16(&err, 26), 1280);

    // and about a ping
    let mut ping = echo(HOST, REMOTE, 8, 5);
    n.outbound(0, &mut ping, 9, false).unwrap();
    let mut err = icmp_error(ROUTER, &ping, 11, 0, 0).unwrap();
    assert_eq!(n.inbound(1, &mut err, false), Inbound::Forward { to: HOST, tag: 9 });
    assert_valid(&err);
    assert_eq!(get16(&err[28..], 24), 5, "inner echo identifier restored");
}

#[test]
fn icmp_error_from_inside_goes_out() {
    let mut n = nat();
    let mut out = udp(HOST, 2222, REMOTE, 7000, b"hi");
    n.outbound(0, &mut out, 0, false).unwrap();
    let ext = src_of(&out).1;
    let mut back = udp(REMOTE, 7000, PUB, ext, b"reply");
    n.inbound(1, &mut back, false).unwrap_forward();
    // the host says: port unreachable
    let mut err = icmp_error(HOST, &back, 3, 3, 0).unwrap();
    assert_eq!(n.outbound(2, &mut err, 0, false), Ok(PUB));
    assert_valid(&err);
    assert_eq!(get32(&err, 12), PUB);
    let inner = &err[28..];
    assert_eq!(checksum(&inner[..20]), 0);
    assert_eq!(dst_of(inner), (PUB, ext), "inner destination is the external endpoint");
}

trait Fwd {
    fn unwrap_forward(self);
}
impl Fwd for Inbound {
    fn unwrap_forward(self) {
        assert!(matches!(self, Inbound::Forward { .. }), "{self:?}");
    }
}

#[test]
fn tcp_needs_syn_to_start() {
    let mut n = nat();
    let mut p = tcp(HOST, 1, REMOTE, 80, ACK, &[], b"x");
    assert_eq!(n.outbound(0, &mut p, 0, false), Err(Drop::NoSession));
    let mut p = tcp(HOST, 1, REMOTE, 80, SYN | ACK, &[], &[]);
    assert_eq!(n.outbound(0, &mut p, 0, false), Err(Drop::NoSession));
    assert_eq!(n.stats().sessions, 0);
}

#[test]
fn ttl() {
    let mut n = nat();
    let mut p = udp(HOST, 1, REMOTE, 2, b"x");
    p[8] = 1;
    assert_eq!(n.outbound(0, &mut p, 0, false), Err(Drop::TtlExceeded));
    let mut p = udp(HOST, 1, REMOTE, 2, b"x");
    n.outbound(0, &mut p, 0, false).unwrap();
    let mut r = udp(REMOTE, 2, PUB, src_of(&p).1, b"y");
    r[8] = 1;
    let c = checksum(&{
        let mut h = r[..20].to_vec();
        h[10..12].fill(0);
        h
    });
    set16(&mut r, 10, c);
    assert_eq!(n.inbound(0, &mut r, false), Inbound::Drop(Drop::TtlExceeded));
    let e = icmp_error(PUB, &r, 11, 0, 0).unwrap();
    assert_valid(&e);
    assert_eq!(get32(&e, 16), REMOTE);
}

#[test]
fn mss_clamp_both_ways() {
    let mut cfg = Config::default();
    cfg.mss = Some(1360);
    let mut n = Nat::new(cfg, 1);
    n.set_default_egress(PUB);
    let opts = [2, 4, 0x05, 0xB4, 1, 1, 4, 2]; // MSS 1460, NOP, NOP, SACK permitted
    let mut syn = tcp(HOST, 1000, REMOTE, 80, SYN, &opts, &[]);
    n.outbound(0, &mut syn, 0, false).unwrap();
    assert_valid(&syn);
    assert_eq!(get16(&syn, 42), 1360);
    let mut sa = tcp(REMOTE, 80, PUB, src_of(&syn).1, SYN | ACK, &opts, &[]);
    n.inbound(1, &mut sa, false).unwrap_forward();
    assert_valid(&sa);
    assert_eq!(get16(&sa, 42), 1360);
    // smaller ones are left alone
    let small = [2, 4, 0x02, 0x18];
    let mut syn = tcp(HOST, 1001, REMOTE, 80, SYN, &small, &[]);
    n.outbound(0, &mut syn, 0, false).unwrap();
    assert_eq!(get16(&syn, 42), 536);
}

#[test]
fn per_host_egress() {
    let mut n = nat();
    n.set_egress(HOST2, Some(PUB2));
    let mut a = udp(HOST, 20000, REMOTE, 2, b"a");
    let mut b = udp(HOST2, 20000, REMOTE, 2, b"b");
    assert_eq!(n.outbound(0, &mut a, 0, false), Ok(PUB));
    assert_eq!(n.outbound(0, &mut b, 0, false), Ok(PUB2));
    // same port on different egress addresses does not collide
    assert_eq!(src_of(&a).1, src_of(&b).1);
    let mut r = udp(REMOTE, 2, PUB2, src_of(&b).1, b"r");
    assert_eq!(n.inbound(1, &mut r, false), Inbound::Forward { to: HOST2, tag: 0 });
    let mut r = udp(REMOTE, 2, PUB, src_of(&a).1, b"r");
    assert_eq!(n.inbound(1, &mut r, false), Inbound::Forward { to: HOST, tag: 0 });

    let mut nobody = Nat::new(Config::default(), 1);
    let mut p = udp(HOST, 1, REMOTE, 2, b"a");
    assert_eq!(nobody.outbound(0, &mut p, 0, false), Err(Drop::NoEgress));
}

#[test]
fn expiry_and_timeouts() {
    let mut n = nat();
    let c = n.config().clone();
    // unanswered UDP: short timeout
    let mut p = udp(HOST, 1, REMOTE, 2, b"a");
    n.outbound(0, &mut p, 0, false).unwrap();
    let ext = src_of(&p).1;
    let mut r = udp(REMOTE, 2, PUB, ext, b"r");
    assert_eq!(n.inbound(c.udp_ms, &mut r, false), Inbound::NotOurs, "expired");
    assert_eq!(n.stats().sessions, 0, "removed on lookup");
    // answered UDP: stream timeout
    let mut p = udp(HOST, 1, REMOTE, 2, b"a");
    n.outbound(0, &mut p, 0, false).unwrap();
    let mut r = udp(REMOTE, 2, PUB, src_of(&p).1, b"r");
    n.inbound(1, &mut r, false).unwrap_forward();
    let mut r = udp(REMOTE, 2, PUB, src_of(&p).1, b"r");
    n.inbound(c.udp_ms + 10, &mut r, false).unwrap_forward();
    // established TCP lives long, RST shortens it
    let mut s = tcp(HOST, 7, REMOTE, 80, SYN, &[], &[]);
    n.outbound(0, &mut s, 0, false).unwrap();
    let ext = src_of(&s).1;
    let mut sa = tcp(REMOTE, 80, PUB, ext, SYN | ACK, &[], &[]);
    n.inbound(1, &mut sa, false).unwrap_forward();
    let t = 1 + c.tcp_transitory_ms + 1000;
    let mut a = tcp(REMOTE, 80, PUB, ext, ACK, &[], b"d");
    n.inbound(t, &mut a, false).unwrap_forward();
    let mut rst = tcp(HOST, 7, REMOTE, 80, RST, &[], &[]);
    n.outbound(t, &mut rst, 0, false).unwrap();
    let mut late = tcp(REMOTE, 80, PUB, ext, ACK, &[], b"d");
    assert_eq!(n.inbound(t + RST_MS, &mut late, false), Inbound::NotOurs);
    // the sweeper frees what nobody looks up
    n.expire(u64::MAX / 2, 1000);
    assert_eq!(n.stats().sessions, 0);
}

#[test]
fn ports_are_released_and_reused() {
    let mut cfg = Config::default();
    cfg.ports = (50000, 50001);
    let mut n = Nat::new(cfg, 1);
    n.set_default_egress(PUB);
    let mut a = udp(HOST, 1, REMOTE, 2, b"a");
    let mut b = udp(HOST, 2, REMOTE, 2, b"b");
    let mut c = udp(HOST, 3, REMOTE, 2, b"c");
    n.outbound(0, &mut a, 0, false).unwrap();
    n.outbound(0, &mut b, 0, false).unwrap();
    assert_eq!(n.outbound(0, &mut c, 0, false), Err(Drop::PortsExhausted));
    // the mapping is shared: another destination from port 1 is fine
    let mut a2 = udp(HOST, 1, ROUTER, 2, b"a");
    n.outbound(0, &mut a2, 0, false).unwrap();
    n.expire(1_000_000, 100);
    let mut c = udp(HOST, 3, REMOTE, 2, b"c");
    n.outbound(1_000_000, &mut c, 0, false).unwrap();
}

#[test]
fn limits() {
    let mut cfg = Config::default();
    cfg.max_per_host = 2;
    cfg.max_sessions = 3;
    let mut n = Nat::new(cfg, 1);
    n.set_default_egress(PUB);
    for port in 1..=2 {
        n.outbound(0, &mut udp(HOST, port, REMOTE, 2, b"x"), 0, false).unwrap();
    }
    assert_eq!(n.outbound(0, &mut udp(HOST, 3, REMOTE, 2, b"x"), 0, false), Err(Drop::HostLimit));
    n.outbound(0, &mut udp(HOST2, 1, REMOTE, 2, b"x"), 0, false).unwrap();
    assert_eq!(n.outbound(0, &mut udp(HOST2, 2, REMOTE, 2, b"x"), 0, false), Err(Drop::TableFull));
    n.remove_host(HOST);
    assert_eq!(n.stats().sessions, 1);
    n.outbound(0, &mut udp(HOST2, 2, REMOTE, 2, b"x"), 0, false).unwrap();
}

/// Split an IPv4 packet into fragments with `chunk` bytes of payload each.
fn fragment(p: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let payload = &p[20..];
    let mut out = Vec::new();
    for (k, c) in payload.chunks(chunk).enumerate() {
        let mut f = p[..20].to_vec();
        set16(&mut f, 2, (20 + c.len()) as u16);
        let more = (k + 1) * chunk < payload.len();
        set16(&mut f, 6, (if more { 0x2000 } else { 0 }) | (k * chunk / 8) as u16);
        f[10..12].fill(0);
        let cs = checksum(&f);
        set16(&mut f, 10, cs);
        f.extend_from_slice(c);
        out.push(f);
    }
    out
}

fn reassemble(frags: &[Vec<u8>]) -> Vec<u8> {
    let mut p = frags[0][..20].to_vec();
    for f in frags {
        p.extend_from_slice(&f[20..]);
    }
    let len = p.len() as u16;
    set16(&mut p, 2, len);
    set16(&mut p, 6, 0);
    p[10..12].fill(0);
    let c = checksum(&p[..20]);
    set16(&mut p, 10, c);
    p
}

#[test]
fn fragments_follow_the_first() {
    let mut n = nat();
    let big = udp(HOST, 4000, REMOTE, 5000, &[7u8; 3000]);
    let mut frags = fragment(&big, 1480);
    assert_eq!(frags.len(), 3);
    // a later fragment before the first: no session yet
    let mut early = frags[1].clone();
    assert_eq!(n.outbound(0, &mut early, 0, false), Err(Drop::NoSession));
    for f in frags.iter_mut() {
        assert_eq!(n.outbound(0, f, 0, false), Ok(PUB));
        assert_eq!(checksum(&f[..20]), 0);
        assert_eq!(get32(f, 12), PUB);
    }
    let whole = reassemble(&frags);
    assert_valid(&whole);
    let ext = src_of(&whole).1;

    let reply = udp(REMOTE, 5000, PUB, ext, &[9u8; 2000]);
    let mut frags = fragment(&reply, 1480);
    for f in frags.iter_mut() {
        assert_eq!(n.inbound(1, f, false), Inbound::Forward { to: HOST, tag: 0 });
    }
    let whole = reassemble(&frags);
    assert_valid(&whole);
    assert_eq!(dst_of(&whole), (HOST, 4000));
}

#[test]
fn static_nat_both_ways() {
    // srcnat HOST -> PUB, dstnat PUB -> HOST
    for mut p in [tcp(HOST, 1111, REMOTE, 80, SYN, &[], b"hi"), udp(HOST, 2222, REMOTE, 53, b"q"), echo(HOST, REMOTE, 8, 7)] {
        let before = p[20..24].to_vec();
        assert_eq!(rewrite(&mut p, true, PUB, false), Some(HOST));
        assert_valid(&p);
        assert_eq!(get32(&p, 12), PUB);
        assert_eq!(p[20..24], before[..], "ports untouched");
    }
    let mut back = tcp(REMOTE, 80, PUB, 1111, SYN | ACK, &[], b"");
    assert_eq!(rewrite(&mut back, false, HOST, false), Some(PUB));
    assert_valid(&back);
    assert_eq!(dst_of(&back), (HOST, 1111));
    // UDP without a checksum stays without
    let mut u = udp(HOST, 1, REMOTE, 2, b"x");
    set16(&mut u, 26, 0);
    rewrite(&mut u, true, PUB, false);
    assert_eq!(get16(&u, 26), 0);
}

#[test]
fn static_nat_icmp_errors_and_fragments() {
    // a router answers a packet we srcnat'ed: dstnat takes it back, the quoted
    // packet's source too
    let mut out = udp(HOST, 1111, REMOTE, 53, &[0u8; 100]);
    rewrite(&mut out, true, PUB, false);
    let mut err = icmp_error(ROUTER, &out, 3, 4, 1280).unwrap();
    rewrite(&mut err, false, HOST, false);
    assert_valid(&err);
    let inner = &err[28..];
    assert_eq!(checksum(&inner[..20]), 0, "inner header checksum");
    assert_eq!(get32(inner, 12), HOST, "quoted source back to the host");
    // the host answers a dstnat'ed packet with an error: srcnat fixes the quote
    let mut inb = udp(REMOTE, 53, PUB, 1111, &[0u8; 100]);
    rewrite(&mut inb, false, HOST, false);
    let mut err = icmp_error(HOST, &inb, 3, 3, 0).unwrap();
    rewrite(&mut err, true, PUB, false);
    assert_valid(&err);
    assert_eq!((get32(&err, 12), get32(&err[28..], 16)), (PUB, PUB));
    let q = &err[28..];
    assert_eq!(get16(q, 26), get16(&udp(REMOTE, 53, PUB, 1111, &[0u8; 100]), 26), "quoted UDP checksum as sent");
    // fragments: the first one's L4 checksum is fixed for the whole packet
    let whole = udp(HOST, 9, REMOTE, 9, &[7u8; 3000]);
    let mut frags = fragment(&whole, 1400);
    for f in &mut frags {
        rewrite(f, true, PUB, false);
        assert_eq!(checksum(&f[..20]), 0);
    }
    assert_valid(&reassemble(&frags));
    assert_eq!(rewrite(&mut [0u8; 10], true, PUB, false), None);
}

const WAN2: Ip = ip(203, 0, 113, 240);
const REMOTE2: Ip = ip(198, 51, 100, 99);
const TCP_IDLE: u64 = 2 * 3600 * 1000;

fn no_local(_: Ip) -> bool {
    false
}

#[test]
fn static_srcnat_tracks_replies() {
    let mut s = StaticNat::new(7);
    s.set_rules(vec![(HOST, PUB)], vec![]);
    let mut out = tcp(HOST, 1111, REMOTE, 80, SYN, &[], b"");
    assert!(s.process(0, &mut out, &no_local, false));
    assert_valid(&out);
    assert_eq!(src_of(&out), (PUB, 1111), "port kept");
    // the reply finds its way back without a dstnat rule
    let mut back = tcp(REMOTE, 80, PUB, 1111, SYN | ACK, &[], b"");
    assert!(s.process(1, &mut back, &no_local, false));
    assert_valid(&back);
    assert_eq!(dst_of(&back), (HOST, 1111));
    // others to the public address are not let in
    let mut stranger = tcp(REMOTE2, 80, PUB, 1111, SYN, &[], b"");
    assert!(!s.process(1, &mut stranger, &no_local, false));
    // the host talking to us keeps its address
    let mut mine = udp(HOST, 5, PUB2, 53, b"q");
    assert!(!s.process(1, &mut mine, &|a| a == PUB2, false));
    // idle connections go
    s.expire(TCP_IDLE + 10, 1000);
    assert_eq!(s.stats.conns, 0);
}

#[test]
fn port_forwards() {
    let mut s = StaticNat::new(5);
    let fw = |proto, ports, hport| PortForward { proto, public: WAN2, ports, host: HOST, hport };
    s.set_all(vec![], vec![], vec![fw(TCP, (28820, 28820), 28820), fw(TCP, (2222, 2222), 22), fw(UDP, (5000, 5010), 6000)]);
    // the same port
    let mut syn = tcp(REMOTE, 40000, WAN2, 28820, SYN, &[], b"");
    assert!(s.process(0, &mut syn, &no_local, false));
    assert_valid(&syn);
    assert_eq!(dst_of(&syn), (HOST, 28820));
    let mut back = tcp(HOST, 28820, REMOTE, 40000, SYN | ACK, &[], b"");
    assert!(s.process(1, &mut back, &no_local, false));
    assert_valid(&back);
    assert_eq!(src_of(&back), (WAN2, 28820));
    // another port: as the host's 22
    let mut ssh = tcp(REMOTE, 40001, WAN2, 2222, SYN, &[], b"x");
    assert!(s.process(2, &mut ssh, &no_local, false));
    assert_valid(&ssh);
    assert_eq!(dst_of(&ssh), (HOST, 22));
    let mut ssh_back = tcp(HOST, 22, REMOTE, 40001, SYN | ACK, &[], b"y");
    assert!(s.process(3, &mut ssh_back, &no_local, false));
    assert_valid(&ssh_back);
    assert_eq!(src_of(&ssh_back), (WAN2, 2222));
    // ... with partial checksums too
    let mut part = tcp(REMOTE, 40001, WAN2, 2222, ACK, &[], &[3u8; 2000]);
    make_partial(&mut part);
    assert!(s.process(4, &mut part, &no_local, true));
    complete(&mut part);
    assert_valid(&part);
    // a UDP range keeps the offset
    let mut u = udp(REMOTE, 1, WAN2, 5007, b"q");
    assert!(s.process(5, &mut u, &no_local, false));
    assert_valid(&u);
    assert_eq!(dst_of(&u), (HOST, 6007));
    // other ports and protocols are not ours
    let mut other = tcp(REMOTE, 1, WAN2, 80, SYN, &[], b"");
    assert!(!s.process(6, &mut other, &no_local, false));
    let mut wrong_proto = udp(REMOTE, 1, WAN2, 28820, b"q");
    assert!(!s.process(6, &mut wrong_proto, &no_local, false));
    // a router's ICMP error about the host's (changed-port) reply reaches it
    let mut err = icmp_error(ROUTER, &ssh_back, 3, 4, 1280).unwrap();
    assert!(s.process(7, &mut err, &no_local, false));
    assert_valid(&err);
    let inner = &err[28..];
    assert_eq!((get32(&err, 16), get32(inner, 12), get16(inner, 20)), (HOST, HOST, 22));
    // the host's ICMP error about a forwarded packet leaves from the public side
    let mut err = icmp_error(HOST, &ssh, 3, 3, 0).unwrap();
    assert!(s.process(8, &mut err, &no_local, false));
    assert_valid(&err);
    let inner = &err[28..];
    assert_eq!((get32(&err, 12), get32(inner, 16), get16(inner, 22)), (WAN2, WAN2, 2222));
}

#[test]
fn srcnat_leaves_replies_to_the_hosts_own_address() {
    let mut s = StaticNat::new(7);
    s.set_rules(vec![(HOST, PUB)], vec![]);
    // someone pings the host at its own address (routed): the reply keeps it
    let mut ping = echo(REMOTE, HOST, 8, 21);
    assert!(!s.process(0, &mut ping, &no_local, false), "the request is left alone");
    let mut pong = echo(HOST, REMOTE, 0, 21);
    assert!(!s.process(1, &mut pong, &no_local, false));
    assert_eq!(get32(&pong, 12), HOST, "answered from the address that was pinged");
    // a TCP connection to the host the same
    let mut syn = tcp(REMOTE, 5555, HOST, 22, SYN, &[], b"");
    s.process(2, &mut syn, &no_local, false);
    let mut synack = tcp(HOST, 22, REMOTE, 5555, SYN | ACK, &[], b"");
    s.process(3, &mut synack, &no_local, false);
    assert_eq!(src_of(&synack), (HOST, 22));
    // what the host starts itself still leaves as PUB
    let mut out = tcp(HOST, 6000, REMOTE, 80, SYN, &[], b"");
    assert!(s.process(4, &mut out, &no_local, false));
    assert_eq!(src_of(&out), (PUB, 6000));
}

#[test]
fn static_dstnat_from_several_wans() {
    let mut s = StaticNat::new(7);
    // the host is published on two WANs, and goes out by WAN 1 itself
    s.set_rules(vec![(HOST, PUB)], vec![(PUB, HOST), (WAN2, HOST)]);
    for (public, sport) in [(PUB, 4000), (WAN2, 5000)] {
        let mut syn = tcp(REMOTE, sport, public, 443, SYN, &[], b"");
        assert!(s.process(0, &mut syn, &no_local, false));
        assert_valid(&syn);
        assert_eq!(dst_of(&syn), (HOST, 443));
        // the answer leaves from the address the connection came in on
        let mut ack = tcp(HOST, 443, REMOTE, sport, SYN | ACK, &[], b"");
        assert!(s.process(1, &mut ack, &no_local, false));
        assert_valid(&ack);
        assert_eq!(src_of(&ack), (public, 443), "answered from {public:x}");
        // an ICMP error the host sends about it too
        let mut err = icmp_error(HOST, &syn, 3, 3, 0).unwrap();
        assert!(s.process(1, &mut err, &no_local, false));
        assert_valid(&err);
        assert_eq!((get32(&err, 12), get32(&err[28..], 16)), (public, public));
    }
    // a ping to the second WAN address is answered from it
    let mut ping = echo(REMOTE, WAN2, 8, 9);
    assert!(s.process(2, &mut ping, &no_local, false));
    let mut pong = echo(HOST, REMOTE, 0, 9);
    assert!(s.process(2, &mut pong, &no_local, false));
    assert_valid(&pong);
    assert_eq!(get32(&pong, 12), WAN2);
    // the host's own new connections use its srcnat address
    let mut new = udp(HOST, 7777, REMOTE, 53, b"q");
    assert!(s.process(3, &mut new, &no_local, false));
    assert_eq!(src_of(&new), (PUB, 7777));
    // an ICMP error from a router about it reaches the host
    let mut err = icmp_error(ROUTER, &new, 3, 4, 1280).unwrap();
    assert!(s.process(4, &mut err, &no_local, false));
    assert_valid(&err);
    assert_eq!((get32(&err, 16), get32(&err[28..], 12)), (HOST, HOST));
    // fragments follow their first
    let whole = udp(REMOTE, 9, WAN2, 9, &[1u8; 3000]);
    let mut frags = fragment(&whole, 1400);
    for f in &mut frags {
        assert!(s.process(5, f, &no_local, false));
        assert_eq!(get32(f, 16), HOST);
    }
    assert_valid(&reassemble(&frags));
    // new rules: the connection in progress keeps its translation (it came
    // in on WAN 2, which is no longer published) ...
    let conns = s.stats.conns;
    s.set_rules(vec![], vec![(PUB, HOST)]);
    assert_eq!(s.stats.conns, conns);
    let mut late = tcp(HOST, 443, REMOTE, 5000, ACK, &[], b"");
    assert!(s.process(6, &mut late, &no_local, false));
    assert_eq!(src_of(&late), (WAN2, 443));
    // ... but a new one to WAN 2 is not translated any more
    let mut fresh = tcp(REMOTE, 5001, WAN2, 443, SYN, &[], b"");
    assert!(!s.process(7, &mut fresh, &no_local, false));
}

/// Changing or removing a port forward leaves the connections in progress
/// alone (they keep their host until they end), and the others too; only
/// new connections see the new rules.
#[test]
fn rule_changes_keep_connections() {
    let mut s = StaticNat::new(11);
    let fw = |ports, host, hport| PortForward { proto: TCP, public: WAN2, ports, host, hport };
    s.set_all(vec![], vec![], vec![fw((2222, 2222), HOST, 22), fw((8080, 8080), HOST, 80)]);
    let open = |s: &mut StaticNat, sport: u16, dport: u16| {
        let mut syn = tcp(REMOTE, sport, WAN2, dport, SYN, &[], b"");
        let ok = s.process(0, &mut syn, &no_local, false);
        (ok, dst_of(&syn))
    };
    assert_eq!(open(&mut s, 40001, 2222), (true, (HOST, 22)));
    assert_eq!(open(&mut s, 40002, 8080), (true, (HOST, 80)));
    // the forward on 2222 moves to another host
    s.set_all(vec![], vec![], vec![fw((2222, 2222), HOST2, 22), fw((8080, 8080), HOST, 80)]);
    let mut more = tcp(REMOTE, 40001, WAN2, 2222, ACK, &[], b"data");
    assert!(s.process(1, &mut more, &no_local, false));
    assert_valid(&more);
    assert_eq!(dst_of(&more), (HOST, 22), "the connection in progress stays with its host");
    let mut reply = tcp(HOST, 22, REMOTE, 40001, ACK, &[], b"r");
    assert!(s.process(1, &mut reply, &no_local, false));
    assert_eq!(src_of(&reply), (WAN2, 2222));
    assert_eq!(open(&mut s, 40003, 2222), (true, (HOST2, 22)), "a new one goes to the new host");
    // both forwards removed
    s.set_all(vec![], vec![], vec![]);
    let mut web = tcp(REMOTE, 40002, WAN2, 8080, ACK, &[], b"GET");
    assert!(s.process(2, &mut web, &no_local, false));
    assert_eq!(dst_of(&web), (HOST, 80), "untouched by the changes");
    let mut old = tcp(REMOTE, 40001, WAN2, 2222, ACK, &[], b"x");
    assert!(s.process(2, &mut old, &no_local, false));
    assert_eq!(dst_of(&old), (HOST, 22));
    assert!(!open(&mut s, 40004, 8080).0, "no new connections on a removed forward");
    assert!(s.is_empty() && !s.idle(), "no rules, but connections to serve");
    // a connection that ends goes, as before
    let mut fin = tcp(REMOTE, 40002, WAN2, 8080, FIN | ACK, &[], b"");
    assert!(s.process(3, &mut fin, &no_local, false));
    let mut fin_back = tcp(HOST, 80, REMOTE, 40002, FIN | ACK, &[], b"");
    assert!(s.process(3, &mut fin_back, &no_local, false));
    let mut after = tcp(REMOTE, 40002, WAN2, 8080, ACK, &[], b"");
    assert!(!s.process(3 + 241_000, &mut after, &no_local, false), "gone once its FIN timeout passed");
    // the rest expire too, and then there is nothing to do
    s.expire(3 + 3 * 3600 * 1000, usize::MAX);
    assert!(s.idle());
}

/// The packet with its TCP/UDP checksum made partial, as with offloads: the
/// pseudo-header sum only, not complemented.
fn make_partial(p: &mut [u8]) {
    let h = parse(p).unwrap();
    let at = h.ihl + csum_at(h.proto).0;
    let mut b = Vec::new();
    b.extend_from_slice(&h.src.to_be_bytes());
    b.extend_from_slice(&h.dst.to_be_bytes());
    b.extend_from_slice(&[0, h.proto]);
    b.extend_from_slice(&((h.total - h.ihl) as u16).to_be_bytes());
    set16(p, at, !checksum(&b));
}

/// What the host does with a partial checksum: sum the L4 bytes onto it.
fn complete(p: &mut [u8]) {
    let h = parse(p).unwrap();
    let at = h.ihl + csum_at(h.proto).0;
    let c = checksum(&p[h.ihl..h.total]);
    set16(p, at, c);
}

#[test]
fn partial_checksums_through_nat() {
    let mut n = nat();
    // out: address and port change, MSS clamped on the SYN
    let mut cfg = Config::default();
    cfg.mss = Some(1300);
    let mut m = Nat::new(cfg, 3);
    m.set_default_egress(PUB);
    let mut syn = tcp(HOST, 1111, REMOTE, 443, SYN, &[2, 4, 0x05, 0xb4], b"");
    make_partial(&mut syn);
    m.outbound(0, &mut syn, 1, true).unwrap();
    complete(&mut syn);
    assert_valid(&syn);
    let mut out = tcp(HOST, 2222, REMOTE, 80, SYN, &[], &[5u8; 3000]);
    make_partial(&mut out);
    n.outbound(0, &mut out, 1, true).unwrap();
    let ext = src_of(&out);
    complete(&mut out);
    assert_valid(&out);
    // and back
    let mut back = tcp(REMOTE, 80, ext.0, ext.1, SYN | ACK, &[], &[6u8; 3000]);
    make_partial(&mut back);
    assert!(matches!(n.inbound(1, &mut back, true), Inbound::Forward { .. }));
    complete(&mut back);
    assert_valid(&back);
    assert_eq!(dst_of(&back), (HOST, 2222));
    // static NAT too
    let mut s = StaticNat::new(9);
    s.set_rules(vec![(HOST, PUB)], vec![]);
    let mut u = udp(HOST, 53, REMOTE, 53, &[1u8; 2000]);
    make_partial(&mut u);
    assert!(s.process(0, &mut u, &no_local, true));
    complete(&mut u);
    assert_valid(&u);
    assert_eq!(get32(&u, 12), PUB);
}

#[test]
fn garbage_does_not_panic() {
    let mut n = nat();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let samples = [
        tcp(HOST, 1, REMOTE, 2, SYN, &[2, 4, 5, 0xB4], &[]),
        udp(HOST, 1, REMOTE, 2, b"abc"),
        echo(HOST, REMOTE, 8, 1),
        icmp_error(ROUTER, &udp(PUB, 10000, REMOTE, 2, b"x"), 3, 4, 1280).unwrap(),
    ];
    for k in 0..20_000 {
        let mut p = samples[k % samples.len()].clone();
        for _ in 0..1 + rnd() % 4 {
            let i = (rnd() % p.len() as u64) as usize;
            p[i] = rnd() as u8;
        }
        p.truncate((rnd() % (p.len() as u64 + 1)) as usize);
        let _ = n.outbound(k as u64, &mut p.clone(), 0, false);
        let _ = n.inbound(k as u64, &mut p, false);
    }
}

/// cargo test -p nat-core --release --target x86_64-unknown-linux-gnu -- --ignored --nocapture
#[test]
#[ignore]
fn throughput() {
    let mut n = nat();
    let hosts = 700u32;
    let flows_per_host = 50u16;
    let mut pkts: Vec<Vec<u8>> = Vec::new();
    for h in 0..hosts {
        for f in 0..flows_per_host {
            pkts.push(udp(HOST + h, 20000 + f, REMOTE + (f as u32), 443, &[0u8; 32]));
        }
    }
    for p in pkts.iter_mut() {
        n.outbound(0, &mut p.clone(), 0, false).unwrap();
    }
    let replies: Vec<Vec<u8>> = pkts
        .iter()
        .map(|p| {
            let mut o = p.clone();
            n.outbound(0, &mut o, 0, false).unwrap();
            let (e, ep) = src_of(&o);
            udp(get32(p, 16), 443, e, ep, &[0u8; 32])
        })
        .collect();
    let rounds = 20;
    let t = std::time::Instant::now();
    let mut buf = vec![0u8; 1500];
    for r in 0..rounds {
        for (p, q) in pkts.iter().zip(&replies) {
            let b = &mut buf[..p.len()];
            b.copy_from_slice(p);
            n.outbound(r, b, 0, false).unwrap();
            let b = &mut buf[..q.len()];
            b.copy_from_slice(q);
            assert!(matches!(n.inbound(r, b, false), Inbound::Forward { .. }));
        }
    }
    let total = rounds as f64 * pkts.len() as f64 * 2.0;
    let s = t.elapsed().as_secs_f64();
    println!("{} sessions: {:.1} Mpps per core ({:.0} ns/packet incl. copying the packet in)", n.stats().sessions, total / s / 1e6, s * 1e9 / total);
}
