use super::*;

/// An Ethernet + IPv4 + UDP/TCP frame of `size` bytes from port `sport`.
fn pkt(sport: u16, size: usize, ecn: u8, proto: u8) -> Vec<u8> {
    let mut f = vec![0u8; size.max(ETH + 28)];
    f[12..14].copy_from_slice(&[8, 0]);
    f[ETH] = 0x45;
    f[ETH + 1] = ecn;
    f[ETH + 9] = proto;
    f[ETH + 12..ETH + 16].copy_from_slice(&[10, 0, 0, 2]);
    f[ETH + 16..ETH + 20].copy_from_slice(&[203, 0, 113, 9]);
    f[ETH + 20..ETH + 22].copy_from_slice(&sport.to_be_bytes());
    f[ETH + 22..ETH + 24].copy_from_slice(&443u16.to_be_bytes());
    // a valid header checksum, to check the ECN mark keeps it valid
    let mut s: u32 = 0;
    for i in (ETH..ETH + 20).step_by(2) {
        s += u16::from_be_bytes([f[i], f[i + 1]]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    f[ETH + 10..ETH + 12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    f
}

fn hdr_ok(f: &[u8]) -> bool {
    let mut s: u32 = 0;
    for i in (ETH..ETH + 20).step_by(2) {
        s += u16::from_be_bytes([f[i], f[i + 1]]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s == 0xFFFF
}

const MS: u64 = 1_000_000;

/// Poll like the main loop, every 100 µs from `from` to `to`.
fn run(s: &mut Shaper, from: u64, to: u64) -> Vec<Pkt> {
    let mut out = Vec::new();
    let mut t = from;
    while t < to {
        s.release(t, &mut out);
        t += 100_000;
    }
    out
}

#[test]
fn rates() {
    assert_eq!(parse_rate("100mbit"), Some(100_000_000));
    assert_eq!(parse_rate("200M"), Some(200_000_000));
    assert_eq!(parse_rate("1.5gbit"), Some(1_500_000_000));
    assert_eq!(parse_rate("512kbit"), Some(512_000));
    assert_eq!(parse_rate("100000000"), Some(100_000_000));
    assert_eq!(parse_rate("fast"), None);
    assert_eq!(parse_rate("1k"), None, "below 64 kbit");
}

#[test]
fn shapes_to_the_rate() {
    let mut s = Shaper::new(100_000_000, 0, 64 << 20);
    for i in 0..20_000 {
        s.enqueue(0, pkt(1000 + (i % 7) as u16, 1500, 0, 17), rustros_api::Offload::default(), 1);
    }
    let mut out = Vec::new();
    let mut bytes = 0u64;
    // one second in 100 µs steps (as the poll loop would)
    let mut t = 0;
    while t < 1000 * MS {
        s.release(t, &mut out);
        bytes += out.drain(..).map(|p| p.data.len() as u64).sum::<u64>();
        t += 100_000;
    }
    let mbit = bytes * 8 / 1_000_000;
    assert!((99..=101).contains(&mbit), "{mbit} Mbit in a second");
}

#[test]
fn flows_share_fairly() {
    let mut s = Shaper::new(10_000_000, 0, 64 << 20);
    for _ in 0..200 {
        s.enqueue(0, pkt(1, 1500, 0, 6), rustros_api::Offload::default(), 1); // a bulk flow
    }
    for _ in 0..20 {
        s.enqueue(0, pkt(2, 1500, 0, 6), rustros_api::Offload::default(), 1); // a second one
    }
    let out = run(&mut s, 0, 40 * MS); // ~33 packets at 10 Mbit
    let second = out.iter().filter(|p| p.data[ETH + 21] == 2).count();
    assert!(second * 3 >= out.len(), "{second} of {} from the second flow", out.len());
}

#[test]
fn new_flow_goes_first() {
    let mut s = Shaper::new(10_000_000, 0, 64 << 20);
    for _ in 0..100 {
        s.enqueue(0, pkt(1, 1500, 0, 6), rustros_api::Offload::default(), 1);
    }
    run(&mut s, 0, 10 * MS);
    // a small packet of a new flow (DNS, a keystroke) jumps the bulk queue
    s.enqueue(10 * MS, pkt(53, 80, 0, 17), rustros_api::Offload::default(), 1);
    let out = run(&mut s, 10 * MS, 14 * MS);
    assert!(out.iter().take(2).any(|p| p.data[ETH + 21] == 53), "sparse flow waited");
}

#[test]
fn a_flood_does_not_delay_others() {
    // an unresponsive flow offering twice the rate for two seconds, and a
    // small flow (a game, a call) beside it
    let mut s = Shaper::new(10_000_000, 0, 64 << 20);
    let mut out = Vec::new();
    let mut small = Vec::new();
    let mut t = 0;
    while t < 2000 * MS {
        if t % (6 * MS / 10) == 0 {
            s.enqueue(t, pkt(1, 1500, 0, 6), rustros_api::Offload::default(), 1); // 20 Mbit offered
        }
        if t % (10 * MS) == 0 {
            s.enqueue(t, pkt(7, 120, 0, 17), rustros_api::Offload::default(), 1);
        }
        s.release(t, &mut out);
        for p in out.drain(..) {
            if p.data[ETH + 21] == 7 {
                small.push(t - p.enq_ns);
            }
        }
        t += 100_000;
    }
    assert!(s.stats.aqm_drops > 30, "CoDel works on the flood: {} drops", s.stats.aqm_drops);
    let avg = small.iter().sum::<u64>() / small.len() as u64;
    assert!(small.len() > 190 && avg < 3 * MS, "the small flow: {} packets, average delay {} us", small.len(), avg / 1000);
}

#[test]
fn ecn_marks_instead_of_dropping() {
    let mut s = Shaper::new(10_000_000, 0, 64 << 20);
    let mut out = Vec::new();
    let mut marked = 0;
    let mut t = 0;
    while t < 2000 * MS {
        if t % (6 * MS / 10) == 0 {
            s.enqueue(t, pkt(1, 1500, 2, 6), rustros_api::Offload::default(), 1); // ECT(0)
        }
        s.release(t, &mut out);
        for p in out.drain(..) {
            if p.data[ETH + 1] & 3 == 3 {
                marked += 1;
                assert!(hdr_ok(&p.data), "checksum after marking");
            }
        }
        t += 100_000;
    }
    assert!(marked > 50, "{marked} marked");
    assert_eq!(s.stats.aqm_drops, 0);
}

#[test]
fn limit_drops_from_the_fattest() {
    let mut s = Shaper::new(10_000_000, 0, 100_000);
    for _ in 0..200 {
        s.enqueue(0, pkt(1, 1500, 0, 6), rustros_api::Offload::default(), 1);
    }
    s.enqueue(0, pkt(2, 1500, 0, 6), rustros_api::Offload::default(), 1);
    assert!(s.backlog() <= 100_000);
    assert!(s.stats.overflow_drops > 100);
    let out = run(&mut s, 0, 10 * MS);
    assert!(out.iter().any(|p| p.data[ETH + 21] == 2), "the small flow survived");
}

#[test]
fn what_is_never_shaped() {
    let mut arp = vec![0u8; 60];
    arp[12..14].copy_from_slice(&[8, 6]);
    assert!(exempt(&arp));
    let mut upd = pkt(9000, 100, 0, 6);
    assert!(exempt(&upd));
    upd[ETH + 20..ETH + 22].copy_from_slice(&55555u16.to_be_bytes());
    upd[ETH + 22..ETH + 24].copy_from_slice(&9000u16.to_be_bytes());
    assert!(exempt(&upd));
    assert!(!exempt(&pkt(1234, 100, 0, 6)));
    assert!(!exempt(&pkt(9000, 100, 0, 17)), "UDP 9000 is shaped");
}
