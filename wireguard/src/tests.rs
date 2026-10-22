use super::*;

const NOW: u64 = 1_000_000;
const UNIX: u64 = 1_761_000_000_000_000_000;
const A_IP: Ip = 0x0A08_0001; // 10.8.0.1
const B_IP: Ip = 0x0A08_0002;

fn pair() -> (Device, Device) {
    let (ka, kb) = ([1u8; 32], [2u8; 32]);
    let mut a = Device::new(ka, b"a");
    let mut b = Device::new(kb, b"b");
    a.add_peer(PeerConfig { public: public_key(&kb), psk: [7; 32], endpoint: Some((2, 51820)), keepalive: 0, allowed: vec![(B_IP, !0)], reserved: [0; 3] });
    b.add_peer(PeerConfig { public: public_key(&ka), psk: [7; 32], endpoint: None, keepalive: 0, allowed: vec![(A_IP, !0)], reserved: [0; 3] });
    (a, b)
}

fn ipv4(src: Ip, dst: Ip, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend(src.to_be_bytes());
    p.extend(dst.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Deliver every datagram to the other side until both are quiet; what
/// each received.
fn talk(a: &mut Device, b: &mut Device, mut to_b: Vec<Out>, now: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    for _ in 0..10 {
        let mut to_a = Vec::new();
        for (_, m) in to_b.drain(..) {
            if let Received::Packet { data, .. } = b.handle(now, UNIX, (1, 51820), &m, &mut to_a) {
                got_b.push(data);
            }
        }
        for (_, m) in to_a.drain(..) {
            if let Received::Packet { data, .. } = a.handle(now, UNIX, (2, 51820), &m, &mut to_b) {
                got_a.push(data);
            }
        }
        if to_b.is_empty() {
            break;
        }
    }
    (got_a, got_b)
}

#[test]
fn keys_in_base64() {
    let k = public_key(&[3u8; 32]);
    assert_eq!(key_from_base64(&key_to_base64(&k)), Some(k));
    assert_eq!(key_from_base64("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=").map(|k| k[0]), Some(0x6e));
    assert_eq!(key_from_base64("short"), None);
}

#[test]
fn handshake_and_data_both_ways() {
    let (mut a, mut b) = pair();
    let mut out = Vec::new();
    let hello = ipv4(A_IP, B_IP, b"hello");
    a.send(NOW, UNIX, 0, &hello, &mut out);
    assert_eq!(out.len(), 1, "an initiation, the packet queued");
    assert_eq!(out[0].1.len(), INITIATION_LEN);
    let (_, got_b) = talk(&mut a, &mut b, out, NOW);
    assert_eq!(got_b, vec![hello.clone()], "delivered after the handshake");
    assert!(a.peers[0].is_up() && b.peers[0].is_up());
    // and back, on the confirmed session
    let mut out = Vec::new();
    let reply = ipv4(B_IP, A_IP, b"hi back");
    b.send(NOW + 1, UNIX, 0, &reply, &mut out);
    assert_eq!(out.len(), 1);
    let mut back = Vec::new();
    let r = a.handle(NOW + 1, UNIX, (2, 51820), &out[0].1, &mut back);
    assert_eq!(r, Received::Packet { peer: 0, data: reply });
    // a replayed data packet is dropped
    let mut x = Vec::new();
    assert_eq!(a.handle(NOW + 2, UNIX, (2, 51820), &out[0].1, &mut x), Received::Nothing);
}

#[test]
fn spoofed_source_and_wrong_keys() {
    let (mut a, mut b) = pair();
    let mut out = Vec::new();
    a.send(NOW, UNIX, 0, &ipv4(0x0909_0909, B_IP, b"spoof"), &mut out);
    let (_, got_b) = talk(&mut a, &mut b, out, NOW);
    assert!(got_b.is_empty(), "a source outside its allowed IPs is dropped");
    // a stranger's initiation gets nothing
    let mut c = Device::new([9u8; 32], b"c");
    c.add_peer(PeerConfig { public: b.public, psk: [7; 32], endpoint: Some((2, 51820)), keepalive: 0, allowed: vec![(B_IP, !0)], reserved: [0; 3] });
    let mut out = Vec::new();
    c.send(NOW, UNIX, 0, &ipv4(A_IP, B_IP, b"x"), &mut out);
    let mut resp = Vec::new();
    b.handle(NOW, UNIX, (3, 1), &out[0].1, &mut resp);
    assert!(resp.is_empty());
}

#[test]
fn replayed_initiation_is_ignored() {
    let (mut a, mut b) = pair();
    let mut out = Vec::new();
    a.send(NOW, UNIX, 0, &ipv4(A_IP, B_IP, b"x"), &mut out);
    let init = out[0].1.clone();
    let mut r1 = Vec::new();
    b.handle(NOW, UNIX, (1, 1), &init, &mut r1);
    assert_eq!(r1.len(), 1);
    let mut r2 = Vec::new();
    b.handle(NOW + 5, UNIX, (1, 1), &init, &mut r2);
    assert!(r2.is_empty(), "same timestamp again");
}

#[test]
fn timers() {
    let (mut a, mut b) = pair();
    let mut out = Vec::new();
    a.send(NOW, UNIX, 0, &ipv4(A_IP, B_IP, b"x"), &mut out);
    // nobody answers: the initiation is resent every 5 s, for 90 s
    let mut t = NOW;
    let mut resends = 0;
    while t < NOW + 100_000 {
        t += 1000;
        let mut o = Vec::new();
        a.tick(t, UNIX + (t - NOW) * 1_000_000, &mut o);
        resends += o.len();
    }
    assert!((15..=19).contains(&resends), "{resends} resends");
    assert!(a.peers[0].init.is_none(), "gave up");
    // up, then 120 s later the initiator rekeys on the next packet
    let (mut a, mut b2) = pair();
    let mut out = Vec::new();
    a.send(NOW, UNIX, 0, &ipv4(A_IP, B_IP, b"x"), &mut out);
    talk(&mut a, &mut b2, out, NOW);
    let mut o = Vec::new();
    a.send(NOW + REKEY_AFTER_MS, UNIX + 1, 0, &ipv4(A_IP, B_IP, b"y"), &mut o);
    assert_eq!(o.len(), 2, "the packet, and a new initiation");
    let (_, got) = talk(&mut a, &mut b2, o, NOW + REKEY_AFTER_MS);
    assert!(got.iter().any(|p| p.ends_with(b"y")));
    // persistent keepalive
    let _ = &mut b;
    let mut c = Device::new([4u8; 32], b"c");
    c.add_peer(PeerConfig { public: public_key(&[5u8; 32]), psk: [0; 32], endpoint: Some((5, 1)), keepalive: 25, allowed: vec![], reserved: [0; 3] });
    let mut o = Vec::new();
    c.tick(NOW + 26_000, UNIX, &mut o);
    assert_eq!(o.len(), 1, "a handshake to keep the peer up");
}

#[test]
fn reserved_bytes_go_out() {
    let (mut a, mut b) = pair();
    a.peers[0].cfg.reserved = [1, 2, 3];
    let mut out = Vec::new();
    a.send(NOW, UNIX, 0, &ipv4(A_IP, B_IP, b"x"), &mut out);
    assert_eq!(&out[0].1[..4], &[INITIATION, 1, 2, 3]);
    let (_, got) = talk(&mut a, &mut b, out, NOW);
    assert_eq!(got.len(), 1, "the other side does not mind them");
}

#[test]
fn replay_window() {
    let mut s = Session::new(1, 2, [0; 32], [0; 32], 0, true);
    assert!(s.accept(0) && !s.accept(0));
    assert!(s.accept(5) && s.accept(3) && !s.accept(3));
    assert!(s.accept(5000) && !s.accept(5000 - WINDOW - 1) && s.accept(5000 - 10));
    assert!(s.accept(4000 - 1 + WINDOW) && !s.accept(4000 - 1 + WINDOW));
}
