use super::*;

const PEER: Peer = (0xC633_6407, 50000); // 198.51.100.7:50000

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ip {
    u32::from_be_bytes([a, b, c, d])
}

/// A minimal L2TP client.
struct Client {
    peer: Peer,
    tid: u16,
    sid: u16,
    ns: u16,
    nr: u16,
    /// server's tunnel and session ids
    stid: u16,
    ssid: u16,
}

impl Client {
    fn new(peer: Peer) -> Client {
        Client { peer, tid: 77, sid: 5, ns: 0, nr: 0, stid: 0, ssid: 0 }
    }

    fn ctl(&mut self, session: u16, msg: u16, extra: &[(u16, &[u8])]) -> Vec<u8> {
        let mut a = Vec::new();
        avp(&mut a, AVP_MESSAGE_TYPE, &msg.to_be_bytes());
        for (t, v) in extra {
            avp(&mut a, *t, v);
        }
        let len = 12 + a.len();
        let mut p = Vec::new();
        p.extend(0xC802u16.to_be_bytes());
        p.extend((len as u16).to_be_bytes());
        p.extend(self.stid.to_be_bytes());
        p.extend(session.to_be_bytes());
        p.extend(self.ns.to_be_bytes());
        p.extend(self.nr.to_be_bytes());
        p.extend(a);
        self.ns += 1;
        p
    }

    fn ppp(&self, proto: u16, payload: &[u8]) -> Vec<u8> {
        ppp(&Route { peer: self.peer, tunnel: self.stid, session: self.ssid }, proto, payload)
    }
}

struct Rig {
    s: Server,
    out: Vec<(Peer, Vec<u8>)>,
    ev: Vec<Event>,
    now: u64,
}

impl Rig {
    fn new(cfg: Config) -> Rig {
        Rig { s: Server::new(cfg), out: Vec::new(), ev: Vec::new(), now: 0 }
    }
    fn send(&mut self, peer: Peer, p: &[u8]) -> Vec<Vec<u8>> {
        self.out.clear();
        self.s.handle(self.now, peer, p, &mut self.out, &mut self.ev);
        self.out.iter().map(|(to, p)| {
            assert_eq!(*to, peer);
            p.clone()
        }).collect()
    }
}

/// Control message type of a reply (None for a ZLB).
fn msg_type(p: &[u8]) -> Option<u16> {
    let h = parse_header(p).unwrap();
    assert!(h.control);
    parse_avps(&p[h.payload..]).iter().find(|a| a.0 == AVP_MESSAGE_TYPE).and_then(|a| be16(a.1, 0))
}

fn avp16(p: &[u8], ty: u16) -> u16 {
    let h = parse_header(p).unwrap();
    parse_avps(&p[h.payload..]).iter().find(|a| a.0 == ty).and_then(|a| be16(a.1, 0)).unwrap()
}

/// (PPP protocol, code, id, data) of a data packet.
fn ppp_of(p: &[u8]) -> (u16, u8, u8, Vec<u8>) {
    let h = parse_header(p).unwrap();
    assert!(!h.control);
    let f = &p[h.payload..];
    let (proto, off) = ppp_proto(f).unwrap();
    let f = &f[off..];
    (proto, f[0], f[1], f[4..].to_vec())
}

/// Tunnel + session up to the start of PPP; returns the server's LCP request.
fn connect(r: &mut Rig, c: &mut Client) -> Vec<u8> {
    let p = c.ctl(0, SCCRQ, &[(AVP_ASSIGNED_TUNNEL_ID, &c.tid.to_be_bytes())]);
    let rep = r.send(c.peer, &p);
    assert_eq!(msg_type(&rep[0]), Some(SCCRP));
    c.stid = avp16(&rep[0], AVP_ASSIGNED_TUNNEL_ID);
    assert_eq!(&rep[0][4..6], &c.tid.to_be_bytes(), "addressed to our tunnel id");
    c.nr = 1;
    let p = c.ctl(0, 3, &[]); // SCCCN
    assert_eq!(msg_type(&r.send(c.peer, &p)[0]), None, "ZLB");
    let p = c.ctl(0, ICRQ, &[(AVP_ASSIGNED_SESSION_ID, &c.sid.to_be_bytes())]);
    let rep = r.send(c.peer, &p);
    assert_eq!(msg_type(&rep[0]), Some(ICRP));
    c.ssid = avp16(&rep[0], AVP_ASSIGNED_SESSION_ID);
    c.nr = 2;
    let p = c.ctl(c.ssid, ICCN, &[]);
    let rep = r.send(c.peer, &p);
    assert_eq!(rep.len(), 2);
    let (proto, code, _, _) = ppp_of(&rep[0]);
    assert_eq!((proto, code), (PROTO_LCP, 1), "LCP request starts PPP");
    rep[0].clone()
}

/// LCP both ways, then PAP (if `auth`) and IPCP; returns the address.
fn ppp_up(r: &mut Rig, c: &mut Client, auth: Option<(&str, &str)>) -> Option<Ip> {
    // client request: MRU + magic + a callback option we must reject
    let req = cp(1, 1, &[1, 4, 0x05, 0x78, 5, 6, 1, 2, 3, 4, 13, 3, 6]);
    let rep = r.send(c.peer, &c.ppp(PROTO_LCP, &req));
    let (_, code, _, data) = ppp_of(&rep[0]);
    assert_eq!((code, data), (4, vec![13, 3, 6]), "callback rejected");
    let req = cp(1, 2, &[1, 4, 0x05, 0x78, 5, 6, 1, 2, 3, 4]);
    let rep = r.send(c.peer, &c.ppp(PROTO_LCP, &req));
    assert_eq!(ppp_of(&rep[0]).1, 2, "ack");
    // ack the server's request (it was resent with the reply)
    let ours = ppp_of(&rep[1]);
    assert_eq!(ours.1, 1);
    r.send(c.peer, &c.ppp(PROTO_LCP, &cp(2, ours.2, &ours.3)));
    if let Some((u, pw)) = auth {
        let mut d = vec![u.len() as u8];
        d.extend(u.as_bytes());
        d.push(pw.len() as u8);
        d.extend(pw.as_bytes());
        let rep = r.send(c.peer, &c.ppp(PROTO_PAP, &cp(1, 9, &d)));
        if ppp_of(&rep[0]).1 != 2 {
            return None;
        }
    }
    // IPCP: ask for 0.0.0.0, get a Nak with the address, ask again
    let rep = r.send(c.peer, &c.ppp(PROTO_IPCP, &cp(1, 1, &[3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0])));
    assert_eq!(ppp_of(&rep[0]).1, 1, "server's own IPCP request");
    assert_eq!(ppp_of(&rep[0]).3, [3, 6, 10, 0, 0, 1]);
    let (_, code, _, nak) = ppp_of(&rep[1]);
    assert_eq!(code, 3);
    let addr = u32::from_be_bytes(nak[2..6].try_into().unwrap());
    assert_eq!(&nak[6..], &[129, 6, 8, 8, 8, 8]);
    let rep = r.send(c.peer, &c.ppp(PROTO_IPCP, &cp(1, 2, &nak)));
    assert_eq!(ppp_of(&rep[0]).1, 2, "IPCP ack");
    Some(addr)
}

fn ip_packet(src: Ip, dst: Ip) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend(src.to_be_bytes());
    p.extend(dst.to_be_bytes());
    p.extend([0u8; 8]);
    p
}

#[test]
fn open_server_full_session() {
    let mut r = Rig::new(Config::default());
    let mut c = Client::new(PEER);
    connect(&mut r, &mut c);
    let addr = ppp_up(&mut r, &mut c, None).unwrap();
    assert_eq!(addr, ip(10, 0, 0, 2));
    assert!(r.ev.contains(&Event::Up { ip: addr, peer: PEER, user: String::new(), egress: None }));

    // data: fast path finds the IP packet
    let pkt = c.ppp(PROTO_IP, &ip_packet(addr, ip(1, 1, 1, 1)));
    assert_eq!(r.s.classify(1, PEER, &pkt), Data::Ip { client: addr, offset: 10 });
    // compressed address/control and protocol fields
    let mut short = pkt[..6].to_vec();
    short.push(0x21);
    short.extend(ip_packet(addr, ip(1, 1, 1, 1)));
    assert_eq!(r.s.classify(1, PEER, &short), Data::Ip { client: addr, offset: 7 });
    // spoofed source, wrong peer, LCP
    assert_eq!(r.s.classify(1, PEER, &c.ppp(PROTO_IP, &ip_packet(ip(10, 0, 0, 9), 1))), Data::Drop);
    assert_eq!(r.s.classify(1, (1, 2), &pkt), Data::Drop);
    assert_eq!(r.s.classify(1, PEER, &c.ppp(PROTO_LCP, &cp(9, 1, &[0; 4]))), Data::Control);

    let route = r.s.route(addr).unwrap();
    assert_eq!(route, Route { peer: PEER, tunnel: c.tid, session: c.sid });
    assert_eq!(data_header(&route), [0, 2, 0, 77, 0, 5, 0xff, 3, 0, 0x21]);

    // LCP echo is answered
    let rep = r.send(PEER, &c.ppp(PROTO_LCP, &cp(9, 4, &[1, 2, 3, 4, 0xAA])));
    assert_eq!(ppp_of(&rep[0]), (PROTO_LCP, 10, 4, vec![0, 0, 0, 0, 0xAA]));

    // the session ends
    let p = c.ctl(c.ssid, CDN, &[]);
    r.send(PEER, &p);
    assert!(r.ev.contains(&Event::Down { ip: addr }));
    assert_eq!(r.s.route(addr), None);
    assert_eq!(r.s.classify(1, PEER, &pkt), Data::Drop);
}

fn accounts() -> Config {
    Config {
        accounts: vec![
            Account { user: String::from("alice"), password: String::from("s3cret"), egress: Some(ip(203, 0, 113, 2)) },
            Account { user: String::from("bob"), password: String::from("pw"), egress: None },
        ],
        ..Config::default()
    }
}

#[test]
fn pap_accounts_and_egress() {
    let mut r = Rig::new(accounts());
    let mut c = Client::new(PEER);
    let req = connect(&mut r, &mut c);
    assert!(ppp_of(&req).3.ends_with(&[3, 4, 0xc0, 0x23]), "asks for PAP");
    // before authentication no IP gets through
    let addr = ip(10, 0, 0, 2);
    assert_eq!(r.s.classify(0, PEER, &c.ppp(PROTO_IP, &ip_packet(addr, 1))), Data::Drop);
    assert_eq!(ppp_up(&mut r, &mut c, Some(("alice", "s3cret"))), Some(addr));
    assert!(r.ev.contains(&Event::Up { ip: addr, peer: PEER, user: String::from("alice"), egress: Some(ip(203, 0, 113, 2)) }));
    assert!(matches!(r.s.classify(0, PEER, &c.ppp(PROTO_IP, &ip_packet(addr, 1))), Data::Ip { .. }));
}

#[test]
fn wrong_password_is_refused() {
    let mut r = Rig::new(accounts());
    let mut c = Client::new(PEER);
    connect(&mut r, &mut c);
    assert_eq!(ppp_up(&mut r, &mut c, Some(("alice", "nope"))), None);
    assert!(r.ev.iter().any(|e| matches!(e, Event::AuthFailed { user, .. } if user == "alice")));
    assert!(!r.ev.iter().any(|e| matches!(e, Event::Up { .. })));
    assert_eq!(r.s.classify(0, PEER, &c.ppp(PROTO_IP, &ip_packet(ip(10, 0, 0, 2), 1))), Data::Drop);
}

#[test]
fn client_without_pap() {
    // open server: drops PAP from its request
    let mut r = Rig::new(Config::default());
    let mut c = Client::new(PEER);
    let req = connect(&mut r, &mut c);
    let (_, _, id, data) = ppp_of(&req);
    let rep = r.send(PEER, &c.ppp(PROTO_LCP, &cp(4, id, &data[4..])));
    assert_eq!(ppp_of(&rep[0]).3, [1, 4, 0x05, 0x78], "request again without PAP");
    // with accounts: refuses
    let mut r = Rig::new(accounts());
    let mut c = Client::new(PEER);
    let req = connect(&mut r, &mut c);
    let (_, _, id, data) = ppp_of(&req);
    let rep = r.send(PEER, &c.ppp(PROTO_LCP, &cp(4, id, &data[4..])));
    assert_eq!(ppp_of(&rep[0]).1, 5, "terminate");
    assert!(r.ev.contains(&Event::NoPap { peer: PEER }));
}

#[test]
fn retransmission_only_acknowledged() {
    let mut r = Rig::new(Config::default());
    let mut c = Client::new(PEER);
    connect(&mut r, &mut c);
    // the ICRQ again (old Ns): just a ZLB, no second session
    c.ns = 2;
    let p = c.ctl(0, ICRQ, &[(AVP_ASSIGNED_SESSION_ID, &9u16.to_be_bytes())]);
    let rep = r.send(PEER, &p);
    assert_eq!(rep.len(), 1);
    assert_eq!(msg_type(&rep[0]), None);
    assert_eq!(r.s.sessions().count(), 1);
}

#[test]
fn several_clients_get_their_own_addresses() {
    let mut r = Rig::new(Config::default());
    let mut addrs = Vec::new();
    for k in 0..3 {
        let mut c = Client::new((PEER.0 + k, 40000));
        connect(&mut r, &mut c);
        addrs.push(ppp_up(&mut r, &mut c, None).unwrap());
    }
    assert_eq!(addrs, [ip(10, 0, 0, 2), ip(10, 0, 0, 3), ip(10, 0, 0, 4)]);
    assert_ne!(r.s.route(addrs[0]).unwrap().peer, r.s.route(addrs[1]).unwrap().peer);
}

#[test]
fn reconnect_and_stopccn_and_idle() {
    let mut r = Rig::new(Config::default());
    let mut c = Client::new(PEER);
    connect(&mut r, &mut c);
    let a = ppp_up(&mut r, &mut c, None).unwrap();
    // the client restarts with a new tunnel id from the same address
    let mut c2 = Client::new(PEER);
    c2.tid = 78;
    connect(&mut r, &mut c2);
    assert!(r.ev.contains(&Event::Down { ip: a }));
    let b = ppp_up(&mut r, &mut c2, None).unwrap();
    assert_eq!(a, b, "the address was freed and reused");
    // StopCCN drops the tunnel
    let p = c2.ctl(0, STOPCCN, &[]);
    r.ev.clear();
    r.send(PEER, &p);
    assert!(r.ev.contains(&Event::Down { ip: b }));
    assert_eq!(r.s.sessions().count(), 0);
    // a silent tunnel is dropped
    let mut c3 = Client::new(PEER);
    c3.tid = 79;
    connect(&mut r, &mut c3);
    r.ev.clear();
    r.s.tick(299_000, &mut r.ev);
    assert!(r.ev.is_empty());
    r.s.tick(301_000, &mut r.ev);
    assert!(matches!(r.ev[..], [Event::Down { .. }]));
}

#[test]
fn pool_full() {
    let mut r = Rig::new(Config::default());
    for k in 0..253 {
        let mut c = Client::new((PEER.0 + k, 1));
        connect(&mut r, &mut c);
    }
    let mut c = Client::new((PEER.0 + 999, 1));
    let p = c.ctl(0, SCCRQ, &[(AVP_ASSIGNED_TUNNEL_ID, &c.tid.to_be_bytes())]);
    let rep = r.send(c.peer, &p);
    c.stid = avp16(&rep[0], AVP_ASSIGNED_TUNNEL_ID);
    c.nr = 1;
    let p = c.ctl(0, ICRQ, &[(AVP_ASSIGNED_SESSION_ID, &c.sid.to_be_bytes())]);
    let rep = r.send(c.peer, &p);
    assert_eq!(msg_type(&rep[0]), None);
    assert!(r.ev.contains(&Event::PoolFull { peer: c.peer }));
}

#[test]
fn garbage_does_not_panic() {
    let mut r = Rig::new(accounts());
    let mut c = Client::new(PEER);
    connect(&mut r, &mut c);
    let samples = [c.ppp(PROTO_LCP, &cp(1, 1, &[1, 4, 5, 0x78])), c.ppp(PROTO_PAP, &cp(1, 1, &[5, b'a', 1, b'b'])), c.ctl(0, ICRQ, &[(14, &[0, 1])])];
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for k in 0..20_000 {
        let mut p = samples[k % samples.len()].clone();
        for _ in 0..1 + rnd() % 3 {
            let i = (rnd() % p.len() as u64) as usize;
            p[i] = rnd() as u8;
        }
        p.truncate((rnd() % (p.len() as u64 + 1)) as usize);
        let _ = r.s.classify(k as u64, PEER, &p);
        r.send(PEER, &p);
    }
}
