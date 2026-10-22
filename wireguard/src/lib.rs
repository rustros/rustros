//! WireGuard for RustROS: the Noise IKpsk2 handshake, transport data,
//! cookies and timers (as in the WireGuard paper and the Linux driver),
//! no_std and free of OS dependencies. The caller moves UDP datagrams and
//! IP packets; this keeps the state.
//!
//! * `handle`: a UDP datagram from the network: handshake messages are
//!   answered (in `out`), data is decrypted and handed back with its peer.
//! * `send`: an IP packet for a peer: encrypted, or queued while a handshake
//!   runs (which `send` starts).
//! * `tick`: retransmissions, rekeying, keepalives, expiry.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use x25519_dalek::{PublicKey, StaticSecret};

pub type Ip = u32;
pub type Key = [u8; 32];
pub type Endpoint = (Ip, u16);

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const INITIATION: u8 = 1;
const RESPONSE: u8 = 2;
const COOKIE_REPLY: u8 = 3;
const DATA: u8 = 4;
const INITIATION_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 64;
/// type, reserved, receiver index, counter
pub const DATA_HEADER: usize = 16;
pub const TAG: usize = 16;

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const REKEY_AFTER_MS: u64 = 120_000;
const REJECT_AFTER_MS: u64 = 180_000;
const REKEY_ATTEMPT_MS: u64 = 90_000;
const REKEY_TIMEOUT_MS: u64 = 5_000;
const KEEPALIVE_MS: u64 = 10_000;
const COOKIE_MS: u64 = 120_000;
/// IP packets kept per peer while a handshake runs.
const QUEUE: usize = 64;
const WINDOW: u64 = 2048;

// ---------------------------------------------------------------- crypto

fn hash(parts: &[&[u8]]) -> Key {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("32-byte key");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// HMAC-BLAKE2s.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Key {
    let mut k = [0u8; 64];
    k[..key.len()].copy_from_slice(key);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Blake2s256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner: Key = inner.finalize().into();
    hash(&[&opad, &inner])
}

fn kdf1(c: &Key, input: &[u8]) -> Key {
    let t0 = hmac(c, &[input]);
    hmac(&t0, &[&[1]])
}

fn kdf2(c: &Key, input: &[u8]) -> (Key, Key) {
    let t0 = hmac(c, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    (t1, t2)
}

fn kdf3(c: &Key, input: &[u8]) -> (Key, Key, Key) {
    let t0 = hmac(c, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    let t3 = hmac(&t0, &[&t2, &[3]]);
    (t1, t2, t3)
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn seal(key: &Key, counter: u64, plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let c = <ChaCha20Poly1305 as KeyInit>::new(key.into());
    c.encrypt(&nonce(counter).into(), Payload { msg: plain, aad }).expect("encryption")
}

fn open(key: &Key, counter: u64, sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let c = <ChaCha20Poly1305 as KeyInit>::new(key.into());
    c.decrypt(&nonce(counter).into(), Payload { msg: sealed, aad }).ok()
}

fn dh(private: &StaticSecret, public: &Key) -> Key {
    private.diffie_hellman(&PublicKey::from(*public)).to_bytes()
}

/// The public key of a private key.
pub fn public_key(private: &Key) -> Key {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// Base64 (standard, padded) as WireGuard writes keys.
pub fn key_from_base64(s: &str) -> Option<Key> {
    let s = s.trim().trim_end_matches('=');
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(33);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in s.as_bytes() {
        acc = acc << 6 | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out.try_into().ok()
}

pub fn key_to_base64(k: &Key) -> alloc::string::String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = alloc::string::String::new();
    for ch in k.chunks(3) {
        let n = ch.iter().enumerate().fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= ch.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

// ---------------------------------------------------------------- state

/// A session's keys (one handshake's worth).
struct Session {
    local: u32,
    remote: u32,
    send: Key,
    recv: Key,
    sent: u64,
    /// highest counter received, and which of the WINDOW below it were
    replay_top: u64,
    replay: [u64; (WINDOW / 64) as usize],
    created: u64,
    /// we sent the initiation (only the initiator rekeys by time)
    initiator: bool,
}

impl Session {
    fn new(local: u32, remote: u32, send: Key, recv: Key, now: u64, initiator: bool) -> Session {
        Session { local, remote, send, recv, sent: 0, replay_top: 0, replay: [0; (WINDOW / 64) as usize], created: now, initiator }
    }

    /// A counter not seen yet (and within the window): mark it.
    /// `replay_top` is the highest counter seen plus one.
    fn accept(&mut self, n: u64) -> bool {
        if n >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let words = self.replay.len() as u64;
        if n >= self.replay_top {
            // newer than all: forget the bits it moves past
            let from = self.replay_top.max((n + 1).saturating_sub(WINDOW));
            for c in from..=n {
                self.replay[(c / 64 % words) as usize] &= !(1u64 << (c % 64));
            }
            self.replay_top = n + 1;
        } else if self.replay_top - n > WINDOW {
            return false; // too old
        }
        let (w, b) = ((n / 64 % words) as usize, 1u64 << (n % 64));
        if self.replay[w] & b != 0 {
            return false;
        }
        self.replay[w] |= b;
        true
    }

    fn alive(&self, now: u64) -> bool {
        now.saturating_sub(self.created) < REJECT_AFTER_MS && self.sent < REJECT_AFTER_MESSAGES
    }
}

/// Our half-done initiation.
struct Initiation {
    local: u32,
    e: StaticSecret,
    c: Key,
    h: Key,
    /// when the first initiation of this attempt went out, and the last
    started: u64,
    sent: u64,
}

pub struct PeerConfig {
    pub public: Key,
    pub psk: Key,
    pub endpoint: Option<Endpoint>,
    /// persistent keepalive, seconds (0: off)
    pub keepalive: u16,
    /// allowed IPs: (net, mask)
    pub allowed: Vec<(Ip, Ip)>,
    /// the three reserved header bytes of what we send (Cloudflare WARP
    /// wants its client id there; zero for everyone else)
    pub reserved: [u8; 3],
}

pub struct Peer {
    pub cfg: PeerConfig,
    /// where it was heard from last (roaming), else the configured one
    pub endpoint: Option<Endpoint>,
    /// HASH(LABEL_MAC1 || its public key): the mac1 key for what we send it
    mac1_key: Key,
    /// DH(our static, its static)
    ss: Key,
    init: Option<Initiation>,
    current: Option<Session>,
    previous: Option<Session>,
    /// a session we answered, waiting for the initiator's first data
    next: Option<Session>,
    /// the newest initiation timestamp accepted from it (replays are dropped)
    last_tai: [u8; 12],
    cookie: Option<([u8; 16], u64)>,
    last_mac1: [u8; 16],
    queue: Vec<Vec<u8>>,
    pub last_sent: u64,
    pub last_received: u64,
    /// when the current session's handshake completed
    pub last_handshake: u64,
    /// data received and not answered yet (a keepalive is due after a while)
    owe_keepalive: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl Peer {
    pub fn is_up(&self) -> bool {
        self.current.is_some() || self.next.is_some()
    }
}

/// What came in.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// a decrypted IP packet from peer `peer` (its allowed IPs checked)
    Packet { peer: usize, data: Vec<u8> },
    Nothing,
}

/// A datagram to send: to `to`, the bytes.
pub type Out = (Endpoint, Vec<u8>);

pub struct Device {
    private: StaticSecret,
    pub public: Key,
    /// HASH(LABEL_MAC1 || our public): checks what is sent to us
    mac1_key: Key,
    pub peers: Vec<Peer>,
    /// our session index -> peer
    by_index: BTreeMap<u32, usize>,
    /// a CSPRNG: BLAKE2s over a seed and a counter
    seed: Key,
    drawn: u64,
}

fn tai64n(unix_ns: u64) -> [u8; 12] {
    let mut t = [0u8; 12];
    t[..8].copy_from_slice(&(0x4000_0000_0000_000Au64 + unix_ns / 1_000_000_000).to_be_bytes());
    // whole milliseconds only, as Linux does (timing side channels)
    t[8..].copy_from_slice(&(((unix_ns % 1_000_000_000) / 1_000_000 * 1_000_000) as u32).to_be_bytes());
    t
}

impl Device {
    /// `seed`: random bytes from the hardware (more with `reseed`).
    pub fn new(private: Key, seed: &[u8]) -> Device {
        let private = StaticSecret::from(private);
        let public = PublicKey::from(&private).to_bytes();
        Device {
            mac1_key: hash(&[LABEL_MAC1, &public]),
            private,
            public,
            peers: Vec::new(),
            by_index: BTreeMap::new(),
            seed: hash(&[b"rustros-wg", seed]),
            drawn: 0,
        }
    }

    pub fn reseed(&mut self, more: &[u8]) {
        self.seed = hash(&[&self.seed, more]);
    }

    fn random(&mut self) -> Key {
        self.drawn += 1;
        hash(&[&self.seed, &self.drawn.to_le_bytes()])
    }

    fn new_index(&mut self, peer: usize) -> u32 {
        loop {
            let r = self.random();
            let i = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
            if i != 0 && !self.by_index.contains_key(&i) {
                self.by_index.insert(i, peer);
                return i;
            }
        }
    }

    fn forget(&mut self, s: Option<Session>) {
        if let Some(s) = s {
            self.by_index.remove(&s.local);
        }
    }

    pub fn add_peer(&mut self, cfg: PeerConfig) -> usize {
        let ss = dh(&self.private, &cfg.public);
        self.peers.push(Peer {
            mac1_key: hash(&[LABEL_MAC1, &cfg.public]),
            endpoint: cfg.endpoint,
            cfg,
            ss,
            init: None,
            current: None,
            previous: None,
            next: None,
            last_tai: [0; 12],
            cookie: None,
            last_mac1: [0; 16],
            queue: Vec::new(),
            last_sent: 0,
            last_received: 0,
            last_handshake: 0,
            owe_keepalive: false,
            rx_bytes: 0,
            tx_bytes: 0,
        });
        self.peers.len() - 1
    }

    /// The peer whose allowed IPs hold `dst` (the longest prefix).
    pub fn peer_for(&self, dst: Ip) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.cfg.allowed.iter().filter(move |&&(n, m)| dst & m == n).map(move |&(_, m)| (m.count_ones(), i)))
            .max()
            .map(|(_, i)| i)
    }

    /// mac1 and mac2 on a handshake message (`m` without them yet).
    fn macs(&mut self, peer: usize, m: &mut Vec<u8>, now: u64) {
        let p = &mut self.peers[peer];
        let m1 = mac(&p.mac1_key, m);
        m.extend_from_slice(&m1);
        p.last_mac1 = m1;
        let m2 = match p.cookie {
            Some((c, at)) if now.saturating_sub(at) < COOKIE_MS => mac(&c, m),
            _ => [0; 16],
        };
        m.extend_from_slice(&m2);
    }

    /// Start a handshake with `peer` (a new initiation).
    fn initiate(&mut self, peer: usize, now: u64, unix_ns: u64, out: &mut Vec<Out>) {
        let Some(to) = self.peers[peer].endpoint else { return };
        let started = self.peers[peer].init.as_ref().map_or(now, |i| i.started);
        if let Some(old) = self.peers[peer].init.take() {
            self.by_index.remove(&old.local);
        }
        let e = StaticSecret::from(self.random());
        let ep = PublicKey::from(&e).to_bytes();
        let local = self.new_index(peer);
        let p = &self.peers[peer];
        let c = hash(&[CONSTRUCTION]);
        let h = hash(&[&c, IDENTIFIER]);
        let h = hash(&[&h, &p.cfg.public]);
        let c = kdf1(&c, &ep);
        let h = hash(&[&h, &ep]);
        let (c, k) = kdf2(&c, &dh(&e, &p.cfg.public));
        let enc_static = seal(&k, 0, &self.public, &h);
        let h = hash(&[&h, &enc_static]);
        let (c, k) = kdf2(&c, &p.ss);
        let enc_ts = seal(&k, 0, &tai64n(unix_ns), &h);
        let h = hash(&[&h, &enc_ts]);
        let mut m = Vec::with_capacity(INITIATION_LEN);
        let rv = self.peers[peer].cfg.reserved;
        m.extend_from_slice(&[INITIATION, rv[0], rv[1], rv[2]]);
        m.extend_from_slice(&local.to_le_bytes());
        m.extend_from_slice(&ep);
        m.extend_from_slice(&enc_static);
        m.extend_from_slice(&enc_ts);
        self.macs(peer, &mut m, now);
        self.peers[peer].init = Some(Initiation { local, e, c, h, started, sent: now });
        self.peers[peer].last_sent = now;
        out.push((to, m));
    }

    /// An IP packet for `peer`: encrypted, or queued until a handshake is done.
    pub fn send(&mut self, now: u64, unix_ns: u64, peer: usize, packet: &[u8], out: &mut Vec<Out>) {
        let Some(p) = self.peers.get_mut(peer) else { return };
        let Some(to) = p.endpoint else { return };
        let usable = p.current.as_ref().is_some_and(|s| s.alive(now));
        if !usable {
            if p.queue.len() < QUEUE {
                p.queue.push(packet.to_vec());
            }
            if p.init.is_none() {
                self.initiate(peer, now, unix_ns, out);
            }
            return;
        }
        let rv = p.cfg.reserved;
        let s = p.current.as_mut().unwrap();
        out.push((to, encrypt(s, packet, rv)));
        p.last_sent = now;
        p.owe_keepalive = false;
        p.tx_bytes += packet.len() as u64;
        // the initiator rekeys after a while (and the session stays usable)
        let s = p.current.as_ref().unwrap();
        if s.initiator && (now.saturating_sub(s.created) >= REKEY_AFTER_MS || s.sent >= REKEY_AFTER_MESSAGES) && p.init.is_none() {
            self.initiate(peer, now, unix_ns, out);
        }
    }

    /// A UDP datagram from `from`.
    pub fn handle(&mut self, now: u64, unix_ns: u64, from: Endpoint, pkt: &[u8], out: &mut Vec<Out>) -> Received {
        match (pkt.first(), pkt.len()) {
            (Some(&INITIATION), INITIATION_LEN) => self.on_initiation(now, unix_ns, from, pkt, out),
            (Some(&RESPONSE), RESPONSE_LEN) => self.on_response(now, unix_ns, from, pkt, out),
            (Some(&COOKIE_REPLY), COOKIE_LEN) => self.on_cookie(now, pkt),
            (Some(&DATA), n) if n >= DATA_HEADER + TAG => return self.on_data(now, unix_ns, from, pkt, out),
            _ => {}
        }
        Received::Nothing
    }

    fn mac1_ok(&self, pkt: &[u8]) -> bool {
        let at = pkt.len() - 32;
        mac(&self.mac1_key, &pkt[..at]) == pkt[at..at + 16]
    }

    fn on_initiation(&mut self, now: u64, _unix_ns: u64, from: Endpoint, m: &[u8], out: &mut Vec<Out>) {
        if !self.mac1_ok(m) {
            return;
        }
        let sender = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let ep: Key = m[8..40].try_into().unwrap();
        let c = hash(&[CONSTRUCTION]);
        let h = hash(&[&c, IDENTIFIER]);
        let h = hash(&[&h, &self.public]);
        let c = kdf1(&c, &ep);
        let h = hash(&[&h, &ep]);
        let (c, k) = kdf2(&c, &dh(&self.private, &ep));
        let Some(stat) = open(&k, 0, &m[40..88], &h) else { return };
        let h = hash(&[&h, &m[40..88]]);
        let Some(peer) = self.peers.iter().position(|p| p.cfg.public[..] == stat[..]) else { return };
        let (c, k) = kdf2(&c, &self.peers[peer].ss);
        let Some(ts) = open(&k, 0, &m[88..116], &h) else { return };
        let h = hash(&[&h, &m[88..116]]);
        // replayed initiations: the timestamp must grow
        let ts: [u8; 12] = ts.try_into().unwrap_or([0; 12]);
        if ts <= self.peers[peer].last_tai {
            return;
        }
        self.peers[peer].last_tai = ts;
        // the response
        let e = StaticSecret::from(self.random());
        let epr = PublicKey::from(&e).to_bytes();
        let local = self.new_index(peer);
        let c = kdf1(&c, &epr);
        let h = hash(&[&h, &epr]);
        let c = kdf1(&c, &dh(&e, &ep));
        let c = kdf1(&c, &dh(&e, &self.peers[peer].cfg.public));
        let (c, t, k) = kdf3(&c, &self.peers[peer].cfg.psk);
        let h = hash(&[&h, &t]);
        let empty = seal(&k, 0, &[], &h);
        let mut r = Vec::with_capacity(RESPONSE_LEN);
        let rv = self.peers[peer].cfg.reserved;
        r.extend_from_slice(&[RESPONSE, rv[0], rv[1], rv[2]]);
        r.extend_from_slice(&local.to_le_bytes());
        r.extend_from_slice(&sender.to_le_bytes());
        r.extend_from_slice(&epr);
        r.extend_from_slice(&empty);
        self.macs(peer, &mut r, now);
        let (t1, t2) = kdf2(&c, &[]);
        // usable once the initiator's first data arrives
        let s = Session::new(local, sender, t2, t1, now, false);
        let old = self.peers[peer].next.replace(s);
        self.forget(old);
        let p = &mut self.peers[peer];
        p.endpoint = Some(from);
        p.last_received = now;
        p.last_sent = now;
        out.push((from, r));
    }

    fn on_response(&mut self, now: u64, unix_ns: u64, from: Endpoint, m: &[u8], out: &mut Vec<Out>) {
        if !self.mac1_ok(m) {
            return;
        }
        let sender = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let receiver = u32::from_le_bytes([m[8], m[9], m[10], m[11]]);
        let Some(&peer) = self.by_index.get(&receiver) else { return };
        let Some(init) = self.peers[peer].init.as_ref().filter(|i| i.local == receiver) else { return };
        let epr: Key = m[12..44].try_into().unwrap();
        let c = kdf1(&init.c, &epr);
        let h = hash(&[&init.h, &epr]);
        let c = kdf1(&c, &dh(&init.e, &epr));
        let c = kdf1(&c, &dh(&self.private, &epr));
        let (c, t, k) = kdf3(&c, &self.peers[peer].cfg.psk);
        let h = hash(&[&h, &t]);
        if open(&k, 0, &m[44..60], &h).is_none() {
            return;
        }
        let (t1, t2) = kdf2(&c, &[]);
        let local = receiver;
        let p = &mut self.peers[peer];
        p.init = None;
        let s = Session::new(local, sender, t1, t2, now, true);
        let prev = p.previous.take();
        p.previous = p.current.replace(s);
        p.endpoint = Some(from);
        p.last_received = now;
        p.last_handshake = now;
        self.forget(prev);
        self.flush(peer, now, unix_ns, out);
    }

    /// Send what waited for the handshake (or a keepalive, which confirms
    /// the session to the responder).
    fn flush(&mut self, peer: usize, now: u64, unix_ns: u64, out: &mut Vec<Out>) {
        let queued = core::mem::take(&mut self.peers[peer].queue);
        if queued.is_empty() {
            self.send(now, unix_ns, peer, &[], out);
        }
        for q in queued {
            self.send(now, unix_ns, peer, &q, out);
        }
    }

    fn on_cookie(&mut self, now: u64, m: &[u8]) {
        let receiver = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let Some(&peer) = self.by_index.get(&receiver) else { return };
        let p = &mut self.peers[peer];
        let key = hash(&[LABEL_COOKIE, &p.cfg.public]);
        let x = <XChaCha20Poly1305 as KeyInit>::new((&key).into());
        let nonce: [u8; 24] = m[8..32].try_into().unwrap();
        if let Ok(c) = x.decrypt(&nonce.into(), Payload { msg: &m[32..64], aad: &p.last_mac1 }) {
            if let Ok(c) = c.try_into() {
                p.cookie = Some((c, now));
            }
        }
    }

    fn on_data(&mut self, now: u64, unix_ns: u64, from: Endpoint, m: &[u8], out: &mut Vec<Out>) -> Received {
        let receiver = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
        let counter = u64::from_le_bytes(m[8..16].try_into().unwrap());
        let Some(&peer) = self.by_index.get(&receiver) else { return Received::Nothing };
        let p = &mut self.peers[peer];
        // which session: current, previous, or the one we just answered
        let slot = [p.current.as_ref(), p.previous.as_ref(), p.next.as_ref()].iter().position(|s| s.is_some_and(|s| s.local == receiver));
        let s = match slot {
            Some(0) => p.current.as_mut(),
            Some(1) => p.previous.as_mut(),
            Some(2) => p.next.as_mut(),
            _ => None,
        };
        let Some(s) = s else { return Received::Nothing };
        if !s.alive(now) {
            return Received::Nothing;
        }
        let Some(plain) = open(&s.recv, counter, &m[DATA_HEADER..], &[]) else { return Received::Nothing };
        if !s.accept(counter) {
            return Received::Nothing;
        }
        // the initiator used the session we answered: it is ours now
        if slot == Some(2) {
            let s = p.next.take();
            let prev = p.previous.take();
            p.previous = p.current.take();
            p.current = s;
            p.last_handshake = now;
            self.forget(prev);
            let p = &mut self.peers[peer];
            let queued = core::mem::take(&mut p.queue);
            p.endpoint = Some(from);
            p.last_received = now;
            for q in queued {
                self.send(now, unix_ns, peer, &q, out);
            }
        }
        let p = &mut self.peers[peer];
        p.endpoint = Some(from);
        p.last_received = now;
        if plain.is_empty() {
            return Received::Nothing; // a keepalive
        }
        p.owe_keepalive = true;
        p.rx_bytes += plain.len() as u64;
        // the real length (the plaintext is padded), and the source must be
        // one the peer may use
        if plain.len() < 20 || plain[0] >> 4 != 4 {
            return Received::Nothing;
        }
        let len = (u16::from_be_bytes([plain[2], plain[3]]) as usize).min(plain.len());
        let src = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
        if !p.cfg.allowed.iter().any(|&(n, mk)| src & mk == n) {
            return Received::Nothing;
        }
        let mut data = plain;
        data.truncate(len);
        Received::Packet { peer, data }
    }

    /// Timers; call every second or so.
    pub fn tick(&mut self, now: u64, unix_ns: u64, out: &mut Vec<Out>) {
        for peer in 0..self.peers.len() {
            let p = &mut self.peers[peer];
            // expiry
            for s in [&mut p.current, &mut p.previous, &mut p.next] {
                if s.as_ref().is_some_and(|s| !s.alive(now)) {
                    let gone = s.take();
                    if let Some(g) = gone {
                        self.by_index.remove(&g.local);
                    }
                }
            }
            let p = &mut self.peers[peer];
            // a handshake that is not answered: again, for a while
            if let Some(i) = p.init.as_ref() {
                if now.saturating_sub(i.started) > REKEY_ATTEMPT_MS {
                    let local = i.local;
                    p.init = None;
                    p.queue.clear();
                    self.by_index.remove(&local);
                } else if now.saturating_sub(i.sent) >= REKEY_TIMEOUT_MS {
                    self.initiate(peer, now, unix_ns, out);
                }
                continue;
            }
            let p = &self.peers[peer];
            let up = p.current.as_ref().is_some_and(|s| s.alive(now));
            // data came and nothing went back: a keepalive
            if up && p.owe_keepalive && now.saturating_sub(p.last_sent) >= KEEPALIVE_MS {
                self.send(now, unix_ns, peer, &[], out);
                continue;
            }
            let p = &self.peers[peer];
            // sent, and nothing heard for a while: handshake again
            if up && p.last_sent > p.last_received && now.saturating_sub(p.last_received) >= KEEPALIVE_MS + REKEY_TIMEOUT_MS {
                self.initiate(peer, now, unix_ns, out);
                continue;
            }
            // persistent keepalive (and the first handshake for peers we
            // keep up)
            let ka = p.cfg.keepalive as u64 * 1000;
            if ka > 0 && now.saturating_sub(p.last_sent) >= ka {
                self.send(now, unix_ns, peer, &[], out);
            }
        }
    }
}

/// A transport message: the packet padded to 16 bytes and sealed.
fn encrypt(s: &mut Session, packet: &[u8], reserved: [u8; 3]) -> Vec<u8> {
    let n = s.sent;
    s.sent += 1;
    let mut plain = packet.to_vec();
    plain.resize(packet.len().div_ceil(16) * 16, 0);
    let mut m = Vec::with_capacity(DATA_HEADER + plain.len() + TAG);
    m.extend_from_slice(&[DATA, reserved[0], reserved[1], reserved[2]]);
    m.extend_from_slice(&s.remote.to_le_bytes());
    m.extend_from_slice(&n.to_le_bytes());
    m.extend_from_slice(&seal(&s.send, n, &plain, &[]));
    m
}

#[cfg(test)]
mod tests;
