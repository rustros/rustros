//! AnyTLS server module (anytls-go's protocol, version 2, as sing-box and
//! mihomo speak it), any number of instances.
//!
//! A client makes TLS with the instance's certificate, sends the SHA-256 of
//! its password and some padding, then frames: command (1 byte), stream id
//! (4), length (2), data. A stream's first data is its target, written as
//! SOCKS5 writes an address; `sp.v2.udp-over-tcp.arpa` (v1:
//! `sp.udp-over-tcp.arpa`) is UDP, as sing-box carries it over TCP.
//!
//! Settings (`cfg anytls <instance>.<key> <value>`):
//!
//! ```text
//! <i>.listen      443          the port (an instance without one is off)
//! <i>.bind        a.b.c.d|nic1 only connections to this address of ours
//! <i>.cert        PEM          certificate and chain (one line: the newlines as
//!                              spaces or \n)
//! <i>.key         PEM          its private key (ECDSA P-256, Ed25519, RSA; secret)
//! <i>.user.<name> password     who may use it
//! <i>.egress      a.b.c.d|nic1 TCP to targets from this address (its WAN)
//! <i>.allow       10.0.0.0/8,… who may connect (default: anyone)
//! <i>.dns         1.1.1.1      resolver for targets' names
//! <i>.max         64           sessions at once
//! <i>.log         on           print sessions and streams
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use rustros_api::socket::{SockAddr, Socket};
use rustros_api::{Caps, Module, Net, Param, Sys, say};
use rustros_util::conn::Conn;
use rustros_util::dns::{Looked, Lookup};
use rustros_util::sha256::Sha256;
use rustros_util::wire::{Ip, IpFmt, parse_ip, parse_net};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

/// The padding scheme here: anytls-go's default, as it is written there
/// (its MD5 is what a client using it says it has).
const PADDING: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
const PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

const UOT_V2: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_V1: &str = "sp.udp-over-tcp.arpa";

const RELOAD_MS: u64 = 2000;
const DNS_DEFAULT: Ip = 0x0101_0101;
/// TLS, the password and a stream's target must come by then.
const SETUP_MS: u64 = 30_000;
const CONNECT_MS: u64 = 15_000;
/// A session with no stream may be silent this long.
const IDLE_MS: u64 = 120_000;
/// A UDP stream silent this long (both ways) is ended.
const UDP_IDLE_MS: u64 = 300_000;
/// What is read from a target at once, for one frame.
const CHUNK: usize = 16 * 1024;
/// Output a session may have waiting before its targets are read no more.
const MAX_OUT: usize = 512 * 1024;
/// Client data a stream may hold for its target.
const MAX_IN: usize = 512 * 1024;
const DNS_CACHE: usize = 256;
const DNS_TTL_MS: u64 = 60_000;

struct Instance {
    name: String,
    port: u16,
    bind: Ip,
    egress: Ip,
    allow: Vec<(Ip, Ip)>,
    /// (name, SHA-256 of the password)
    users: Vec<(String, [u8; 32])>,
    config: Arc<tls::RustlsServerConfig>,
    dns: Ip,
    max: usize,
    log: bool,
    // counters
    sessions: usize,
    total: u64,
    bytes: u64,
    refused: u64,
}

enum Phase {
    /// TLS
    Handshake,
    /// the password's hash and the padding
    Auth,
    Frames,
}

enum StreamPhase {
    /// reading the target
    Target,
    Resolve(Lookup),
    Connecting(Conn),
    Relay(Conn),
    /// v2's request: whether all packets go to one target, and that target
    UdpRequest,
    Udp(Udp),
}

struct Udp {
    sock: Socket,
    /// all packets to this one (v2, connect)
    one: Option<SockAddr>,
    /// a packet waiting for its target's name: (lookup, name, port, data)
    waiting: Option<(Lookup, String, u16, Vec<u8>)>,
    last: u64,
}

struct Stream {
    phase: StreamPhase,
    /// what the client sent, not yet passed on
    input: Vec<u8>,
    host: String,
    port: u16,
    udp_v2: bool,
    deadline: u64,
}

struct Session {
    inst: String,
    user: String,
    c: Conn,
    tls: tls::Tls,
    phase: Phase,
    /// plaintext from the client, not yet taken apart
    plain: Vec<u8>,
    /// frames to send
    out: Vec<u8>,
    streams: BTreeMap<u32, Stream>,
    settled: bool,
    version: u32,
    deadline: u64,
    last: u64,
}

#[derive(Default)]
pub struct AnyTls {
    instances: Vec<Instance>,
    listeners: BTreeMap<u16, Socket>,
    sessions: Vec<Session>,
    closing: Vec<(Conn, u64)>,
    dns_cache: BTreeMap<String, (Ip, u64)>,
    applied: String,
    said: BTreeMap<String, String>,
    reload_at: u64,
}

fn get<'a>(s: &[(&str, &'a str)], k: &str) -> Option<&'a str> {
    s.iter().find(|(x, _)| *x == k).map(|(_, v)| *v)
}

fn addr_of(ifs: &[(String, Ip, Ip, Ip)], v: &str) -> Option<Ip> {
    parse_ip(v).or_else(|| ifs.iter().find(|f| f.0 == v).map(|f| f.1).filter(|&a| a != 0))
}

fn frame(out: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// An address and port at the start of `b`, its kinds by the bytes given
/// (SOCKS5's: 1 IPv4, 3 a name, 4 IPv6; udp-over-tcp's packets: 0, 2, 1).
/// None: more bytes are needed; Some(Err): not one we take.
fn read_addr(b: &[u8], v4: u8, name: u8, v6: u8) -> Option<Result<(String, u16, usize), String>> {
    let t = *b.first()?;
    let (host, at) = if t == v4 {
        let a = b.get(1..5)?;
        (format!("{}", IpFmt(u32::from_be_bytes([a[0], a[1], a[2], a[3]]))), 5)
    } else if t == name {
        let l = *b.get(1)? as usize;
        let n = b.get(2..2 + l)?;
        (String::from_utf8_lossy(n).into_owned(), 2 + l)
    } else if t == v6 {
        b.get(..19)?;
        return Some(Err(String::from("IPv6 is not supported")));
    } else {
        return Some(Err(format!("address type {t}")));
    };
    let p = b.get(at..at + 2)?;
    Some(Ok((host, u16::from_be_bytes([p[0], p[1]]), at + 2)))
}

impl AnyTls {
    pub fn new() -> AnyTls {
        AnyTls::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        let ifs: Vec<(String, Ip, Ip, Ip)> = (0..net.nic_count()).filter_map(|i| net.nic_info(i).map(|n| (net.nic_name(i), n.ip, n.mask, n.gw))).collect();
        let Some(kv) = sys.kv() else { return };
        let mut settings: Vec<(String, String)> = kv
            .keys("cfg/")
            .into_iter()
            .filter_map(|k| {
                let v = kv.get(&k)?;
                Some((String::from(&k[4..]), String::from_utf8_lossy(&v).into_owned()))
            })
            .collect();
        settings.sort();
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).chain(ifs.iter().map(|f| format!("{}={}/{};", f.0, f.1, f.2))).collect();
        if text == self.applied {
            return;
        }
        self.applied = text;
        let mut by: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
        for (k, v) in &settings {
            if let Some((i, key)) = k.split_once('.') {
                by.entry(i).or_default().push((key, v.trim()));
            }
        }
        let mut old: BTreeMap<String, (usize, u64, u64, u64)> = self.instances.drain(..).map(|i| (i.name, (i.sessions, i.total, i.bytes, i.refused))).collect();
        let mut said = BTreeMap::new();
        for (name, s) in &by {
            let line = match Self::instance(name, s, &ifs) {
                Ok(mut i) => {
                    let (sessions, total, bytes, refused) = old.remove(*name).unwrap_or_default();
                    (i.sessions, i.total, i.bytes, i.refused) = (sessions, total, bytes, refused);
                    let line = format!(
                        "anytls: {} on {}:{}, {} users, out from {}\n",
                        i.name,
                        if i.bind == 0 { String::from("*") } else { format!("{}", IpFmt(i.bind)) },
                        i.port,
                        i.users.len(),
                        if i.egress == 0 { String::from("the route's address") } else { format!("{}", IpFmt(i.egress)) }
                    );
                    if let Some(o) = self.instances.iter().find(|o| o.port == i.port && o.bind == i.bind) {
                        format!("anytls: {}: port {} already taken by {}\n", i.name, i.port, o.name)
                    } else {
                        self.instances.push(i);
                        line
                    }
                }
                Err(e) => format!("anytls: {name}: {e}\n"),
            };
            said.insert(String::from(*name), line);
        }
        for (name, line) in &said {
            if self.said.get(name) != Some(line) {
                sys.print(line);
            }
        }
        for name in self.said.keys().filter(|n| !said.contains_key(*n)) {
            say!(sys, "anytls: {}: removed\n", name);
        }
        self.said = said;
        let Some(net) = sys.net() else { return };
        let ports: Vec<u16> = self.instances.iter().map(|i| i.port).collect();
        self.listeners.retain(|port, l| {
            let keep = ports.contains(port);
            if !keep {
                let _ = net.close(*l);
            }
            keep
        });
        for p in ports {
            if !self.listeners.contains_key(&p) {
                match rustros_util::sock::tcp_listen(net, p) {
                    Ok(l) => {
                        self.listeners.insert(p, l);
                    }
                    Err(e) => say!(net, "anytls: cannot listen on {}: {:?}\n", p, e),
                }
            }
        }
        let names: Vec<&str> = self.instances.iter().map(|i| i.name.as_str()).collect();
        self.sessions.retain_mut(|s| {
            let keep = names.contains(&s.inst.as_str());
            if !keep {
                end_session(net, s);
            }
            keep
        });
    }

    /// An instance from its settings, or why it is off.
    fn instance(name: &str, s: &[(&str, &str)], ifs: &[(String, Ip, Ip, Ip)]) -> Result<Instance, String> {
        let port = get(s, "listen").and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0).ok_or_else(|| format!("off (cfg anytls {name}.listen 443)"))?;
        let addr = |key: &str| match get(s, key) {
            None | Some("") | Some("any") => Ok(0),
            Some(v) => addr_of(ifs, v).ok_or_else(|| format!("bad setting '{key} {v}' (an address or an interface)")),
        };
        let (bind, egress) = (addr("bind")?, addr("egress")?);
        let (Some(cert), Some(key)) = (get(s, "cert"), get(s, "key")) else {
            return Err(format!("needs a certificate and its key (cfg anytls {name}.cert / {name}.key, PEM)"));
        };
        let config = tls::server_config(&rustros_util::pem::normalize(cert), &rustros_util::pem::normalize(key))?;
        let users: Vec<(String, [u8; 32])> = s
            .iter()
            .filter_map(|(k, v)| {
                let n = k.strip_prefix("user.")?;
                let mut h = Sha256::new();
                h.update(v.as_bytes());
                Some((String::from(n), h.finish()))
            })
            .collect();
        if users.is_empty() {
            return Err(format!("no users (cfg anytls {name}.user.<name> <password>)"));
        }
        let mut allow = Vec::new();
        for item in get(s, "allow").unwrap_or("any").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if item == "any" {
                allow.push((0, 0));
            } else if let Some(f) = ifs.iter().find(|f| f.0 == item) {
                if f.1 != 0 {
                    allow.push((f.1 & f.2, f.2));
                }
            } else if let Some((n, m)) = parse_net(item) {
                allow.push((n & m, m));
            } else {
                return Err(format!("bad setting 'allow {item}'"));
            }
        }
        Ok(Instance {
            name: String::from(name),
            port,
            bind,
            egress,
            allow,
            users,
            config,
            dns: get(s, "dns").and_then(parse_ip).unwrap_or(DNS_DEFAULT),
            max: get(s, "max").and_then(|m| m.parse().ok()).unwrap_or(64),
            log: get(s, "log") == Some("on"),
            sessions: 0,
            total: 0,
            bytes: 0,
            refused: 0,
        })
    }

    fn accept(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        let Some(net) = sys.net() else { return };
        for (&port, &l) in &self.listeners {
            while let Ok((s, peer)) = net.accept(l, 0) {
                let local = net.getsockname(s).ok().and_then(|a| a.ipv4()).unwrap_or(0);
                let Some(inst) = self.instances.iter_mut().filter(|i| i.port == port && (i.bind == 0 || i.bind == local)).max_by_key(|i| i.bind != 0) else {
                    rustros_util::sock::abort(net, s);
                    continue;
                };
                if !inst.allow.iter().any(|&(n, m)| peer.ipv4().unwrap_or(0) & m == n) || inst.sessions >= inst.max {
                    inst.refused += 1;
                    rustros_util::sock::abort(net, s);
                    continue;
                }
                let Ok(t) = tls::Tls::server(inst.config.clone()) else {
                    rustros_util::sock::abort(net, s);
                    continue;
                };
                inst.sessions += 1;
                inst.total += 1;
                self.sessions.push(Session {
                    inst: inst.name.clone(),
                    user: String::new(),
                    c: Conn::new(s, peer),
                    tls: t,
                    phase: Phase::Handshake,
                    plain: Vec::new(),
                    out: Vec::new(),
                    streams: BTreeMap::new(),
                    settled: false,
                    version: 1,
                    deadline: now + SETUP_MS,
                    last: now,
                });
            }
        }
    }

    /// One session's step; false when it is over.
    fn step(&mut self, sys: &mut dyn Sys, si: usize, now: u64) -> bool {
        let Some(ii) = self.instances.iter().position(|i| i.name == self.sessions[si].inst) else { return false };
        let Some(net) = sys.net() else { return true };
        let inst = &mut self.instances[ii];
        let s = &mut self.sessions[si];
        if !matches!(s.phase, Phase::Frames) && now >= s.deadline {
            if inst.log {
                say!(net, "anytls: {}: {} gave up during {}\n", inst.name, IpFmt(s.c.peer.ipv4().unwrap_or(0)), if matches!(s.phase, Phase::Handshake) { "TLS" } else { "the password" });
            }
            return false;
        }
        // the wire: ciphertext in, plaintext out of TLS
        let backlog = s.tls.pending_write() + s.c.queued();
        let room = if backlog > MAX_OUT { s.c.inbuf.len() } else { 64 * 1024 };
        let alive = s.c.pump(net, room);
        if !s.c.inbuf.is_empty() {
            let cipher = core::mem::take(&mut s.c.inbuf);
            s.tls.feed(&cipher);
            s.last = now;
        }
        if let Some(e) = s.tls.error.take() {
            if inst.log {
                say!(net, "anytls: {}: {} TLS: {}\n", inst.name, IpFmt(s.c.peer.ipv4().unwrap_or(0)), e);
            }
            flush(s, net);
            return false;
        }
        s.plain.extend_from_slice(&s.tls.take_received());
        if matches!(s.phase, Phase::Handshake) && s.tls.established {
            s.phase = Phase::Auth;
        }
        if matches!(s.phase, Phase::Auth) && s.plain.len() >= 34 {
            let pad = u16::from_be_bytes([s.plain[32], s.plain[33]]) as usize;
            if s.plain.len() >= 34 + pad {
                let user = inst.users.iter().find(|(_, h)| rustros_util::sha256::ct_eq(h, &s.plain[..32]));
                let Some((name, _)) = user else {
                    if inst.log {
                        say!(net, "anytls: {}: {} wrong password\n", inst.name, IpFmt(s.c.peer.ipv4().unwrap_or(0)));
                    }
                    return false;
                };
                s.user = name.clone();
                if inst.log {
                    say!(net, "anytls: {}: {} logged in as {}\n", inst.name, IpFmt(s.c.peer.ipv4().unwrap_or(0)), s.user);
                }
                s.plain.drain(..34 + pad);
                s.phase = Phase::Frames;
            }
        }
        if matches!(s.phase, Phase::Frames) && !frames(s, inst, net, now) {
            flush(s, net);
            return false;
        }
        for sid in s.streams.keys().copied().collect::<Vec<_>>() {
            let room = MAX_OUT.saturating_sub(s.out.len() + s.tls.pending_write() + s.c.queued());
            let st = s.streams.get_mut(&sid).unwrap();
            let (keep, sent) = stream_step(st, sid, s.version, inst, &mut self.dns_cache, net, now, &mut s.out, room);
            inst.bytes += sent as u64;
            if sent > 0 {
                s.last = now;
            }
            if !keep {
                if let Some(st) = s.streams.remove(&sid) {
                    end_stream(net, st);
                }
            }
        }
        flush(s, net);
        if !alive || s.c.eof {
            return false;
        }
        if s.streams.is_empty() && now - s.last >= IDLE_MS {
            return false;
        }
        true
    }
}

/// Frames to TLS, TLS to the wire.
fn flush(s: &mut Session, net: &mut dyn Net) {
    if !s.out.is_empty() {
        let out = core::mem::take(&mut s.out);
        s.tls.write(&out);
    }
    let w = s.tls.take_outgoing();
    if !w.is_empty() {
        s.c.write(&w);
    }
    s.c.pump(net, 0);
}

/// The client's frames; false when the session must end.
fn frames(s: &mut Session, inst: &Instance, net: &mut dyn Net, now: u64) -> bool {
    loop {
        if s.plain.len() < 7 {
            return true;
        }
        let cmd = s.plain[0];
        let sid = u32::from_be_bytes([s.plain[1], s.plain[2], s.plain[3], s.plain[4]]);
        let len = u16::from_be_bytes([s.plain[5], s.plain[6]]) as usize;
        // only these carry data (anytls-go reads none of the others')
        let with_data = matches!(cmd, CMD_PSH | CMD_WASTE | CMD_SETTINGS | CMD_ALERT | CMD_UPDATE_PADDING | CMD_SYNACK | CMD_SERVER_SETTINGS);
        let n = if with_data { len } else { 0 };
        if s.plain.len() < 7 + n {
            return true;
        }
        let data: Vec<u8> = s.plain[7..7 + n].to_vec();
        s.plain.drain(..7 + n);
        match cmd {
            CMD_PSH => {
                if let Some(st) = s.streams.get_mut(&sid) {
                    if st.input.len() + data.len() <= MAX_IN {
                        st.input.extend_from_slice(&data);
                    }
                }
            }
            CMD_SYN => {
                if !s.settled {
                    frame(&mut s.out, CMD_ALERT, 0, b"client did not send its settings");
                    return false;
                }
                s.streams.entry(sid).or_insert(Stream { phase: StreamPhase::Target, input: Vec::new(), host: String::new(), port: 0, udp_v2: false, deadline: now + SETUP_MS });
            }
            CMD_FIN => {
                // the client ends it: its target is let go
                if let Some(mut st) = s.streams.remove(&sid) {
                    if let StreamPhase::Relay(up) = &mut st.phase {
                        let input = core::mem::take(&mut st.input);
                        up.write(&input);
                    }
                    end_stream(net, st);
                }
            }
            CMD_SETTINGS => {
                s.settled = true;
                let text = String::from_utf8_lossy(&data);
                let get = |k: &str| text.lines().filter_map(|l| l.split_once('=')).find(|(a, _)| a.trim() == k).map(|(_, v)| String::from(v.trim()));
                if get("padding-md5").as_deref() != Some(PADDING_MD5) {
                    frame(&mut s.out, CMD_UPDATE_PADDING, 0, PADDING.as_bytes());
                }
                if let Some(v) = get("v").and_then(|v| v.parse::<u32>().ok()) {
                    s.version = v;
                    if v >= 2 {
                        frame(&mut s.out, CMD_SERVER_SETTINGS, 0, b"v=2");
                    }
                }
                if inst.log {
                    say!(net, "anytls: {}: {} client {}\n", inst.name, s.user, get("client").unwrap_or_default());
                }
            }
            CMD_HEART_REQUEST => frame(&mut s.out, CMD_HEART_RESPONSE, sid, &[]),
            CMD_ALERT => return false,
            _ => {}
        }
    }
}

fn end_stream(net: &mut dyn Net, st: Stream) {
    match st.phase {
        StreamPhase::Resolve(l) => l.cancel(net),
        StreamPhase::Connecting(mut c) => c.abort(net),
        StreamPhase::Relay(mut c) => {
            let _ = c.close();
            c.pump(net, 0);
        }
        StreamPhase::Udp(u) => {
            if let Some((l, ..)) = u.waiting {
                l.cancel(net);
            }
            let _ = net.close(u.sock);
        }
        _ => {}
    }
}

fn end_session(net: &mut dyn Net, s: &mut Session) {
    for (_, st) in core::mem::take(&mut s.streams) {
        end_stream(net, st);
    }
    s.c.abort(net);
}

/// A failed stream: the client is told why (v2), then the stream ends.
fn refuse(out: &mut Vec<u8>, sid: u32, version: u32, why: &str) -> (bool, usize) {
    if version >= 2 {
        frame(out, CMD_SYNACK, sid, why.as_bytes());
    }
    frame(out, CMD_FIN, sid, &[]);
    (false, 0)
}

fn cached(cache: &mut BTreeMap<String, (Ip, u64)>, name: &str, now: u64) -> Option<Ip> {
    cache.get(name).filter(|e| e.1 > now).map(|e| e.0)
}

fn remember(cache: &mut BTreeMap<String, (Ip, u64)>, name: String, ip: Ip, now: u64) {
    if cache.len() >= DNS_CACHE {
        cache.retain(|_, e| e.1 > now);
        if cache.len() >= DNS_CACHE {
            cache.clear();
        }
    }
    cache.insert(name, (ip, now + DNS_TTL_MS));
}

fn connect(inst: &Instance, net: &mut dyn Net, ip: Ip, port: u16) -> Option<Conn> {
    let to = SockAddr::v4(ip, port);
    let r = if inst.egress != 0 { rustros_util::sock::tcp_connect(net, &to, inst.egress) } else { rustros_util::sock::tcp_connect(net, &to, 0) };
    r.ok().map(|s| Conn::new(s, to))
}

/// One stream's step: (keep it, bytes moved).
#[allow(clippy::too_many_arguments)]
fn stream_step(st: &mut Stream, sid: u32, version: u32, inst: &Instance, cache: &mut BTreeMap<String, (Ip, u64)>, net: &mut dyn Net, now: u64, out: &mut Vec<u8>, room: usize) -> (bool, usize) {
    loop {
        match &mut st.phase {
            StreamPhase::Target => {
                if now >= st.deadline {
                    return refuse(out, sid, version, "the target did not come");
                }
                match read_addr(&st.input, 1, 3, 4) {
                    None => return (true, 0),
                    Some(Err(e)) => return refuse(out, sid, version, &e),
                    Some(Ok((host, port, used))) => {
                        st.input.drain(..used);
                        let h = host.trim_end_matches('.').to_ascii_lowercase();
                        if h == UOT_V2 || h == UOT_V1 {
                            if version >= 2 {
                                frame(out, CMD_SYNACK, sid, &[]);
                            }
                            st.udp_v2 = h == UOT_V2;
                            if inst.log {
                                say!(net, "anytls: {}: stream {} UDP\n", inst.name, sid);
                            }
                            if st.udp_v2 {
                                st.phase = StreamPhase::UdpRequest;
                            } else {
                                let Ok(sock) = rustros_util::sock::udp_bind(net, 0) else { return refuse(out, sid, 1, "no UDP socket") };
                                st.phase = StreamPhase::Udp(Udp { sock, one: None, waiting: None, last: now });
                            }
                            continue;
                        }
                        st.host = h;
                        st.port = port;
                        st.deadline = now + CONNECT_MS;
                        if inst.log {
                            say!(net, "anytls: {}: stream {} to {}:{}\n", inst.name, sid, st.host, port);
                        }
                        let ip = parse_ip(&st.host).or_else(|| cached(cache, &st.host, now));
                        match ip {
                            Some(ip) => match connect(inst, net, ip, port) {
                                Some(c) => st.phase = StreamPhase::Connecting(c),
                                None => return refuse(out, sid, version, "no route"),
                            },
                            None => match Lookup::start(net, &st.host, inst.dns) {
                                Some(l) => st.phase = StreamPhase::Resolve(l),
                                None => return refuse(out, sid, version, "no DNS socket"),
                            },
                        }
                    }
                }
            }
            StreamPhase::Resolve(l) => match l.poll(net, now) {
                None => return (true, 0),
                Some(Looked::Found(ip)) => {
                    remember(cache, st.host.clone(), ip, now);
                    match connect(inst, net, ip, st.port) {
                        Some(c) => st.phase = StreamPhase::Connecting(c),
                        None => {
                            st.phase = StreamPhase::Target;
                            return refuse(out, sid, version, "no route");
                        }
                    }
                }
                Some(_) => {
                    st.phase = StreamPhase::Target;
                    return refuse(out, sid, version, "the name does not resolve");
                }
            },
            StreamPhase::Connecting(c) => match rustros_util::sock::connected(net, c.stream) {
                Ok(false) if now < st.deadline => return (true, 0),
                Ok(true) => {
                    if version >= 2 {
                        frame(out, CMD_SYNACK, sid, &[]);
                    }
                    let StreamPhase::Connecting(c) = core::mem::replace(&mut st.phase, StreamPhase::Target) else { unreachable!() };
                    st.phase = StreamPhase::Relay(c);
                }
                _ => return refuse(out, sid, version, "connection refused or timed out"),
            },
            StreamPhase::Relay(up) => {
                let mut moved = 0;
                if !st.input.is_empty() && up.queued() < MAX_IN {
                    moved += st.input.len();
                    up.write(&st.input);
                    st.input.clear();
                }
                let want = room.min(CHUNK * 4);
                let alive = up.pump(net, want.min(CHUNK * 4));
                while !up.inbuf.is_empty() {
                    let n = up.inbuf.len().min(CHUNK);
                    frame(out, CMD_PSH, sid, &up.inbuf[..n]);
                    up.inbuf.drain(..n);
                    moved += n;
                }
                if !alive || up.eof {
                    // the target's end ends the stream
                    frame(out, CMD_FIN, sid, &[]);
                    return (false, moved);
                }
                return (true, moved);
            }
            StreamPhase::UdpRequest => {
                // v2: connect flag, then the target
                let Some(&connect_flag) = st.input.first() else { return (true, 0) };
                match read_addr(&st.input[1..], 1, 3, 4) {
                    None => return (true, 0),
                    Some(Err(e)) => return refuse(out, sid, 1, &e),
                    Some(Ok((host, port, used))) => {
                        st.input.drain(..1 + used);
                        let Ok(sock) = rustros_util::sock::udp_bind(net, 0) else { return refuse(out, sid, 1, "no UDP socket") };
                        let mut u = Udp { sock, one: None, waiting: None, last: now };
                        if connect_flag != 0 {
                            match parse_ip(&host).or_else(|| cached(cache, &host, now)) {
                                Some(ip) => u.one = Some(SockAddr::v4(ip, port)),
                                None => match Lookup::start(net, &host, inst.dns) {
                                    // resolved before any packet goes
                                    Some(l) => u.waiting = Some((l, host, port, Vec::new())),
                                    None => {
                                        let _ = net.close(sock);
                                        return refuse(out, sid, 1, "no DNS socket");
                                    }
                                },
                            }
                        }
                        st.phase = StreamPhase::Udp(u);
                    }
                }
            }
            StreamPhase::Udp(u) => return udp_step(u, &mut st.input, sid, inst, cache, net, now, out),
        }
    }
}

/// UDP over the stream: packets from the client sent on, what comes back
/// framed to it.
#[allow(clippy::too_many_arguments)]
fn udp_step(u: &mut Udp, input: &mut Vec<u8>, sid: u32, inst: &Instance, cache: &mut BTreeMap<String, (Ip, u64)>, net: &mut dyn Net, now: u64, out: &mut Vec<u8>) -> (bool, usize) {
    let mut moved = 0;
    // a name being looked up holds the packets behind it
    if let Some((l, name, port, data)) = &mut u.waiting {
        match l.poll(net, now) {
            None => return (true, 0),
            Some(r) => {
                let (name, port, data) = (core::mem::take(name), *port, core::mem::take(data));
                u.waiting = None;
                if let Looked::Found(ip) = r {
                    remember(cache, name, ip, now);
                    if data.is_empty() && u.one.is_none() {
                        u.one = Some(SockAddr::v4(ip, port)); // the v2 connect target
                    } else {
                        let _ = net.sendto(u.sock, &data, 0, Some(&SockAddr::v4(ip, port)));
                    }
                }
            }
        }
    }
    loop {
        let ((host, port), hdr) = if let Some(one) = u.one {
            ((format!("{}", IpFmt(one.ipv4().unwrap_or(0))), one.port()), 0)
        } else {
            match read_addr(input, 0, 2, 1) {
                None => break,
                Some(Err(_)) => return (false, moved),
                Some(Ok((h, p, used))) => ((h, p), used),
            }
        };
        let Some(l) = input.get(hdr..hdr + 2) else { break };
        let len = u16::from_be_bytes([l[0], l[1]]) as usize;
        if input.len() < hdr + 2 + len {
            break;
        }
        let data = input[hdr + 2..hdr + 2 + len].to_vec();
        input.drain(..hdr + 2 + len);
        u.last = now;
        moved += len;
        match parse_ip(&host).or_else(|| cached(cache, &host, now)) {
            Some(ip) => {
                let _ = net.sendto(u.sock, &data, 0, Some(&SockAddr::v4(ip, port)));
            }
            None => {
                if let Some(l) = Lookup::start(net, &host, inst.dns) {
                    u.waiting = Some((l, host, port, data));
                }
                break;
            }
        }
    }
    // what comes back
    let mut buf = [0u8; 2048];
    while let Ok((n, from)) = net.recvfrom(u.sock, &mut buf, 0) {
        let mut p = Vec::with_capacity(n + 9);
        if u.one.is_none() {
            p.push(0);
            let from = from.unwrap_or(SockAddr::v4(0, 0));
            p.extend_from_slice(&from.ipv4().unwrap_or(0).to_be_bytes());
            p.extend_from_slice(&from.port().to_be_bytes());
        }
        p.extend_from_slice(&(n as u16).to_be_bytes());
        p.extend_from_slice(&buf[..n]);
        frame(out, CMD_PSH, sid, &p);
        u.last = now;
        moved += n;
    }
    (now - u.last < UDP_IDLE_MS, moved)
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "<i>.listen", kind: "number", default: "", help: "the port (an instance without one is off)" },
    Param { key: "<i>.bind", kind: "address", default: "", help: "only connections to this address of ours (or interface)" },
    Param { key: "<i>.cert", kind: "text", default: "", help: "certificate and chain, PEM (newlines as spaces or \\n)" },
    Param { key: "<i>.key", kind: "secret", default: "", help: "its private key, PEM (ECDSA P-256, Ed25519 or RSA)" },
    Param { key: "<i>.user.<name>", kind: "secret", default: "", help: "passwords of who may use it" },
    Param { key: "<i>.egress", kind: "address", default: "", help: "TCP to targets from this address (its WAN)" },
    Param { key: "<i>.allow", kind: "list", default: "any", help: "who may connect: interfaces, networks, addresses, any" },
    Param { key: "<i>.dns", kind: "address", default: "1.1.1.1", help: "resolver for targets' names" },
    Param { key: "<i>.max", kind: "number", default: "64", help: "sessions at once" },
    Param { key: "<i>.log", kind: "switch", default: "off", help: "print sessions and streams" },
];

impl Module for AnyTls {
    fn name(&self) -> &'static str {
        "anytls"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        let unix = sys.unix_time();
        tls::set_time(unix);
        let mut seed = [0u8; 32];
        for c in seed.chunks_mut(8) {
            c.copy_from_slice(&sys.random().to_le_bytes());
        }
        tls::seed(seed);
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
        if self.instances.is_empty() && self.said.is_empty() {
            say!(sys, "anytls: no instance (cfg anytls a1.listen 443, .cert, .key, .user.<name>)\n");
        }
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            tls::set_time(sys.unix_time());
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        self.accept(sys);
        if let Some(net) = sys.net() {
            self.closing.retain_mut(|(c, until)| {
                if now >= *until {
                    c.abort(net);
                    return false;
                }
                c.pump(net, 0)
            });
        }
        let mut i = 0;
        while i < self.sessions.len() {
            if self.step(sys, i, now) {
                i += 1;
                continue;
            }
            let mut s = self.sessions.swap_remove(i);
            if let Some(net) = sys.net() {
                for (_, st) in core::mem::take(&mut s.streams) {
                    end_stream(net, st);
                }
            }
            if let Some(inst) = self.instances.iter_mut().find(|x| x.name == s.inst) {
                inst.sessions = inst.sessions.saturating_sub(1);
                if inst.log {
                    if let Some(net) = sys.net() {
                        say!(net, "anytls: {}: {} session ended\n", inst.name, IpFmt(s.c.peer.ipv4().unwrap_or(0)));
                    }
                }
            }
            let _ = s.c.close();
            self.closing.push((s.c, now + CONNECT_MS));
        }
    }

    fn status(&self) -> String {
        if self.instances.is_empty() {
            return String::from("no instance (cfg anytls a1.listen 443)");
        }
        self.instances
            .iter()
            .map(|i| {
                format!(
                    "{} :{}: {} sessions, {} total, {} KB{}",
                    i.name,
                    i.port,
                    i.sessions,
                    i.total,
                    i.bytes / 1024,
                    if i.refused > 0 { format!(", {} refused", i.refused) } else { String::new() }
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(read_addr(&[1, 10, 0, 0, 5, 0, 80], 1, 3, 4).unwrap().unwrap(), (String::from("10.0.0.5"), 80, 7));
        let mut n = alloc::vec![3, 7];
        n.extend_from_slice(b"example");
        n.extend_from_slice(&[1, 187]);
        assert_eq!(read_addr(&n, 1, 3, 4).unwrap().unwrap(), (String::from("example"), 443, 11));
        assert!(read_addr(&n[..5], 1, 3, 4).is_none());
        assert!(read_addr(&[9], 1, 3, 4).unwrap().is_err());
    }
}
