//! Proxy module: SOCKS5 and HTTP proxies, any number of instances.
//!
//! Each instance listens on a port (and, optionally, only on one of our
//! addresses), lets in the clients of its `allow` networks, may ask for a
//! user name and password, and connects out from its `egress` address, so
//! the instances on one machine can leave through different WANs.
//!
//! Settings (`cfg proxy <instance>.<key> <value>`):
//!
//! ```text
//! <i>.listen       1080            the port (an instance without one is off)
//! <i>.type         mixed           socks5 | http | mixed (both on one port)
//! <i>.bind         a.b.c.d|nic1    only connections to this address of ours
//! <i>.egress       a.b.c.d|nic1    connect out from this address (its WAN)
//! <i>.allow        nic2,10.9.0.0/16,...  who may use it (default: the networks
//!                                  of the interfaces without a gateway)
//! <i>.user.<name>  password        logins (none: no login asked)
//! <i>.dns          a.b.c.d         resolver for names (default 1.1.1.1)
//! <i>.max          256             connections at once
//! <i>.log          on              print each connection
//! ```
//!
//! SOCKS5 does CONNECT (IPv4 and names; no UDP, no BIND); HTTP does CONNECT
//! and plain `http://` requests (one per connection).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, Module, Net, NetError, Param, SocketAddr, Sys, TcpListener, UdpSocket, say};
use rustros_util::conn::Conn;
use rustros_util::dns;
use rustros_util::wire::{Ip, IpFmt, parse_ip, parse_net};

const RELOAD_MS: u64 = 2000;
const DNS_DEFAULT: Ip = 0x0101_0101;
const DNS_RETRY_MS: u64 = 2000;
const DNS_TRIES: u8 = 3;
const DNS_CACHE: usize = 256;
const DNS_TTL_MS: u64 = 60_000;
/// Greeting, login and request must be done by then.
const HANDSHAKE_MS: u64 = 30_000;
const CONNECT_MS: u64 = 15_000;
const IDLE_MS: u64 = 600_000;
/// The most a relay buffers for the slower side.
const MAX_QUEUE: usize = 256 * 1024;
const MAX_HEADER: usize = 16 * 1024;
const CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Socks5,
    Http,
    Mixed,
}

struct Instance {
    name: String,
    kind: Kind,
    port: u16,
    bind: Ip,
    egress: Ip,
    allow: Vec<(Ip, Ip)>,
    users: BTreeMap<String, String>,
    dns: Ip,
    max: usize,
    log: bool,
    // counters
    conns: usize,
    total: u64,
    bytes: u64,
    /// connections turned away (not in `allow`, or too many)
    refused: u64,
}

impl Instance {
    fn allowed(&self, ip: Ip) -> bool {
        self.allow.iter().any(|&(n, m)| ip & m == n)
    }

    fn login(&self, user: &[u8], pass: &[u8]) -> bool {
        core::str::from_utf8(user).ok().and_then(|u| self.users.get(u)).is_some_and(|p| p.as_bytes() == pass)
    }
}

/// What to say to the client once the connection out has worked or failed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Socks,
    /// CONNECT: "200 Connection established"
    HttpTunnel,
    /// a plain request: it is sent on, the answer comes back as it is
    HttpPlain,
}

enum Phase {
    /// waiting for the first bytes (mixed) or the SOCKS greeting
    Greet,
    SocksAuth,
    SocksRequest,
    HttpHeader,
    Resolve { sock: UdpSocket, id: u16, server: Ip, sent: u64, tries: u8 },
    Connecting,
    Relay,
}

struct Client {
    inst: String,
    c: Conn,
    up: Option<Conn>,
    phase: Phase,
    reply: Reply,
    host: String,
    port: u16,
    /// sent upstream once connected (a rewritten HTTP request)
    first: Vec<u8>,
    deadline: u64,
    last: u64,
}

#[derive(Default)]
pub struct Proxy {
    instances: Vec<Instance>,
    listeners: BTreeMap<u16, TcpListener>,
    clients: Vec<Client>,
    /// connections being closed: their last bytes still going out
    closing: Vec<(Conn, u64)>,
    dns_cache: BTreeMap<String, (Ip, u64)>,
    applied: String,
    /// what was last said about each instance, to report changes only
    said: BTreeMap<String, String>,
    reload_at: u64,
}

fn get<'a>(s: &[(&str, &'a str)], k: &str) -> Option<&'a str> {
    s.iter().find(|(x, _)| *x == k).map(|(_, v)| *v)
}

/// An address, or the address of an interface named so.
fn addr_of(ifs: &[(String, Ip, Ip, Ip)], v: &str) -> Option<Ip> {
    parse_ip(v).or_else(|| ifs.iter().find(|f| f.0 == v).map(|f| f.1).filter(|&a| a != 0))
}

fn http_error(status: &str, extra: &str) -> Vec<u8> {
    let body = format!("{status}\n");
    format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).into_bytes()
}

fn socks_reply(rep: u8, bound: SocketAddr) -> Vec<u8> {
    let mut r = alloc::vec![5, rep, 0, 1];
    r.extend_from_slice(&bound.ip.to_be_bytes());
    r.extend_from_slice(&bound.port.to_be_bytes());
    r
}

/// "host:port" (or "[v6]:port") with a default port.
fn host_port(s: &str, default: u16) -> Option<(String, u16)> {
    if s.starts_with('[') {
        return None; // IPv6
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((String::from(h), p.parse().ok()?)),
        None => Some((String::from(s), default)),
    }
}

/// What an HTTP request asks for: (host, port, reply, bytes to send on).
/// Err is the answer to give instead.
fn parse_http(inst: &Instance, head: &[u8], rest: &[u8]) -> Result<(String, u16, Reply, Vec<u8>), Vec<u8>> {
    let text = core::str::from_utf8(head).map_err(|_| http_error("400 Bad Request", ""))?;
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split(' ');
    let (method, target, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("HTTP/1.1"));
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return Err(http_error("400 Bad Request", ""));
    }
    let headers: Vec<(&str, &str)> = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim(), v.trim())).collect();
    if !inst.users.is_empty() {
        let ok = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Proxy-Authorization"))
            .and_then(|(_, v)| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")))
            .and_then(rustros_util::base64::decode)
            .is_some_and(|cred| match cred.iter().position(|&b| b == b':') {
                Some(p) => inst.login(&cred[..p], &cred[p + 1..]),
                None => false,
            });
        if !ok {
            return Err(http_error("407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"RustROS\"\r\n"));
        }
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = host_port(target, 443).ok_or_else(|| http_error("400 Bad Request", ""))?;
        return Ok((h, p, Reply::HttpTunnel, rest.to_vec()));
    }
    let Some(t) = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://")) else {
        return Err(http_error("400 Bad Request", ""));
    };
    let (authority, path) = match t.find('/') {
        Some(i) => (&t[..i], &t[i..]),
        None => (t, "/"),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (h, p) = host_port(authority, 80).ok_or_else(|| http_error("400 Bad Request", ""))?;
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (k, v) in &headers {
        let drop = ["Proxy-Authorization", "Proxy-Connection", "Connection", "Keep-Alive"].iter().any(|d| k.eq_ignore_ascii_case(d));
        if !drop {
            has_host |= k.eq_ignore_ascii_case("Host");
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    // one request per connection: the next may be for another server
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(rest);
    Ok((h, p, Reply::HttpPlain, bytes))
}

impl Proxy {
    pub fn new() -> Proxy {
        Proxy::default()
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
        let text: String = settings
            .iter()
            .map(|(k, v)| format!("{k}={v};"))
            .chain(ifs.iter().map(|f| format!("{}={}/{}/{};", f.0, f.1, f.2, f.3)))
            .collect();
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
        let mut said = BTreeMap::new();
        let mut old: BTreeMap<String, (usize, u64, u64, u64)> = self.instances.drain(..).map(|i| (i.name, (i.conns, i.total, i.bytes, i.refused))).collect();
        for (name, s) in &by {
            let Some(port) = get(s, "listen").and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0) else {
                said.insert(String::from(*name), format!("proxy: {name}: off (cfg proxy {name}.listen 1080)\n"));
                continue;
            };
            let kind = match get(s, "type").unwrap_or("mixed") {
                "socks5" | "socks" => Kind::Socks5,
                "http" => Kind::Http,
                "mixed" => Kind::Mixed,
                t => {
                    said.insert(String::from(*name), format!("proxy: {name}: unknown type '{t}' (socks5, http, mixed)\n"));
                    continue;
                }
            };
            let mut bad = Vec::new();
            let mut addr = |key: &str| match get(s, key) {
                None | Some("") | Some("any") => 0,
                Some(v) => addr_of(&ifs, v).unwrap_or_else(|| {
                    bad.push(format!("{key} {v}"));
                    0
                }),
            };
            let (bind, egress) = (addr("bind"), addr("egress"));
            let dns = get(s, "dns").and_then(parse_ip).unwrap_or(DNS_DEFAULT);
            let mut allow = Vec::new();
            let spec = get(s, "allow").unwrap_or("");
            if spec.is_empty() {
                allow.extend(ifs.iter().filter(|f| f.1 != 0 && f.3 == 0).map(|f| (f.1 & f.2, f.2)));
            }
            for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if item == "any" {
                    allow.push((0, 0));
                } else if let Some(f) = ifs.iter().find(|f| f.0 == item) {
                    if f.1 != 0 {
                        allow.push((f.1 & f.2, f.2));
                    }
                } else if let Some((n, m)) = parse_net(item) {
                    allow.push((n & m, m));
                } else if let Some(a) = parse_ip(item) {
                    allow.push((a, !0));
                } else {
                    bad.push(format!("allow {item}"));
                }
            }
            let mut line: String = bad.iter().map(|b| format!("proxy: {name}: bad setting '{b}' (an address or an interface)\n")).collect();
            let users: BTreeMap<String, String> = s.iter().filter_map(|(k, v)| Some((String::from(k.strip_prefix("user.")?), String::from(*v)))).collect();
            let (conns, total, bytes, refused) = old.remove(*name).unwrap_or_default();
            let i = Instance {
                name: String::from(*name),
                kind,
                port,
                bind,
                egress,
                allow,
                users,
                dns,
                max: get(s, "max").and_then(|m| m.parse().ok()).unwrap_or(256),
                log: get(s, "log") == Some("on"),
                conns,
                total,
                bytes,
                refused,
            };
            let open: String = i.allow.iter().map(|(n, m)| format!("{}/{}", IpFmt(*n), m.count_ones())).collect::<Vec<_>>().join(",");
            line += &format!(
                "proxy: {} {:?} on {}:{}, out from {}, open to {}{}\n",
                i.name,
                i.kind,
                if i.bind == 0 { String::from("*") } else { format!("{}", IpFmt(i.bind)) },
                i.port,
                if i.egress == 0 { String::from("the route's address") } else { format!("{}", IpFmt(i.egress)) },
                if open.is_empty() { "nobody (set allow)" } else { &open },
                if i.users.is_empty() { String::new() } else { format!(", {} users", i.users.len()) }
            );
            if let Some(o) = self.instances.iter().find(|o| o.port == i.port && o.bind == i.bind) {
                line = format!("proxy: {}: port {} already taken by {}\n", i.name, i.port, o.name);
            } else {
                self.instances.push(i);
            }
            said.insert(String::from(*name), line);
        }
        for (name, line) in &said {
            if self.said.get(name) != Some(line) {
                sys.print(line);
            }
        }
        for name in self.said.keys().filter(|n| !said.contains_key(*n)) {
            say!(sys, "proxy: {}: removed\n", name);
        }
        self.said = said;
        // listeners: one per port, shared by the instances on it
        let Some(net) = sys.net() else { return };
        let ports: Vec<u16> = self.instances.iter().map(|i| i.port).collect();
        self.listeners.retain(|port, l| {
            let keep = ports.contains(port);
            if !keep {
                net.tcp_unlisten(*l);
            }
            keep
        });
        for p in ports {
            if !self.listeners.contains_key(&p) {
                match net.tcp_listen(p) {
                    Ok(l) => {
                        self.listeners.insert(p, l);
                    }
                    Err(e) => say!(net, "proxy: cannot listen on {}: {:?}\n", p, e),
                }
            }
        }
        // clients of instances that are gone
        let names: Vec<&str> = self.instances.iter().map(|i| i.name.as_str()).collect();
        self.clients.retain_mut(|c| {
            let keep = names.contains(&c.inst.as_str());
            if !keep {
                drop_client(net, c);
            }
            keep
        });
    }

    fn accept(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        let Some(net) = sys.net() else { return };
        for (&port, &l) in &self.listeners {
            while let Ok((s, peer)) = net.tcp_accept(l) {
                let local = net.tcp_local_addr(s).map(|a| a.ip).unwrap_or(0);
                // the instance on that address, else the one on any
                let inst = self
                    .instances
                    .iter_mut()
                    .filter(|i| i.port == port && (i.bind == 0 || i.bind == local))
                    .max_by_key(|i| i.bind != 0);
                let Some(inst) = inst else {
                    net.tcp_abort(s);
                    continue;
                };
                if !inst.allowed(peer.ip) || inst.conns >= inst.max {
                    inst.refused += 1;
                    if inst.log {
                        let why = if inst.conns >= inst.max { "too many connections" } else { "not in allow" };
                        say!(net, "proxy: {}: refused {} ({})\n", inst.name, IpFmt(peer.ip), why);
                    }
                    net.tcp_abort(s);
                    continue;
                }
                inst.conns += 1;
                inst.total += 1;
                let phase = if inst.kind == Kind::Http { Phase::HttpHeader } else { Phase::Greet };
                self.clients.push(Client {
                    inst: inst.name.clone(),
                    c: Conn::new(s, peer),
                    up: None,
                    phase,
                    reply: Reply::Socks,
                    host: String::new(),
                    port: 0,
                    first: Vec::new(),
                    deadline: now + HANDSHAKE_MS,
                    last: now,
                });
            }
        }
    }

    /// One client's step; false when it is over.
    fn step(&mut self, sys: &mut dyn Sys, ci: usize, now: u64) -> bool {
        let Some(ii) = self.instances.iter().position(|i| i.name == self.clients[ci].inst) else { return false };
        let Some(net) = sys.net() else { return true };
        let inst = &mut self.instances[ii];
        let cl = &mut self.clients[ci];
        if !matches!(cl.phase, Phase::Relay) && now >= cl.deadline {
            return fail(cl, net, 6, "504 Gateway Timeout");
        }
        // the client's side
        let room = match &cl.up {
            Some(u) if matches!(cl.phase, Phase::Relay) => {
                if u.queued() >= MAX_QUEUE {
                    cl.c.inbuf.len()
                } else {
                    CHUNK
                }
            }
            Some(_) => cl.c.inbuf.len(), // hold it until connected
            None => MAX_HEADER,
        };
        if !cl.c.pump(net, room) {
            if let Some(u) = cl.up.as_mut() {
                u.close();
                u.pump(net, 0);
            }
            return false;
        }
        loop {
            match &mut cl.phase {
                Phase::Greet => {
                    let Some(&first) = cl.c.inbuf.first() else { break };
                    if first != 5 {
                        if inst.kind == Kind::Socks5 {
                            cl.c.abort(net);
                            return false;
                        }
                        cl.phase = Phase::HttpHeader;
                        continue;
                    }
                    let b = &cl.c.inbuf;
                    if b.len() < 2 || b.len() < 2 + b[1] as usize {
                        break;
                    }
                    let methods = &b[2..2 + b[1] as usize];
                    let want = if inst.users.is_empty() { 0 } else { 2 };
                    let n = 2 + b[1] as usize;
                    if !methods.contains(&want) {
                        cl.c.write(&[5, 0xFF]);
                        cl.c.close();
                        cl.c.pump(net, 0);
                        return false;
                    }
                    cl.c.inbuf.drain(..n);
                    cl.c.write(&[5, want]);
                    cl.phase = if want == 2 { Phase::SocksAuth } else { Phase::SocksRequest };
                }
                Phase::SocksAuth => {
                    let b = &cl.c.inbuf;
                    if b.len() < 2 {
                        break;
                    }
                    let ul = b[1] as usize;
                    if b.len() < 3 + ul {
                        break;
                    }
                    let pl = b[2 + ul] as usize;
                    if b.len() < 3 + ul + pl {
                        break;
                    }
                    let ok = b[0] == 1 && inst.login(&b[2..2 + ul], &b[3 + ul..3 + ul + pl]);
                    cl.c.inbuf.drain(..3 + ul + pl);
                    cl.c.write(&[1, if ok { 0 } else { 1 }]);
                    if !ok {
                        if inst.log {
                            say!(net, "proxy: {}: {} wrong login\n", inst.name, IpFmt(cl.c.peer.ip));
                        }
                        cl.c.close();
                        cl.c.pump(net, 0);
                        return false;
                    }
                    cl.phase = Phase::SocksRequest;
                }
                Phase::SocksRequest => {
                    let b = &cl.c.inbuf;
                    if b.len() < 5 {
                        break;
                    }
                    let (len, host) = match b[3] {
                        1 => (10, b.get(4..8).map(|a| format!("{}", IpFmt(u32::from_be_bytes([a[0], a[1], a[2], a[3]]))))),
                        3 => {
                            let l = b[4] as usize;
                            (7 + l, b.get(5..5 + l).map(|n| String::from_utf8_lossy(n).into_owned()))
                        }
                        4 => (22, None),
                        _ => (0, None),
                    };
                    if b.len() < len {
                        break;
                    }
                    if b[0] != 5 || b[1] != 1 || host.is_none() {
                        // only CONNECT, and no IPv6
                        let rep = if b[0] != 5 || len == 0 { 1 } else if b[1] != 1 { 7 } else { 8 };
                        cl.c.write(&socks_reply(rep, SocketAddr { ip: 0, port: 0 }));
                        cl.c.close();
                        cl.c.pump(net, 0);
                        return false;
                    }
                    cl.port = u16::from_be_bytes([b[len - 2], b[len - 1]]);
                    cl.host = host.unwrap_or_default();
                    cl.c.inbuf.drain(..len);
                    cl.reply = Reply::Socks;
                    start_resolve(cl, inst, &mut self.dns_cache, net, now);
                }
                Phase::HttpHeader => {
                    let Some(end) = cl.c.inbuf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        if cl.c.inbuf.len() >= MAX_HEADER || cl.c.eof {
                            cl.c.write(&http_error("400 Bad Request", ""));
                            cl.c.close();
                            cl.c.pump(net, 0);
                            return false;
                        }
                        break;
                    };
                    match parse_http(inst, &cl.c.inbuf[..end], &cl.c.inbuf[end + 4..]) {
                        Ok((h, p, reply, first)) => {
                            cl.c.inbuf.clear();
                            (cl.host, cl.port, cl.reply, cl.first) = (h, p, reply, first);
                            start_resolve(cl, inst, &mut self.dns_cache, net, now);
                        }
                        Err(answer) => {
                            if inst.log {
                                say!(net, "proxy: {}: {} refused: {}\n", inst.name, IpFmt(cl.c.peer.ip), String::from_utf8_lossy(&answer[9..answer.iter().position(|&b| b == b'\r').unwrap_or(9)]));
                            }
                            cl.c.write(&answer);
                            cl.c.close();
                            cl.c.pump(net, 0);
                            return false;
                        }
                    }
                }
                Phase::Resolve { sock, id, server, .. } => {
                    let (sock, id, server) = (*sock, *id, *server);
                    let mut buf = [0u8; 1500];
                    let mut got = None;
                    while let Ok((n, from)) = net.udp_recv_from(sock, &mut buf) {
                        if from.ip == server {
                            if let Some(a) = dns::answer(&buf[..n], id) {
                                got = Some(a);
                                break;
                            }
                        }
                    }
                    match got {
                        Some(Ok(ip)) => {
                            net.udp_close(sock);
                            if self.dns_cache.len() >= DNS_CACHE {
                                self.dns_cache.retain(|_, e| e.1 > now);
                                if self.dns_cache.len() >= DNS_CACHE {
                                    self.dns_cache.clear();
                                }
                            }
                            self.dns_cache.insert(cl.host.clone(), (ip, now + DNS_TTL_MS));
                            connect(cl, inst, net, ip, now);
                        }
                        Some(Err(())) => {
                            return fail(cl, net, 4, "502 Bad Gateway");
                        }
                        None => {
                            let Phase::Resolve { sent, tries, .. } = &mut cl.phase else { break };
                            if *sent == 0 || now - *sent >= DNS_RETRY_MS {
                                if *tries >= DNS_TRIES {
                                    return fail(cl, net, 4, "504 Gateway Timeout");
                                }
                                *tries += 1;
                                *sent = now;
                                match dns::query(id, &cl.host) {
                                    Some(q) => {
                                        let _ = net.udp_send_to(sock, SocketAddr { ip: server, port: 53 }, &q);
                                    }
                                    None => {
                                        return fail(cl, net, 4, "400 Bad Request");
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                Phase::Connecting => {
                    let Some(up) = cl.up.as_mut() else { return false };
                    match net.tcp_is_connected(up.stream) {
                        Ok(false) => break,
                        Ok(true) => {
                            let bound = net.tcp_local_addr(up.stream).unwrap_or(SocketAddr { ip: 0, port: 0 });
                            match cl.reply {
                                Reply::Socks => cl.c.write(&socks_reply(0, bound)),
                                Reply::HttpTunnel => cl.c.write(b"HTTP/1.1 200 Connection established\r\n\r\n"),
                                Reply::HttpPlain => {}
                            }
                            let first = core::mem::take(&mut cl.first);
                            up.write(&first);
                            cl.phase = Phase::Relay;
                            cl.last = now;
                        }
                        Err(_) => {
                            cl.up = None;
                            return fail(cl, net, 5, "502 Bad Gateway");
                        }
                    }
                }
                Phase::Relay => {
                    let Some(up) = cl.up.as_mut() else { return false };
                    let mut moved = 0;
                    if !cl.c.inbuf.is_empty() {
                        moved += cl.c.inbuf.len();
                        up.write(&cl.c.inbuf);
                        cl.c.inbuf.clear();
                    }
                    let room = if cl.c.queued() >= MAX_QUEUE { up.inbuf.len() } else { CHUNK };
                    let alive = up.pump(net, room);
                    if !up.inbuf.is_empty() {
                        moved += up.inbuf.len();
                        cl.c.write(&up.inbuf);
                        up.inbuf.clear();
                    }
                    inst.bytes += moved as u64;
                    if moved > 0 {
                        cl.last = now;
                    }
                    // no half-close: one side's end ends both, after the rest is sent
                    if !alive || up.eof {
                        if alive {
                            up.close();
                            up.pump(net, 0);
                        }
                        cl.c.close();
                        return cl.c.pump(net, 0);
                    }
                    if cl.c.eof {
                        up.close();
                        up.pump(net, 0);
                        cl.c.close();
                        return cl.c.pump(net, 0);
                    }
                    if now - cl.last >= IDLE_MS {
                        up.abort(net);
                        cl.c.abort(net);
                        return false;
                    }
                    break;
                }
            }
        }
        cl.c.pump(net, 0)
    }
}

fn drop_client(net: &mut dyn Net, c: &mut Client) {
    if let Phase::Resolve { sock, .. } = c.phase {
        net.udp_close(sock);
    }
    if let Some(u) = c.up.as_mut() {
        u.abort(net);
    }
    c.c.abort(net);
}

/// Tell the client the connection out failed (SOCKS reply code or HTTP status) and end.
/// (A lookup's socket is closed when the client is removed.)
fn fail(cl: &mut Client, net: &mut dyn Net, rep: u8, status: &str) -> bool {
    if let Some(u) = cl.up.as_mut() {
        u.abort(net);
    }
    match cl.reply {
        Reply::Socks => cl.c.write(&socks_reply(rep, SocketAddr { ip: 0, port: 0 })),
        _ => cl.c.write(&http_error(status, "")),
    }
    cl.c.close();
    cl.c.pump(net, 0);
    false
}

fn start_resolve(cl: &mut Client, inst: &Instance, cache: &mut BTreeMap<String, (Ip, u64)>, net: &mut dyn Net, now: u64) {
    cl.deadline = now + CONNECT_MS;
    if let Some(ip) = parse_ip(&cl.host) {
        return connect(cl, inst, net, ip, now);
    }
    let name = cl.host.to_ascii_lowercase();
    if let Some(&(ip, until)) = cache.get(&name) {
        if until > now {
            return connect(cl, inst, net, ip, now);
        }
    }
    cl.host = name;
    match net.udp_bind(0) {
        Ok(sock) => cl.phase = Phase::Resolve { sock, id: net.random() as u16, server: inst.dns, sent: 0, tries: 0 },
        Err(_) => {
            fail(cl, net, 1, "502 Bad Gateway");
            cl.phase = Phase::Connecting; // with no connection out: over
        }
    }
}

fn connect(cl: &mut Client, inst: &Instance, net: &mut dyn Net, ip: Ip, now: u64) {
    if inst.log {
        say!(net, "proxy: {}: {} -> {}:{}{}\n", inst.name, IpFmt(cl.c.peer.ip), cl.host, cl.port, if parse_ip(&cl.host).is_some() { String::new() } else { format!(" ({})", IpFmt(ip)) });
    }
    let to = SocketAddr { ip, port: cl.port };
    let r = if inst.egress != 0 { net.tcp_connect_from(inst.egress, to) } else { net.tcp_connect(to) };
    match r {
        Ok(s) => {
            cl.up = Some(Conn::new(s, to));
            cl.phase = Phase::Connecting;
            cl.deadline = now + CONNECT_MS;
        }
        Err(e) => {
            fail(cl, net, if e == NetError::NoRoute { 3 } else { 1 }, "502 Bad Gateway");
            // the caller notices: the client is closing
            cl.phase = Phase::Connecting;
        }
    }
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "<i>.listen", kind: "number", default: "", help: "the port (an instance without one is off)" },
    Param { key: "<i>.type", kind: "choice:mixed|socks5|http", default: "mixed", help: "socks5, http, or both on one port" },
    Param { key: "<i>.bind", kind: "address", default: "", help: "only connections to this address of ours (or interface)" },
    Param { key: "<i>.egress", kind: "address", default: "", help: "connect out from this address (its WAN)" },
    Param { key: "<i>.allow", kind: "list", default: "LAN networks", help: "who may use it: interfaces, networks, addresses, any" },
    Param { key: "<i>.user.<name>", kind: "secret", default: "", help: "logins (none: no login asked)" },
    Param { key: "<i>.dns", kind: "address", default: "1.1.1.1", help: "resolver for names" },
    Param { key: "<i>.max", kind: "number", default: "256", help: "connections at once" },
    Param { key: "<i>.log", kind: "switch", default: "off", help: "print each connection" },
];

impl Module for Proxy {
    fn name(&self) -> &'static str {
        "proxy"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
        if self.instances.is_empty() {
            say!(sys, "proxy: no instance (cfg proxy p1.listen 1080)\n");
        }
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
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
        while i < self.clients.len() {
            if self.step(sys, i, now) {
                i += 1;
            } else {
                let c = self.clients.swap_remove(i);
                if let Some(net) = sys.net() {
                    if let Phase::Resolve { sock, .. } = c.phase {
                        net.udp_close(sock);
                    }
                }
                for mut conn in core::iter::once(c.c).chain(c.up) {
                    conn.close();
                    self.closing.push((conn, now + CONNECT_MS));
                }
                if let Some(inst) = self.instances.iter_mut().find(|x| x.name == c.inst) {
                    inst.conns = inst.conns.saturating_sub(1);
                }
            }
        }
    }

    fn status(&self) -> String {
        if self.instances.is_empty() {
            return String::from("no instance (cfg proxy p1.listen 1080)");
        }
        self.instances
            .iter()
            .map(|i| {
                format!(
                    "{} {:?} {}:{} out {}: {} conns, {} total, {} KB{}",
                    i.name,
                    i.kind,
                    if i.bind == 0 { String::from("*") } else { format!("{}", IpFmt(i.bind)) },
                    i.port,
                    if i.egress == 0 { String::from("route") } else { format!("{}", IpFmt(i.egress)) },
                    i.conns,
                    i.total,
                    i.bytes / 1024,
                    if i.refused == 0 {
                        String::new()
                    } else if i.allow.is_empty() {
                        format!(", {} refused: open to nobody (set {}.allow)", i.refused, i.name)
                    } else {
                        format!(", {} refused", i.refused)
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}
