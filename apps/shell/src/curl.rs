//! `curl`: an HTTP GET (or HEAD) with curl's options, through a DNS lookup,
//! from a chosen local address. Plain HTTP only (no TLS yet).
//!
//! ```text
//! curl [-i] [-I] [-v] [-s] [-m secs] [--interface nicN|a.b.c.d] [--dns-servers a.b.c.d] [http://]host[:port][/path]
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{SocketAddr, Sys, UdpSocket, say};
use rustros_util::conn::Conn;
use rustros_util::dns;
use rustros_util::wire::{Ip, IpFmt, parse_ip};

pub const USAGE: &str = "usage: curl [-i] [-I] [-v] [-s] [-m secs] [--interface nicN|a.b.c.d] [--dns-servers a.b.c.d] [http://]host[:port][/path]\n";
/// The resolver if neither `--dns-servers` nor `cfg shell dns` names one.
const DNS_DEFAULT: Ip = 0x0101_0101;
const DNS_RETRY_MS: u64 = 2000;
const DNS_TRIES: u8 = 3;
const SHOW_MAX: usize = 64 * 1024;

enum Phase {
    /// connect to this address on the next poll
    Start(Ip),
    Resolve { sock: UdpSocket, id: u16, server: Ip, sent: u64, tries: u8 },
    Fetch { conn: Conn, connected: bool, head: Vec<u8>, header_done: bool, shown: usize },
}

pub struct Curl {
    host: String,
    port: u16,
    path: String,
    src: Ip,
    head_only: bool,
    include: bool,
    verbose: bool,
    silent: bool,
    started: u64,
    deadline: u64,
    phase: Phase,
    /// the output so far ends a line
    at_line_start: bool,
}

/// Our address `spec` names: an interface (its address) or one of our
/// addresses (an interface's or an extra one).
pub fn our_address(sys: &mut dyn Sys, spec: &str) -> Result<Ip, String> {
    let Some(net) = sys.net() else { return Err(String::from("no network")) };
    let mine = |ip: Ip| (0..net.nic_count()).any(|i| net.nic_info(i).is_some_and(|f| f.ip == ip) || net.extra_addrs(i).contains(&ip));
    if let Some(ip) = parse_ip(spec) {
        return if ip != 0 && mine(ip) { Ok(ip) } else { Err(format!("{} is not one of our addresses", IpFmt(ip))) };
    }
    let i = rustros_util::netcmd::find_nic(sys, spec).ok_or_else(|| format!("no interface '{spec}'"))?;
    match sys.net().and_then(|n| n.nic_info(i)).map(|n| n.ip) {
        Some(ip) if ip != 0 => Ok(ip),
        _ => Err(format!("{spec} has no address")),
    }
}

impl Curl {
    pub fn start(sys: &mut dyn Sys, args: &[&str]) -> Result<Curl, String> {
        let (mut include, mut head_only, mut verbose, mut silent) = (false, false, false, false);
        let (mut src, mut dns_server, mut max_secs, mut url) = (0, None, 15u64, None);
        let mut it = args.iter().copied();
        while let Some(a) = it.next() {
            let mut value = |name: &str| it.next().ok_or_else(|| format!("curl: {name} needs a value\n{USAGE}"));
            match a {
                "--interface" => src = our_address(sys, value(a)?).map_err(|e| format!("curl: {e}\n"))?,
                "--dns-servers" => {
                    let v = value(a)?;
                    dns_server = Some(v.split(',').next().and_then(parse_ip).ok_or_else(|| format!("curl: bad DNS server '{v}'\n"))?);
                }
                "-m" | "--max-time" => max_secs = value(a)?.parse().ok().filter(|&s| s > 0).ok_or_else(|| String::from("curl: bad --max-time\n"))?,
                "--include" => include = true,
                "--head" => head_only = true,
                "--verbose" => verbose = true,
                "--silent" => silent = true,
                f if f.starts_with('-') && f.len() > 1 && !f.starts_with("--") => {
                    for c in f[1..].chars() {
                        match c {
                            'i' => include = true,
                            'I' => head_only = true,
                            'v' => verbose = true,
                            's' => silent = true,
                            _ => return Err(format!("curl: unknown option -{c}\n{USAGE}")),
                        }
                    }
                }
                f if f.starts_with("--") => return Err(format!("curl: unknown option {f}\n{USAGE}")),
                u => url = Some(u),
            }
        }
        let Some(url) = url else { return Err(String::from(USAGE)) };
        if url.starts_with("https://") {
            return Err(String::from("curl: https needs TLS, which RustROS does not have yet; use http://\n"));
        }
        let rest = url.strip_prefix("http://").unwrap_or(url);
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let hostport = hostport.rsplit('@').next().unwrap_or(hostport);
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| format!("curl: bad port in '{url}'\n"))?),
            None => (hostport, 80),
        };
        if host.is_empty() {
            return Err(String::from(USAGE));
        }
        let now = sys.now_ms();
        let mut c = Curl {
            host: String::from(host),
            port,
            path: String::from(path),
            src,
            head_only,
            include: include || head_only,
            verbose,
            silent,
            started: now,
            deadline: now + max_secs * 1000,
            phase: Phase::Start(0),
            at_line_start: true,
        };
        match parse_ip(host) {
            Some(ip) => c.phase = Phase::Start(ip),
            None => {
                let server = dns_server
                    .or_else(|| sys.kv().and_then(|k| k.get("cfg/dns")).and_then(|v| parse_ip(core::str::from_utf8(&v).ok()?.trim())))
                    .unwrap_or(DNS_DEFAULT);
                let net = sys.net().ok_or_else(|| String::from("curl: no network\n"))?;
                let sock = net.udp_bind(0).map_err(|e| format!("curl: {e:?}\n"))?;
                let id = sys.random() as u16;
                if c.verbose {
                    say!(sys, "* Resolving {} via {}\n", c.host, IpFmt(server));
                }
                c.phase = Phase::Resolve { sock, id, server, sent: 0, tries: 0 };
            }
        }
        Ok(c)
    }

    fn connect(&mut self, sys: &mut dyn Sys, ip: Ip) -> Result<(), String> {
        let to = SocketAddr { ip, port: self.port };
        let net = sys.net().ok_or_else(|| String::from("curl: no network\n"))?;
        let s = if self.src != 0 { net.tcp_connect_from(self.src, to) } else { net.tcp_connect(to) }.map_err(|e| format!("curl: cannot connect to {to}: {e:?}\n"))?;
        let mut conn = Conn::new(s, to);
        let method = if self.head_only { "HEAD" } else { "GET" };
        let host = if self.port == 80 { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
        let req = format!("{method} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.0 (RustROS)\r\nAccept: */*\r\nConnection: close\r\n\r\n", self.path);
        if self.verbose {
            let from = if self.src != 0 { format!(" from {}", IpFmt(self.src)) } else { String::new() };
            say!(sys, "*   Trying {}{}...\n", to, from);
            for l in req.split("\r\n").filter(|l| !l.is_empty()) {
                say!(sys, "> {}\n", l);
            }
        }
        conn.write(req.as_bytes());
        self.phase = Phase::Fetch { conn, connected: false, head: Vec::new(), header_done: false, shown: 0 };
        Ok(())
    }

    /// Work on it; true once finished (the prompt may come back).
    pub fn poll(&mut self, sys: &mut dyn Sys) -> bool {
        let now = sys.now_ms();
        if now >= self.deadline {
            say!(sys, "curl: (28) timed out after {} ms\n", now - self.started);
            self.abort(sys);
            return true;
        }
        match &mut self.phase {
            Phase::Start(ip) => {
                let ip = *ip;
                if let Err(e) = self.connect(sys, ip) {
                    say!(sys, "{}", e);
                    return true;
                }
                false
            }
            Phase::Resolve { sock, id, server, sent, tries } => {
                let (sock, id, server) = (*sock, *id, *server);
                let Some(net) = sys.net() else { return true };
                let mut buf = [0u8; 1500];
                while let Ok((n, from)) = net.udp_recv_from(sock, &mut buf) {
                    if from.ip != server {
                        continue;
                    }
                    match dns::answer(&buf[..n], id) {
                        Some(Ok(ip)) => {
                            net.udp_close(sock);
                            if self.verbose {
                                say!(sys, "* {} is {}\n", self.host, IpFmt(ip));
                            }
                            return match self.connect(sys, ip) {
                                Ok(()) => false,
                                Err(e) => {
                                    say!(sys, "{}", e);
                                    true
                                }
                            };
                        }
                        Some(Err(())) => {
                            net.udp_close(sock);
                            say!(sys, "curl: (6) Could not resolve host: {}\n", self.host);
                            return true;
                        }
                        None => {}
                    }
                }
                if *sent == 0 || now - *sent >= DNS_RETRY_MS {
                    if *tries >= DNS_TRIES {
                        net.udp_close(sock);
                        say!(sys, "curl: (6) no answer from DNS server {}\n", IpFmt(server));
                        return true;
                    }
                    *tries += 1;
                    *sent = now;
                    if let Some(q) = dns::query(id, &self.host) {
                        let _ = net.udp_send_to(sock, SocketAddr { ip: server, port: 53 }, &q);
                    } else {
                        net.udp_close(sock);
                        say!(sys, "curl: (3) bad host name '{}'\n", self.host);
                        return true;
                    }
                }
                false
            }
            Phase::Fetch { conn, connected, head, header_done, shown } => {
                let Some(net) = sys.net() else { return true };
                let up = net.tcp_is_connected(conn.stream) == Ok(true);
                let alive = conn.pump(net, 64 * 1024);
                if !*connected && up {
                    *connected = true;
                    if self.verbose {
                        say!(sys, "* Connected to {} ({}) in {} ms\n", self.host, conn.peer, now - self.started);
                    }
                }
                let data = core::mem::take(&mut conn.inbuf);
                let mut body: &[u8] = &data;
                let mut out = Vec::new();
                if !*header_done && !data.is_empty() {
                    head.extend_from_slice(&data);
                    match head.windows(4).position(|w| w == b"\r\n\r\n") {
                        Some(end) => {
                            *header_done = true;
                            let h = &head[..end + 4];
                            if self.include {
                                out.extend_from_slice(h);
                            } else if self.verbose {
                                for l in String::from_utf8_lossy(h).split("\r\n").filter(|l| !l.is_empty()) {
                                    out.extend_from_slice(format!("< {l}\n").as_bytes());
                                }
                            }
                            out.extend_from_slice(&head[end + 4..]);
                            body = &[];
                        }
                        None => body = &[],
                    }
                }
                out.extend_from_slice(body);
                if !out.is_empty() && *shown < SHOW_MAX {
                    let n = out.len().min(SHOW_MAX - *shown);
                    say!(sys, "{}", String::from_utf8_lossy(&out[..n]));
                    *shown += n;
                    self.at_line_start = out[n - 1] == b'\n';
                }
                if !alive || conn.eof {
                    if let (true, Some(net)) = (alive, sys.net()) {
                        conn.close();
                        conn.pump(net, 0);
                    }
                    if !*connected {
                        say!(sys, "curl: (7) Failed to connect to {} port {}\n", self.host, self.port);
                    } else if !self.silent && self.verbose {
                        say!(sys, "* closed after {} ms\n", now - self.started);
                    }
                    if !self.at_line_start {
                        say!(sys, "\n");
                    }
                    return true;
                }
                false
            }
        }
    }

    pub fn abort(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        match &mut self.phase {
            Phase::Start(_) => {}
            Phase::Resolve { sock, .. } => net.udp_close(*sock),
            Phase::Fetch { conn, .. } => conn.abort(net),
        }
    }
}
