//! `curl`: an HTTP request with curl's options, through a DNS lookup, from
//! a chosen local address; HTTPS through the `tls` crate (TLS 1.3,
//! certificates checked against the Mozilla roots, and the CA certificates
//! of `cfg shell ca` if set). Other commands use it
//! too (`Curl::request`), keeping the answer instead of printing it.
//!
//! ```text
//! curl [-i] [-I] [-v] [-s] [-m secs] [-X method] [-H header]... [-d data]
//!      [--interface nicN|a.b.c.d] [--dns-servers a.b.c.d] [http[s]://]host[:port][/path]
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::socket::{SockAddr, Socket};
use rustros_api::{Sys, say};
use rustros_util::conn::Conn;
use rustros_util::dns;
use rustros_util::wire::{Ip, IpFmt, parse_ip};

pub const USAGE: &str = "usage: curl [-i] [-I] [-v] [-s] [-m secs] [-X method] [-H header]... [-d data] [--interface nicN|a.b.c.d] [--dns-servers a.b.c.d] [http[s]://]host[:port][/path]\n";
/// The resolver if neither `--dns-servers` nor `cfg shell dns` names one.
const DNS_DEFAULT: Ip = 0x0101_0101;
const DNS_RETRY_MS: u64 = 2000;
const DNS_TRIES: u8 = 3;
const SHOW_MAX: usize = 64 * 1024;

enum Phase {
    /// connect to this address on the next poll
    Start(Ip),
    Resolve { sock: Socket, id: u16, server: Ip, sent: u64, tries: u8 },
    Fetch { conn: Conn, tls: Option<Tls>, connected: bool, head: Vec<u8>, header_done: bool, shown: usize },
}

#[cfg(feature = "tls")]
type Tls = tls::TlsClient;
/// Without TLS there is never one.
#[cfg(not(feature = "tls"))]
struct Tls {
    established: bool,
    closed: bool,
    error: Option<String>,
}
#[cfg(not(feature = "tls"))]
impl Tls {
    fn take_outgoing(&mut self) -> Vec<u8> {
        Vec::new()
    }
    fn take_received(&mut self) -> Vec<u8> {
        Vec::new()
    }
    fn feed(&mut self, _: &[u8]) {}
}

/// A request for `Curl::request`.
#[derive(Default)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Vec<String>,
    pub body: Option<Vec<u8>>,
    pub src: Ip,
    pub max_secs: u64,
}

/// What a request kept (`Curl::request`): the status and the body, or why it failed.
pub type Answer = Result<(u16, Vec<u8>), String>;

pub struct Curl {
    host: String,
    port: u16,
    path: String,
    https: bool,
    src: Ip,
    method: String,
    headers: Vec<String>,
    data: Option<Vec<u8>>,
    /// keep the answer (`answer`) instead of printing it
    capture: bool,
    answer: Option<Answer>,
    status: u16,
    /// the body comes in chunks: kept whole and decoded at the end
    chunked: bool,
    body: Vec<u8>,
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
        let (mut method, mut headers, mut data) = (None, Vec::new(), None::<Vec<u8>>);
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
                "-X" | "--request" => method = Some(String::from(value(a)?)),
                "-H" | "--header" => headers.push(String::from(value(a)?)),
                "-d" | "--data" | "--data-raw" => {
                    // several -d: joined with '&', as curl does
                    let v = value(a)?;
                    let d = data.get_or_insert_with(Vec::new);
                    if !d.is_empty() {
                        d.push(b'&');
                    }
                    d.extend_from_slice(v.as_bytes());
                }
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
        if data.is_some() && !headers.iter().any(|h| h.to_ascii_lowercase().starts_with("content-type:")) {
            headers.push(String::from("Content-Type: application/x-www-form-urlencoded"));
        }
        let method = method.unwrap_or_else(|| String::from(if head_only { "HEAD" } else if data.is_some() { "POST" } else { "GET" }));
        let mut c = Curl::new(sys, url, src, dns_server, max_secs)?;
        (c.method, c.headers, c.data) = (method, headers, data);
        c.head_only = head_only;
        c.include = include || head_only;
        (c.verbose, c.silent) = (verbose, silent);
        if let (true, Phase::Resolve { server, .. }) = (verbose, &c.phase) {
            say!(sys, "* Resolving {} via {}\n", c.host, IpFmt(*server));
        }
        Ok(c)
    }

    /// A request whose answer is kept: poll until done, then `answer`.
    pub fn request(sys: &mut dyn Sys, r: Request) -> Result<Curl, String> {
        let mut c = Curl::new(sys, r.url, r.src, None, if r.max_secs == 0 { 15 } else { r.max_secs })?;
        c.method = String::from(r.method);
        (c.headers, c.data, c.capture) = (r.headers, r.body, true);
        Ok(c)
    }

    /// The answer of a finished `request`.
    pub fn answer(&mut self) -> Answer {
        self.answer.take().unwrap_or_else(|| Err(String::from("no answer")))
    }

    /// Report a failure: printed, or kept as the answer.
    fn fail(&mut self, sys: &mut dyn Sys, msg: String) {
        if self.capture {
            self.answer = Some(Err(String::from(msg.trim_end())));
        } else {
            sys.print(&msg);
        }
    }

    fn new(sys: &mut dyn Sys, url: &str, src: Ip, dns_server: Option<Ip>, max_secs: u64) -> Result<Curl, String> {
        let https = url.starts_with("https://");
        let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let hostport = hostport.rsplit('@').next().unwrap_or(hostport);
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| format!("curl: bad port in '{url}'\n"))?),
            None => (hostport, if https { 443 } else { 80 }),
        };
        if https && cfg!(not(feature = "tls")) {
            return Err(String::from("curl: this shell was built without TLS (the loadable shell module has it)\n"));
        }
        #[cfg(feature = "tls")]
        if https {
            if sys.unix_time() == 0 {
                return Err(String::from("curl: no clock (the real-time clock was not readable): certificates cannot be checked\n"));
            }
            // fresh hardware randomness for the keys
            let mut seed = [0u8; 32];
            for c in seed.chunks_mut(8) {
                c.copy_from_slice(&sys.random().to_le_bytes());
            }
            tls::seed(seed);
        }
        if host.is_empty() {
            return Err(String::from(USAGE));
        }
        let now = sys.now_ms();
        let mut c = Curl {
            host: String::from(host),
            port,
            path: String::from(path),
            https,
            src,
            method: String::from("GET"),
            headers: Vec::new(),
            data: None,
            capture: false,
            answer: None,
            status: 0,
            chunked: false,
            body: Vec::new(),
            head_only: false,
            include: false,
            verbose: false,
            silent: false,
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
                let sock = rustros_util::sock::udp_bind(net, 0).map_err(|e| format!("curl: {e:?}\n"))?;
                let id = sys.random() as u16;
                c.phase = Phase::Resolve { sock, id, server, sent: 0, tries: 0 };
            }
        }
        Ok(c)
    }

    fn connect(&mut self, sys: &mut dyn Sys, ip: Ip) -> Result<(), String> {
        let to = SockAddr::v4(ip, self.port);
        let net = sys.net().ok_or_else(|| String::from("curl: no network\n"))?;
        let s = if self.src != 0 { rustros_util::sock::tcp_connect(net, &to, self.src) } else { rustros_util::sock::tcp_connect(net, &to, 0) }.map_err(|e| format!("curl: cannot connect to {to}: {e:?}\n"))?;
        let mut conn = Conn::new(s, to);
        let default_port = if self.https { 443 } else { 80 };
        let host = if self.port == default_port { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", self.method, self.path);
        let has = |name: &str| self.headers.iter().any(|h| h.len() > name.len() && h[..name.len()].eq_ignore_ascii_case(name) && h.as_bytes()[name.len()] == b':');
        if !has("User-Agent") {
            req.push_str("User-Agent: curl/8.0 (RustROS)\r\n");
        }
        if !has("Accept") {
            req.push_str("Accept: */*\r\n");
        }
        for h in &self.headers {
            req.push_str(h);
            req.push_str("\r\n");
        }
        if let Some(d) = &self.data {
            req.push_str(&format!("Content-Length: {}\r\n", d.len()));
        }
        req.push_str("Connection: close\r\n\r\n");
        if self.verbose {
            let from = if self.src != 0 { format!(" from {}", IpFmt(self.src)) } else { String::new() };
            say!(sys, "*   Trying {}{}...\n", to, from);
            for l in req.split("\r\n").filter(|l| !l.is_empty()) {
                if l.len() > 15 && l[..14].eq_ignore_ascii_case("authorization:") {
                    say!(sys, "> {} ***\n", &l[..14]);
                } else {
                    say!(sys, "> {}\n", l);
                }
            }
        }
        let mut req = req.into_bytes();
        if let Some(d) = &self.data {
            req.extend_from_slice(d);
        }
        #[cfg(feature = "tls")]
        let tls = if self.https {
            tls::set_time(sys.unix_time());
            // `cfg shell ca`: CA certificates trusted besides the Mozilla
            // roots (a private CA; the regression tests' local server)
            let ca = sys.kv().and_then(|k| k.get("cfg/ca")).map(|v| rustros_util::pem::normalize(&String::from_utf8_lossy(&v))).unwrap_or_default();
            let mut t = tls::Tls::client_trusting(&self.host, &ca).map_err(|e| format!("curl: (35) TLS: {e}\n"))?;
            t.write(&req); // sent once the handshake is done
            Some(t)
        } else {
            conn.write(&req);
            None
        };
        #[cfg(not(feature = "tls"))]
        let tls: Option<Tls> = {
            conn.write(&req);
            None
        };
        self.phase = Phase::Fetch { conn, tls, connected: false, head: Vec::new(), header_done: false, shown: 0 };
        Ok(())
    }

    /// Work on it; true once finished (the prompt may come back).
    pub fn poll(&mut self, sys: &mut dyn Sys) -> bool {
        let now = sys.now_ms();
        if now >= self.deadline {
            self.fail(sys, format!("curl: (28) timed out after {} ms\n", now - self.started));
            self.abort(sys);
            return true;
        }
        match &mut self.phase {
            Phase::Start(ip) => {
                let ip = *ip;
                if let Err(e) = self.connect(sys, ip) {
                    self.fail(sys, e);
                    return true;
                }
                false
            }
            Phase::Resolve { sock, id, server, sent, tries } => {
                let (sock, id, server) = (*sock, *id, *server);
                let Some(net) = sys.net() else { return true };
                let mut buf = [0u8; 1500];
                while let Ok((n, from)) = net.recvfrom(sock, &mut buf, 0) {
                    if from.and_then(|a| a.ipv4()) != Some(server) {
                        continue;
                    }
                    match dns::answer(&buf[..n], id) {
                        Some(Ok(ip)) => {
                            let _ = net.close(sock);
                            if self.verbose {
                                say!(sys, "* {} is {}\n", self.host, IpFmt(ip));
                            }
                            return match self.connect(sys, ip) {
                                Ok(()) => false,
                                Err(e) => {
                                    self.fail(sys, e);
                                    true
                                }
                            };
                        }
                        Some(Err(())) => {
                            let _ = net.close(sock);
                            self.fail(sys, format!("curl: (6) Could not resolve host: {}\n", self.host));
                            return true;
                        }
                        None => {}
                    }
                }
                if *sent == 0 || now - *sent >= DNS_RETRY_MS {
                    if *tries >= DNS_TRIES {
                        let _ = net.close(sock);
                        self.fail(sys, format!("curl: (6) no answer from DNS server {}\n", IpFmt(server)));
                        return true;
                    }
                    *tries += 1;
                    *sent = now;
                    if let Some(q) = dns::query(id, &self.host) {
                        let _ = net.sendto(sock, &q, 0, Some(&SockAddr::v4(server, 53)));
                    } else {
                        let _ = net.close(sock);
                        self.fail(sys, format!("curl: (3) bad host name '{}'\n", self.host));
                        return true;
                    }
                }
                false
            }
            Phase::Fetch { conn, tls, connected, head, header_done, shown } => {
                let Some(net) = sys.net() else { return true };
                let up = rustros_util::sock::connected(net, conn.stream) == Ok(true);
                if let Some(t) = tls.as_mut() {
                    let out = t.take_outgoing();
                    conn.write(&out);
                }
                let mut alive = conn.pump(net, 64 * 1024);
                if let Some(t) = tls.as_mut() {
                    // ciphertext in, plaintext out (and the handshake's answers)
                    let cipher = core::mem::take(&mut conn.inbuf);
                    let was = t.established;
                    t.feed(&cipher);
                    let out = t.take_outgoing();
                    conn.write(&out);
                    alive = conn.pump(net, 64 * 1024) && alive;
                    let more = core::mem::take(&mut conn.inbuf);
                    t.feed(&more);
                    if t.established && !was && self.verbose {
                        say!(sys, "* TLS 1.3 handshake done, certificate for {} verified\n", self.host);
                    }
                    if let Some(e) = t.error.take() {
                        let msg = format!("curl: (60) TLS: {}\n", e);
                        if let Some(net) = sys.net() {
                            conn.abort(net);
                        }
                        self.fail(sys, msg);
                        return true;
                    }
                    conn.inbuf = t.take_received();
                    if t.closed && conn.inbuf.is_empty() {
                        conn.eof = true;
                    }
                }
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
                            let text = String::from_utf8_lossy(h);
                            self.status = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
                            self.chunked = text.split("\r\n").any(|l| {
                                l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"))
                            });
                            let keep = self.chunked || self.capture;
                            if self.include {
                                out.extend_from_slice(h);
                            } else if self.verbose {
                                for l in String::from_utf8_lossy(h).split("\r\n").filter(|l| !l.is_empty()) {
                                    out.extend_from_slice(format!("< {l}\n").as_bytes());
                                }
                            }
                            if keep {
                                self.body.extend_from_slice(&head[end + 4..]);
                            } else {
                                out.extend_from_slice(&head[end + 4..]);
                            }
                            body = &[];
                        }
                        None => body = &[],
                    }
                }
                if self.chunked || self.capture {
                    self.body.extend_from_slice(body);
                } else {
                    out.extend_from_slice(body);
                }
                let done = !alive || conn.eof;
                if done && *header_done {
                    if self.chunked {
                        self.body = dechunk(&self.body);
                    }
                    if !self.capture {
                        out.extend_from_slice(&self.body);
                    }
                }
                if !out.is_empty() && *shown < SHOW_MAX && !self.capture {
                    let n = out.len().min(SHOW_MAX - *shown);
                    say!(sys, "{}", String::from_utf8_lossy(&out[..n]));
                    *shown += n;
                    self.at_line_start = out[n - 1] == b'\n';
                }
                if done {
                    if let (true, Some(net)) = (alive, sys.net()) {
                        let _ = conn.close();
                        conn.pump(net, 0);
                    }
                    let (connected, header_done) = (*connected, *header_done);
                    if self.capture {
                        self.answer = Some(if header_done {
                            Ok((self.status, core::mem::take(&mut self.body)))
                        } else if connected {
                            Err(String::from("curl: (52) Empty reply from server"))
                        } else {
                            Err(format!("curl: (7) Failed to connect to {} port {}", self.host, self.port))
                        });
                        return true;
                    }
                    if !connected {
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
            Phase::Resolve { sock, .. } => {
                let _ = net.close(*sock);
            }
            Phase::Fetch { conn, .. } => conn.abort(net),
        }
    }
}

/// A chunked body, decoded (what arrived of it).
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = b.windows(2).position(|w| w == b"\r\n") {
        let size = core::str::from_utf8(&b[..eol]).ok().and_then(|l| usize::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16).ok());
        let Some(size) = size.filter(|&n| n > 0) else { break };
        b = &b[eol + 2..];
        let n = size.min(b.len());
        out.extend_from_slice(&b[..n]);
        b = b.get(n + 2..).unwrap_or(&[]);
    }
    out
}
