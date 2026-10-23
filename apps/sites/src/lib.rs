//! Sites: the web server in front of this machine's sites. A request finds
//! its site by the name it is for (Host, and SNI for the certificate);
//! a site serves its files (from this app's directory on the files
//! partition) or passes requests on to a backend over HTTP. Plain HTTP is
//! sent to HTTPS where the site has a certificate.
//!
//! Files go up over HTTPS with the upload token:
//! `PUT /_sites/files/<path>` (the body is the file), `DELETE` the same,
//! `GET /_sites/files/?prefix=<p>` lists them (JSON). A site's files are
//! under `<root>/` (the root is the site's name unless set).
//!
//! Settings (`cfg sites <key> <value>`):
//!
//! ```text
//! http                 80          plain HTTP port (0: off)
//! https                443         HTTPS port (0: off)
//! token                secret      the upload token (none: no uploads)
//! site.<name>.hosts    rustros.com,www.rustros.com   the names it answers
//! site.<name>.root     rustros.com its files' directory
//! site.<name>.proxy    10.9.0.5:8080   pass requests on to this backend instead
//! site.<name>.cert     PEM         its certificate and chain (one line)
//! site.<name>.key      PEM         its private key (secret)
//! site.<name>.redirect on          plain HTTP to HTTPS when it has a certificate
//! acme                 on          certificates from an ACME CA for sites without one
//! acme.directory       URL         the CA (default Let's Encrypt)
//! acme.email           address     the account's contact
//! acme.ca              PEM         also trust this CA (a test CA's directory)
//! acme.dns             1.1.1.1     resolver for the CA's name
//! ```
//!
//! ACME uses HTTP-01: the site's names must reach this machine on port 80.
//! A certificate is renewed after 60 days; a failed order is tried again
//! after an hour, then less often (up to a day).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod acme;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use rustros_api::socket::{SockAddr, Socket};
use rustros_api::{Caps, Module, Param, Sys, say};
use rustros_util::conn::Conn;
use rustros_util::json::quote;
use rustros_util::wire::{IpFmt, parse_ip};

const RELOAD_MS: u64 = 2000;
const MAX_HEAD: usize = 16 * 1024;
/// An upload is at most this (the files partition's limit).
const MAX_BODY: usize = 64 << 20;
/// Time for a request to come in, and to be answered by a backend.
const REQUEST_MS: u64 = 30_000;
const PROXY_MS: u64 = 120_000;
/// Plaintext waiting to go out before more of a file is read.
const OUT_LOW: usize = 128 * 1024;
const CHUNK: usize = 64 * 1024;
const MAX_CONNS: usize = 256;

#[derive(Clone)]
struct Site {
    name: String,
    hosts: Vec<String>,
    root: String,
    proxy: Option<SockAddr>,
    cert: bool,
    /// its certificate is set by hand (no ACME for it)
    manual: bool,
    redirect: bool,
}

enum Phase {
    /// the request's head (and body, for uploads)
    Reading,
    /// a file going out: (its name, next offset, end)
    File(String, u64, u64),
    /// passing the backend's answer on
    Proxy(Conn),
    /// the answer is queued; close once it is out
    Done,
}

struct Client {
    c: Conn,
    tls: Option<tls::Tls>,
    /// plaintext from the client
    input: Vec<u8>,
    /// plaintext to the client
    out: Vec<u8>,
    phase: Phase,
    deadline: u64,
    /// "GET /x" for the log
    what: String,
}

#[derive(Default)]
pub struct Sites {
    sites: Vec<Site>,
    http: u16,
    https: u16,
    token: Option<String>,
    tls: Option<Arc<tls::RustlsServerConfig>>,
    lhttp: Option<(u16, Socket)>,
    lhttps: Option<(u16, Socket)>,
    clients: Vec<Client>,
    closing: Vec<(Conn, u64)>,
    applied: String,
    reload_at: u64,
    served: u64,
    acme_on: bool,
    acme_dir: String,
    acme_email: String,
    acme_ca: String,
    acme_dns: rustros_util::wire::Ip,
    order: Option<acme::Order>,
    /// per site: (next try, failures in a row)
    acme_backoff: BTreeMap<String, (u64, u32)>,
    acme_check_at: u64,
}

fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "md" | "sh" | "pub" | "sig" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}

fn url_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = core::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A request path as a relative file path: decoded, no "." or ".." parts.
fn clean_path(target: &str) -> Option<String> {
    let path = target.split(['?', '#']).next()?;
    let decoded = url_decode(path)?;
    let mut parts = Vec::new();
    for p in decoded.split('/') {
        match p {
            "" | "." => {}
            ".." => return None,
            p if p.contains('\0') || p.contains('\\') => return None,
            p => parts.push(p),
        }
    }
    let mut s = parts.join("/");
    if decoded.ends_with('/') && !s.is_empty() {
        s.push('/');
    }
    Some(s)
}

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        201 => "201 Created",
        204 => "204 No Content",
        301 => "301 Moved Permanently",
        304 => "304 Not Modified",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        413 => "413 Payload Too Large",
        502 => "502 Bad Gateway",
        504 => "504 Gateway Timeout",
        507 => "507 Insufficient Storage",
        _ => "500 Internal Server Error",
    }
}

fn simple(code: u16, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        status_line(code),
        body.len()
    )
    .into_bytes()
}

struct Request<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl Request<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| *v)
    }
    fn host(&self) -> String {
        let h = self.header("Host").unwrap_or("");
        let h = if h.starts_with('[') { h } else { h.rsplit_once(':').map_or(h, |(a, _)| a) };
        h.trim_end_matches('.').to_ascii_lowercase()
    }
}

fn parse_head(head: &str) -> Option<Request<'_>> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let headers = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim(), v.trim())).collect();
    Some(Request { method, target, version, headers })
}

fn get<'a>(s: &[(&str, &'a str)], k: &str) -> Option<&'a str> {
    s.iter().find(|(x, _)| *x == k).map(|(_, v)| *v)
}

impl Sites {
    pub fn new() -> Sites {
        Sites::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
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
        let text: String = settings.iter().map(|(k, v)| format!("{k}={v};")).collect();
        if text == self.applied {
            return;
        }
        self.applied = text;
        let s: Vec<(&str, &str)> = settings.iter().map(|(k, v)| (k.as_str(), v.trim())).collect();
        self.http = get(&s, "http").and_then(|p| p.parse().ok()).unwrap_or(80);
        self.acme_on = get(&s, "acme") != Some("off");
        self.acme_dir = String::from(get(&s, "acme.directory").unwrap_or(acme::LETS_ENCRYPT));
        self.acme_email = String::from(get(&s, "acme.email").unwrap_or(""));
        self.acme_ca = get(&s, "acme.ca").map(rustros_util::pem::normalize).unwrap_or_default();
        self.acme_dns = get(&s, "acme.dns").and_then(parse_ip).unwrap_or(0x0101_0101);
        self.https = get(&s, "https").and_then(|p| p.parse().ok()).unwrap_or(443);
        self.token = get(&s, "token").filter(|t| t.len() >= 16).map(String::from);
        if get(&s, "token").is_some_and(|t| t.len() < 16) {
            say!(sys, "sites: the upload token is too short (16 characters at least): uploads are off\n");
        }
            let mut names: Vec<&str> = s.iter().filter_map(|(k, _)| k.strip_prefix("site.")?.split_once('.').map(|(n, _)| n)).collect();
        names.dedup();
        let mut sites = Vec::new();
        let mut certs = Vec::new();
        for n in names {
            let sv = |k: &str| get(&s, &format!("site.{n}.{k}"));
            let hosts: Vec<String> = sv("hosts").unwrap_or(n).split(',').map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
            let proxy = match sv("proxy") {
                Some(p) => {
                    let p = p.trim_start_matches("http://").trim_end_matches('/');
                    let (h, port) = p.rsplit_once(':').map_or((p, 80), |(h, port)| (h, port.parse().unwrap_or(80)));
                    match parse_ip(h) {
                        Some(ip) => Some(SockAddr::v4(ip, port)),
                        None => {
                            say!(sys, "sites: {}: proxy wants an address (a.b.c.d:port), not '{}'\n", n, h);
                            None
                        }
                    }
                }
                None => None,
            };
            let mut cert = false;
            if let (Some(c), Some(k)) = (sv("cert"), sv("key")) {
                certs.push((hosts.clone(), rustros_util::pem::normalize(c), rustros_util::pem::normalize(k)));
                cert = true;
            } else if let (Some(c), Some(k)) = (kv_str(sys, &format!("acme/{n}/cert")), kv_str(sys, &format!("acme/{n}/key"))) {
                certs.push((hosts.clone(), c, k));
                cert = true;
            }
            let manual = sv("cert").is_some();
            sites.push(Site { name: String::from(n), root: String::from(sv("root").unwrap_or(n)), hosts, proxy, cert, manual, redirect: sv("redirect") != Some("off") });
        }
        self.tls = if certs.is_empty() {
            None
        } else {
            match tls::server_config_sni(&certs) {
                Ok(c) => Some(c),
                Err(e) => {
                    say!(sys, "sites: certificates: {}\n", e);
                    None
                }
            }
        };
        for st in &sites {
            say!(
                sys,
                "sites: {} ({}) {}{}\n",
                st.name,
                st.hosts.join(", "),
                match st.proxy {
                    Some(p) => format!("→ {}", p),
                    None => format!("files in {}/", st.root),
                },
                if st.cert { ", HTTPS" } else { "" }
            );
        }
        if sites.is_empty() {
            say!(sys, "sites: no site (cfg sites site.<name>.hosts example.com)\n");
        }
        self.sites = sites;
        self.listen(sys);
    }

    fn listen(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        let want_https = if self.tls.is_some() { self.https } else { 0 };
        for (slot, want) in [(&mut self.lhttp, self.http), (&mut self.lhttps, want_https)] {
            if slot.is_some_and(|(p, _)| p != want) {
                if let Some((_, l)) = slot.take() {
                    let _ = net.close(l);
                }
            }
            if slot.is_none() && want != 0 && !self.sites.is_empty() {
                match rustros_util::sock::tcp_listen(net, want) {
                    Ok(l) => *slot = Some((want, l)),
                    Err(e) => say!(net, "sites: cannot listen on {}: {:?}\n", want, e),
                }
            }
        }
    }

    fn accept(&mut self, sys: &mut dyn Sys, now: u64) {
        let Some(net) = sys.net() else { return };
        for secure in [false, true] {
            let Some((_, l)) = (if secure { self.lhttps } else { self.lhttp }) else { continue };
            while let Ok((s, peer)) = net.accept(l, 0) {
                if self.clients.len() >= MAX_CONNS {
                    rustros_util::sock::abort(net, s);
                    continue;
                }
                let tls = match (secure, &self.tls) {
                    (true, Some(cfg)) => match tls::Tls::server(cfg.clone()) {
                        Ok(t) => Some(t),
                        Err(_) => {
                            rustros_util::sock::abort(net, s);
                            continue;
                        }
                    },
                    (true, None) => {
                        rustros_util::sock::abort(net, s);
                        continue;
                    }
                    _ => None,
                };
                self.clients.push(Client { c: Conn::new(s, peer), tls, input: Vec::new(), out: Vec::new(), phase: Phase::Reading, deadline: now + REQUEST_MS, what: String::new() });
            }
        }
    }

    fn site_for(&self, host: &str) -> Option<&Site> {
        self.sites.iter().find(|s| s.hosts.iter().any(|h| h == host)).or(self.sites.first())
    }

    /// A whole request is in `cl.input`: decide the answer.
    fn answer(&mut self, sys: &mut dyn Sys, cl: &mut Client, now: u64) {
        let input = core::mem::take(&mut cl.input);
        let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") else { return };
        let head = String::from_utf8_lossy(&input[..end]).into_owned();
        let Some(req) = parse_head(&head) else {
            cl.out = simple(400, "", "bad request\n");
            cl.phase = Phase::Done;
            return;
        };
        let body = &input[end + 4..];
        cl.what = format!("{} {}{}", req.method, req.host(), req.target);
        let secure = cl.tls.is_some();
        // uploads
        if let Some(rest) = req.target.strip_prefix("/_sites/files/") {
            cl.out = self.upload(sys, &req, rest, body, secure);
            cl.phase = Phase::Done;
            return;
        }
        // ACME's check of a name: the key authorization the client stored
        if let Some(token) = req.target.strip_prefix("/.well-known/acme-challenge/") {
            cl.out = match kv_str(sys, &format!("acme/challenge/{token}")) {
                Some(k) if !token.contains('/') => format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{k}", k.len()).into_bytes(),
                _ => simple(404, "", "not found\n"),
            };
            cl.phase = Phase::Done;
            return;
        }
        let host = req.host();
        let Some(site) = self.site_for(&host).cloned() else {
            cl.out = simple(404, "", "no site here\n");
            cl.phase = Phase::Done;
            return;
        };
        if !secure && site.cert && site.redirect && self.https != 0 && self.tls.is_some() {
            let port = if self.https == 443 { String::new() } else { format!(":{}", self.https) };
            cl.out = simple(301, &format!("Location: https://{host}{port}{}\r\n", req.target), "moved to HTTPS\n");
            cl.phase = Phase::Done;
            return;
        }
        if let Some(backend) = site.proxy {
            self.proxy(sys, cl, &req, body, backend, secure, now);
            return;
        }
        if req.method != "GET" && req.method != "HEAD" {
            cl.out = simple(405, "Allow: GET, HEAD\r\n", "method not allowed\n");
            cl.phase = Phase::Done;
            return;
        }
        let Some(rel) = clean_path(req.target) else {
            cl.out = simple(400, "", "bad path\n");
            cl.phase = Phase::Done;
            return;
        };
        let Some(kv) = sys.kv() else { return };
        let mut name = format!("{}/{}", site.root, rel.trim_end_matches('/'));
        if rel.is_empty() || rel.ends_with('/') {
            name = format!("{}/{}index.html", site.root, rel);
        }
        let mut stat = kv.file_stat(&name);
        if stat.is_none() && !rel.is_empty() && !rel.ends_with('/') {
            // a directory without its slash
            if kv.file_stat(&format!("{}/{}/index.html", site.root, rel)).is_some() {
                cl.out = simple(301, &format!("Location: /{rel}/\r\n"), "moved\n");
                cl.phase = Phase::Done;
                return;
            }
        }
        let Some((size, mtime)) = stat.take() else {
            cl.out = simple(404, "", "not found\n");
            cl.phase = Phase::Done;
            return;
        };
        let etag = format!("\"{size:x}-{mtime:x}\"");
        if req.header("If-None-Match") == Some(etag.as_str()) {
            cl.out = format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nConnection: close\r\n\r\n").into_bytes();
            cl.phase = Phase::Done;
            return;
        }
        cl.out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {size}\r\nETag: {etag}\r\nCache-Control: {}\r\nConnection: close\r\n\r\n",
            content_type(&name),
            if name.ends_with(".json") || name.ends_with(".html") { "no-cache" } else { "max-age=300" }
        )
        .into_bytes();
        self.served += 1;
        cl.phase = if req.method == "HEAD" || size == 0 { Phase::Done } else { Phase::File(name, 0, size) };
    }

    fn upload(&mut self, sys: &mut dyn Sys, req: &Request, rest: &str, body: &[u8], secure: bool) -> Vec<u8> {
        if !secure {
            return simple(403, "", "uploads only over HTTPS\n");
        }
        let Some(token) = &self.token else { return simple(403, "", "no upload token set\n") };
        let given = req.header("Authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
        if !rustros_util::sha256::ct_eq(given.as_bytes(), token.as_bytes()) {
            return simple(401, "", "wrong token\n");
        }
        let Some(kv) = sys.kv() else { return simple(500, "", "no storage\n") };
        match req.method {
            "GET" => {
                let prefix = req.target.split_once("?prefix=").map(|(_, p)| url_decode(p).unwrap_or_default()).unwrap_or_default();
                let list: Vec<String> = kv.file_list(&prefix).iter().map(|(n, size)| format!("{{\"name\":{},\"size\":{size}}}", quote(n))).collect();
                let b = format!("[{}]", list.join(","));
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).into_bytes()
            }
            "PUT" | "DELETE" => {
                let Some(path) = clean_path(rest).filter(|p| !p.is_empty() && !p.ends_with('/')) else { return simple(400, "", "bad path\n") };
                if req.method == "DELETE" {
                    return if kv.file_delete(&path) { simple(204, "", "") } else { simple(404, "", "not found\n") };
                }
                match kv.file_put(&path, body) {
                    Ok(()) => {
                        say!(kv, "sites: uploaded {} ({} bytes)\n", path, body.len());
                        simple(201, "", "stored\n")
                    }
                    Err(rustros_api::KvError::Full) => simple(507, "", "the files partition is full\n"),
                    Err(e) => simple(500, "", &format!("not stored: {e:?}\n")),
                }
            }
            _ => simple(405, "", "method not allowed\n"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proxy(&mut self, sys: &mut dyn Sys, cl: &mut Client, req: &Request, body: &[u8], backend: SockAddr, secure: bool, now: u64) {
        let Some(net) = sys.net() else { return };
        let Ok(s) = rustros_util::sock::tcp_connect(net, &backend, 0) else {
            cl.out = simple(502, "", "the backend is unreachable\n");
            cl.phase = Phase::Done;
            return;
        };
        let mut up = Conn::new(s, backend);
        let mut head = format!("{} {} {}\r\n", req.method, req.target, req.version);
        for (k, v) in &req.headers {
            if ["Connection", "Keep-Alive", "Proxy-Connection", "X-Forwarded-For", "X-Forwarded-Proto", "Upgrade"].iter().any(|d| k.eq_ignore_ascii_case(d)) {
                continue;
            }
            head += &format!("{k}: {v}\r\n");
        }
        head += &format!("X-Forwarded-For: {}\r\nX-Forwarded-Proto: {}\r\nConnection: close\r\n\r\n", IpFmt(cl.c.peer.ipv4().unwrap_or(0)), if secure { "https" } else { "http" });
        up.write(head.as_bytes());
        up.write(body);
        cl.deadline = now + PROXY_MS;
        cl.phase = Phase::Proxy(up);
    }

    /// One client's step; false when it is over.
    fn step(&mut self, sys: &mut dyn Sys, mut cl: Client, now: u64) -> Option<Client> {
        let Some(net) = sys.net() else { return Some(cl) };
        if now >= cl.deadline {
            if let Phase::Proxy(mut up) = core::mem::replace(&mut cl.phase, Phase::Done) {
                up.abort(net);
                cl.out.extend_from_slice(&simple(504, "", "the backend did not answer in time\n"));
            } else {
                cl.c.abort(net);
                return None;
            }
        }
        // the wire
        let reading = matches!(cl.phase, Phase::Reading);
        let room = if reading { MAX_HEAD + MAX_BODY } else { 0 };
        let alive = cl.c.pump(net, room.min(cl.c.inbuf.len() + 256 * 1024));
        if !cl.c.inbuf.is_empty() {
            let data = core::mem::take(&mut cl.c.inbuf);
            match cl.tls.as_mut() {
                Some(t) => t.feed(&data),
                None => cl.input.extend_from_slice(&data),
            }
        }
        if let Some(t) = cl.tls.as_mut() {
            if t.error.is_some() {
                cl.c.abort(net);
                return None;
            }
            cl.input.extend_from_slice(&t.take_received());
        }
        if !alive {
            if let Phase::Proxy(mut up) = core::mem::replace(&mut cl.phase, Phase::Done) {
                up.abort(net);
            }
            return None;
        }
        if reading {
            if let Some(end) = cl.input.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&cl.input[..end]).into_owned();
                let len = parse_head(&head).and_then(|r| r.header("Content-Length").and_then(|l| l.parse::<usize>().ok())).unwrap_or(0);
                if len > MAX_BODY {
                    cl.out = simple(413, "", "too large\n");
                    cl.phase = Phase::Done;
                } else if cl.input.len() >= end + 4 + len {
                    cl.input.truncate(end + 4 + len);
                    self.answer(sys, &mut cl, now);
                }
            } else if cl.input.len() > MAX_HEAD {
                cl.out = simple(400, "", "request head too large\n");
                cl.phase = Phase::Done;
            }
        }
        // more of a file, as the output drains
        let backlog = cl.out.len() + cl.c.queued() + cl.tls.as_ref().map_or(0, |t| t.pending_write());
        if let Phase::File(name, off, end) = &mut cl.phase {
            if backlog < OUT_LOW {
                let n = ((*end - *off) as usize).min(CHUNK);
                let mut buf = alloc::vec![0u8; n];
                let got = sys.kv().and_then(|kv| kv.file_read(name, *off, &mut buf)).unwrap_or(0);
                if got == 0 {
                    cl.phase = Phase::Done; // cut short: the length promised was not met; the client sees it
                } else {
                    cl.out.extend_from_slice(&buf[..got]);
                    *off += got as u64;
                    if *off >= *end {
                        cl.phase = Phase::Done;
                    }
                }
            }
        }
        let Some(net) = sys.net() else { return Some(cl) };
        if let Phase::Proxy(up) = &mut cl.phase {
            let room = if backlog > OUT_LOW { up.inbuf.len() } else { CHUNK };
            let alive = up.pump(net, room);
            cl.out.extend_from_slice(&core::mem::take(&mut up.inbuf));
            if !alive || up.eof {
                let Phase::Proxy(mut up) = core::mem::replace(&mut cl.phase, Phase::Done) else { unreachable!() };
                let _ = up.close();
                up.pump(net, 0);
            }
        }
        // out: through TLS or straight
        if !cl.out.is_empty() {
            let out = core::mem::take(&mut cl.out);
            match cl.tls.as_mut() {
                Some(t) => t.write(&out),
                None => cl.c.write(&out),
            }
        }
        if let Some(t) = cl.tls.as_mut() {
            let w = t.take_outgoing();
            if !w.is_empty() {
                cl.c.write(&w);
            }
        }
        cl.c.pump(net, 0);
        if matches!(cl.phase, Phase::Done) && cl.out.is_empty() && cl.tls.as_ref().is_none_or(|t| t.pending_write() == 0) {
            // all handed over: close once sent
            let _ = cl.c.close();
            self.closing.push((cl.c, now + REQUEST_MS));
            return None;
        }
        Some(cl)
    }
}

impl Sites {
    /// Certificates: one order at a time, for a site that has none or an old one.
    fn acme(&mut self, sys: &mut dyn Sys, now: u64) {
        if let Some(mut o) = self.order.take() {
            match o.poll(sys, now) {
                None => self.order = Some(o),
                Some(r) => {
                    if let Some(kv) = sys.kv() {
                        for t in &o.tokens {
                            let _ = kv.delete(&format!("acme/challenge/{t}"));
                        }
                        if let Some(kid) = o.kid() {
                            let _ = kv.put("acme/kid", format!("{} {kid}", self.acme_dir).as_bytes());
                        }
                    }
                    match r {
                        Ok((cert, key)) => {
                            let unix = sys.unix_time();
                            let ok = sys.kv().is_some_and(|kv| {
                                kv.put(&format!("acme/{}/cert", o.site), cert.as_bytes()).is_ok()
                                    && kv.put(&format!("acme/{}/key", o.site), key.as_bytes()).is_ok()
                                    && kv.put(&format!("acme/{}/issued", o.site), format!("{unix}").as_bytes()).is_ok()
                            });
                            say!(sys, "sites: {}: certificate issued{}\n", o.site, if ok { "" } else { " (but not stored!)" });
                            self.acme_backoff.remove(&o.site);
                            self.applied.clear(); // reload: HTTPS with it
                        }
                        Err(e) => {
                            let b = self.acme_backoff.entry(o.site.clone()).or_insert((0, 0));
                            b.1 += 1;
                            let wait = (3_600_000u64 << (b.1 - 1).min(5)).min(86_400_000);
                            b.0 = now + wait;
                            say!(sys, "sites: {}: no certificate: {} (again in {} min)\n", o.site, e, wait / 60_000);
                        }
                    }
                }
            }
            return;
        }
        if !self.acme_on || now < self.acme_check_at {
            return;
        }
        self.acme_check_at = now + 10_000;
        let unix = sys.unix_time();
        let due = self.sites.iter().find(|st| {
            if st.manual || st.hosts.is_empty() || self.acme_backoff.get(&st.name).is_some_and(|b| now < b.0) {
                return false;
            }
            let issued = kv_str(sys, &format!("acme/{}/issued", st.name)).and_then(|v| v.parse::<u64>().ok());
            issued.is_none_or(|t| unix.saturating_sub(t) > 60 * 86_400)
        });
        let Some(st) = due.cloned() else { return };
        // the account: its key and URL kept
        let account = match kv_str(sys, "acme/account").and_then(|h| (0..32).map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>()) {
            Some(b) => p256::ecdsa::SigningKey::from_slice(&b).ok(),
            None => None,
        };
        let account = match account {
            Some(k) => k,
            None => {
                let Some(k) = acme::new_key() else { return };
                let hex: String = k.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
                if sys.kv().is_none_or(|kv| kv.put("acme/account", hex.as_bytes()).is_err()) {
                    return;
                }
                k
            }
        };
        let kid = kv_str(sys, "acme/kid").and_then(|v| v.split_once(' ').filter(|(d, _)| *d == self.acme_dir).map(|(_, k)| String::from(k)));
        say!(sys, "sites: {}: asking {} for a certificate ({})\n", st.name, self.acme_dir, st.hosts.join(", "));
        self.order = acme::Order::new(&st.name, st.hosts.clone(), &self.acme_dir, &self.acme_ca, self.acme_dns, &self.acme_email, account, kid);
    }
}

fn kv_str(sys: &mut dyn Sys, k: &str) -> Option<String> {
    sys.kv()?.get(k).and_then(|v| String::from_utf8(v).ok())
}

const PARAMS: &[Param] = &[
    Param { key: "http", kind: "number", default: "80", help: "plain HTTP port (0: off)" },
    Param { key: "https", kind: "number", default: "443", help: "HTTPS port (0: off); on once a site has a certificate" },
    Param { key: "token", kind: "secret", default: "", help: "the upload token, 16 characters at least (none: no uploads)" },
    Param { key: "site.<name>.hosts", kind: "list", default: "", help: "the names the site answers" },
    Param { key: "site.<name>.root", kind: "text", default: "<name>", help: "its files' directory" },
    Param { key: "site.<name>.proxy", kind: "text", default: "", help: "pass requests on to this backend, a.b.c.d:port" },
    Param { key: "site.<name>.cert", kind: "text", default: "", help: "its certificate and chain, PEM" },
    Param { key: "site.<name>.key", kind: "secret", default: "", help: "its private key, PEM" },
    Param { key: "site.<name>.redirect", kind: "switch", default: "on", help: "plain HTTP to HTTPS when it has a certificate" },
    Param { key: "acme", kind: "switch", default: "on", help: "certificates from an ACME CA for sites without one (HTTP-01: port 80 must reach here)" },
    Param { key: "acme.directory", kind: "text", default: "https://acme-v02.api.letsencrypt.org/directory", help: "the ACME CA" },
    Param { key: "acme.email", kind: "text", default: "", help: "the account's contact address" },
    Param { key: "acme.ca", kind: "text", default: "", help: "also trust this CA, PEM (a test CA)" },
    Param { key: "acme.dns", kind: "address", default: "1.1.1.1", help: "resolver for the CA's name" },
];

impl Module for Sites {
    fn name(&self) -> &'static str {
        "sites"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        tls::set_time(sys.unix_time());
        let mut seed = [0u8; 32];
        for c in seed.chunks_mut(8) {
            c.copy_from_slice(&sys.random().to_le_bytes());
        }
        tls::seed(seed);
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            tls::set_time(sys.unix_time());
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        self.accept(sys, now);
        if let Some(net) = sys.net() {
            self.closing.retain_mut(|(c, until)| {
                if now >= *until {
                    c.abort(net);
                    return false;
                }
                c.pump(net, 0)
            });
        }
        self.acme(sys, now);
        let clients = core::mem::take(&mut self.clients);
        for cl in clients {
            if let Some(cl) = self.step(sys, cl, now) {
                self.clients.push(cl);
            }
        }
    }

    fn status(&self) -> String {
        format!(
            "{} sites, {} connections, {} files served{}{}",
            self.sites.len(),
            self.clients.len(),
            self.served,
            if self.tls.is_some() { ", HTTPS on" } else { "" },
            self.order.as_ref().map(|o| format!(", getting a certificate for {}", o.site)).unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(clean_path("/").as_deref(), Some(""));
        assert_eq!(clean_path("/a/b.html?x=1").as_deref(), Some("a/b.html"));
        assert_eq!(clean_path("/docs/").as_deref(), Some("docs/"));
        assert_eq!(clean_path("/a%20b").as_deref(), Some("a b"));
        assert_eq!(clean_path("/a/../../etc/passwd"), None);
        assert_eq!(clean_path("/%2e%2e/x"), None);
        assert_eq!(content_type("x/latest.JSON"), "application/json");
    }
}
