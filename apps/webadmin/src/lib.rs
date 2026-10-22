//! Web management: status, network configuration (candidate / apply with
//! automatic revert / save, as on the console), module settings, logs,
//! reboot and power off, from a browser.
//!
//! Plain HTTP for now, so it only answers the inside: clients from the
//! `allow` networks (default: the networks of interfaces without a gateway,
//! i.e. not a WAN). The password never crosses the wire: the browser proves
//! it with an HMAC over a one-time challenge; the session cookie is
//! HttpOnly and SameSite=Strict, and changes need a custom header (no
//! cross-site requests).
//!
//! Settings (console `cfg webadmin <key> <value>`, or `rustros-update.py HOST
//! module-config webadmin <key> <value>`):
//!
//! ```text
//! password   <text>             set the password (stored hashed, then removed)
//! port       8080               listening port
//! allow      nic2.2240,10.9.0.0/16,...   who may connect (interfaces or networks)
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

use rustros_api::{Caps, Module, ModuleKind, Param, Sys, TcpListener, say};
use rustros_util::conn::Conn;
use rustros_util::sha256::{Hmac, Sha256, ct_eq};
use rustros_util::wire::{Ip, IpFmt, fmt_ip_list, parse_cidr, parse_ip};

const DEFAULT_PORT: u16 = 8080;
const MAX_HEAD: usize = 8192;
const MAX_BODY: usize = 16 * 1024;
const RELOAD_MS: u64 = 2000;
const SESSION_MS: u64 = 30 * 60 * 1000;
const CHALLENGE_MS: u64 = 60_000;
const MAX_SESSIONS: usize = 16;
const MAX_CHALLENGES: usize = 32;
/// Failed logins before logins pause, and for how long.
const MAX_FAILS: u32 = 5;
const LOCKOUT_MS: u64 = 60_000;
const LOG_TAIL: usize = 128 * 1024;
/// The password hash is HMAC'ed with this domain (the browser does the same).
const PW_SALT: &str = "rustros-web:";

const PAGE: &str = include_str!("page.html");

#[derive(Default)]
pub struct WebAdmin {
    listener: Option<(TcpListener, u16)>,
    conns: Vec<Conn>,
    /// SHA-256 of PW_SALT + password (None: no password set, no logins)
    pw: Option<[u8; 32]>,
    allow: Vec<(Ip, Ip)>,
    /// what `allow` was built from, to report changes once
    allow_text: Option<String>,
    sessions: Vec<([u8; 16], u64)>,
    challenges: Vec<([u8; 16], u64)>,
    fails: u32,
    locked_until: u64,
    reload_at: u64,
    /// (when, power off)
    shutdown_at: Option<(u64, bool)>,
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    cookie: Option<&'a str>,
    custom: bool,
    body: &'a [u8],
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    let s = s.as_bytes();
    if s.len() != 32 {
        return None;
    }
    let mut o = [0u8; 16];
    for (i, c) in s.chunks(2).enumerate() {
        o[i] = u8::from_str_radix(core::str::from_utf8(c).ok()?, 16).ok()?;
    }
    Some(o)
}

/// A JSON string literal.
fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Percent-decoding of a form field.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => o.push(b' '),
            b'%' if i + 2 < b.len() => {
                match core::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        o.push(v);
                        i += 2;
                    }
                    None => o.push(b'%'),
                }
            }
            c => o.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

/// Field `k` of a form body or query string.
fn field(form: &str, k: &str) -> Option<String> {
    form.split('&').find_map(|kv| {
        let (a, b) = kv.split_once('=').unwrap_or((kv, ""));
        (a == k).then(|| url_decode(b))
    })
}

fn response(status: &str, ctype: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn json(body: &str) -> Vec<u8> {
    response("200 OK", "application/json; charset=utf-8", "", body.as_bytes())
}

fn error(status: &str, msg: &str) -> Vec<u8> {
    response(status, "application/json; charset=utf-8", "", format!("{{\"error\":{}}}", js(msg)).as_bytes())
}

/// Parse a complete request out of `buf`: None while incomplete, Err if bad.
fn parse(buf: &[u8]) -> Option<Result<Request<'_>, &'static str>> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let Ok(head) = core::str::from_utf8(&buf[..end]) else { return Some(Err("bad header")) };
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut len = 0usize;
    let (mut cookie, mut custom) = (None, false);
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.parse().unwrap_or(usize::MAX),
            "cookie" => cookie = v.split(';').map(str::trim).find_map(|c| c.strip_prefix("hs=")),
            "x-rustros" => custom = true,
            _ => {}
        }
    }
    if len > MAX_BODY {
        return Some(Err("body too large"));
    }
    let body = buf.get(end + 4..end + 4 + len)?;
    Some(Ok(Request { method, path, query, cookie, custom, body }))
}

impl WebAdmin {
    pub fn new() -> WebAdmin {
        WebAdmin::default()
    }

    fn reload(&mut self, sys: &mut dyn Sys) {
        let get = |sys: &mut dyn Sys, k: &str| sys.kv().and_then(|kv| kv.get(&format!("cfg/{k}"))).map(|v| String::from_utf8_lossy(&v).trim().to_string());
        // a new password: keep only its hash
        if let Some(pw) = get(sys, "password") {
            let mut h = Sha256::new();
            h.update(PW_SALT.as_bytes());
            h.update(pw.as_bytes());
            let hash = hex(&h.finish());
            if let Some(kv) = sys.kv() {
                let _ = kv.put("cfg/pwhash", hash.as_bytes());
                let _ = kv.delete("cfg/password");
            }
            self.sessions.clear();
            say!(sys, "webadmin: password set\n");
        }
        self.pw = get(sys, "pwhash").and_then(|h| {
            let b = h.as_bytes();
            (b.len() == 64).then(|| {
                let mut o = [0u8; 32];
                for i in 0..32 {
                    o[i] = u8::from_str_radix(core::str::from_utf8(&b[i * 2..i * 2 + 2]).unwrap_or("0"), 16).unwrap_or(0);
                }
                o
            })
        });
        // who may connect
        let spec = get(sys, "allow").unwrap_or_default();
        let mut allow = Vec::new();
        let mut bad = Vec::new();
        if let Some(net) = sys.net() {
            let ifs: Vec<(String, Ip, Ip, Ip)> = (0..net.nic_count()).filter_map(|i| net.nic_info(i).map(|n| (net.nic_name(i), n.ip, n.mask, n.gw))).collect();
            if spec.is_empty() {
                allow.extend(ifs.iter().filter(|f| f.1 != 0 && f.3 == 0).map(|f| (f.1 & f.2, f.2)));
            }
            for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Some(f) = ifs.iter().find(|f| f.0 == item) {
                    if f.1 != 0 {
                        allow.push((f.1 & f.2, f.2));
                    }
                } else if let Some((n, m)) = parse_cidr(item) {
                    allow.push((n & m, m));
                } else if let Some(a) = parse_ip(item) {
                    allow.push((a, !0));
                } else {
                    bad.push(item);
                }
            }
        }
        let text: String = allow.iter().map(|(n, m)| format!("{}/{} ", IpFmt(*n), m.count_ones())).collect();
        if self.allow_text.as_ref() != Some(&text) {
            say!(sys, "webadmin: open to {}\n", if text.is_empty() { "nobody (set allow, or give a LAN interface an address)" } else { text.trim_end() });
            for b in bad {
                say!(sys, "webadmin: allow: no interface or network '{}'\n", b);
            }
            self.allow_text = Some(text);
        }
        self.allow = allow;
        // the port
        let port = get(sys, "port").and_then(|p| p.parse().ok()).filter(|&p| p != 0).unwrap_or(DEFAULT_PORT);
        if self.listener.is_none_or(|(_, p)| p != port) {
            let Some(net) = sys.net() else { return };
            if let Some((l, _)) = self.listener.take() {
                net.tcp_unlisten(l);
            }
            match net.tcp_listen(port) {
                Ok(l) => {
                    self.listener = Some((l, port));
                    say!(sys, "webadmin: http on port {}{}\n", port, if self.pw.is_none() { " (no password yet: cfg webadmin password <text>)" } else { "" });
                }
                Err(e) => say!(sys, "webadmin: cannot listen on {}: {:?}\n", port, e),
            }
        }
    }

    fn allowed(&self, ip: Ip) -> bool {
        self.allow.iter().any(|&(n, m)| ip & m == n)
    }

    fn token(sys: &mut dyn Sys) -> [u8; 16] {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&sys.random().to_le_bytes());
        t[8..].copy_from_slice(&sys.random().to_le_bytes());
        t
    }

    fn session(&mut self, now: u64, cookie: Option<&str>) -> bool {
        self.sessions.retain(|s| s.1 > now);
        let Some(t) = cookie.and_then(unhex16) else { return false };
        match self.sessions.iter_mut().find(|s| ct_eq(&s.0, &t)) {
            Some(s) => {
                s.1 = now + SESSION_MS;
                true
            }
            None => false,
        }
    }

    fn handle(&mut self, sys: &mut dyn Sys, r: &Request) -> Vec<u8> {
        let now = sys.now_ms();
        match (r.method, r.path) {
            ("GET", "/") => return response("200 OK", "text/html; charset=utf-8", "", PAGE.as_bytes()),
            ("GET", "/api/challenge") => {
                self.challenges.retain(|c| c.1 > now);
                if self.challenges.len() >= MAX_CHALLENGES {
                    self.challenges.remove(0);
                }
                let n = Self::token(sys);
                self.challenges.push((n, now + CHALLENGE_MS));
                return json(&format!("{{\"nonce\":\"{}\",\"password\":{}}}", hex(&n), self.pw.is_some()));
            }
            ("POST", "/api/login") => return self.login(sys, now, r),
            _ => {}
        }
        if !r.custom && r.method == "POST" {
            return error("403 Forbidden", "missing X-RustROS header");
        }
        if !self.session(now, r.cookie) {
            return error("401 Unauthorized", "login required");
        }
        let form = core::str::from_utf8(r.body).unwrap_or("");
        match (r.method, r.path) {
            ("POST", "/api/logout") => {
                if let Some(t) = r.cookie.and_then(unhex16) {
                    self.sessions.retain(|s| !ct_eq(&s.0, &t));
                }
                response("200 OK", "application/json", "Set-Cookie: hs=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict\r\n", b"{}")
            }
            ("GET", "/api/status") => json(&status(sys)),
            ("GET", "/api/net") => json(&net_state(sys)),
            ("POST", "/api/net") => {
                let cmd = field(form, "cmd").unwrap_or_default();
                let words: Vec<&str> = cmd.split_whitespace().collect();
                // the running configuration only changes through a candidate
                // (apply reverts by itself unless confirmed)
                let direct = matches!(words.as_slice(), ["ip" | "mtu", _, ..]);
                let out = if direct {
                    Err(String::from("edit the candidate: cand ip ... / cand mtu ..., then apply\n"))
                } else {
                    rustros_util::netcmd::run(sys, &words)
                };
                say!(sys, "webadmin: net {}\n", cmd);
                let (ok, text) = match out {
                    Ok(t) => (true, t),
                    Err(t) => (false, t),
                };
                json(&format!("{{\"ok\":{ok},\"out\":{}}}", js(&text)))
            }
            ("GET", "/api/modules") => json(&modules(sys)),
            ("POST", "/api/module") => {
                let (Some(name), Some(action)) = (field(form, "name"), field(form, "action")) else { return error("400 Bad Request", "name and action") };
                let Some(a) = sys.admin() else { return error("403 Forbidden", "no admin") };
                let res = match action.as_str() {
                    "set" | "del" => {
                        let key = field(form, "key").unwrap_or_default();
                        let value = field(form, "value");
                        if key.is_empty() || key.contains('/') {
                            Err(String::from("bad key"))
                        } else {
                            a.module_config_set(&name, &key, if action == "set" { value.as_deref() } else { None })
                        }
                    }
                    "native" => a.module_switch(&name, ModuleKind::Native),
                    "wasm" => a.module_switch(&name, ModuleKind::Wasm),
                    _ => Err(String::from("unknown action")),
                };
                say!(sys, "webadmin: module {} {} {}\n", name, action, if res.is_ok() { "done" } else { "failed" });
                match res {
                    Ok(()) => json("{\"ok\":true}"),
                    Err(e) => json(&format!("{{\"ok\":false,\"out\":{}}}", js(&e))),
                }
            }
            ("GET", "/api/logs") => {
                let Some(a) = sys.admin() else { return error("403 Forbidden", "no admin") };
                let this = a.log_this_boot();
                let list: Vec<String> = a.log_list().iter().map(|(b, n)| format!("[{b},{n}]")).collect();
                json(&format!("{{\"this\":{},\"boots\":[{}]}}", this.map_or(String::from("null"), |b| b.to_string()), list.join(",")))
            }
            ("GET", "/api/log") => {
                let Some(a) = sys.admin() else { return error("403 Forbidden", "no admin") };
                let boot = field(r.query, "boot").and_then(|b| b.parse().ok()).or(a.log_this_boot());
                let Some(text) = boot.and_then(|b| a.log_read(b)) else { return error("404 Not Found", "no such log") };
                let tail = &text[text.len().saturating_sub(LOG_TAIL)..];
                response("200 OK", "text/plain; charset=utf-8", "", tail)
            }
            ("POST", "/api/system") => {
                let action = field(form, "action").unwrap_or_default();
                let Some(a) = sys.admin() else { return error("403 Forbidden", "no admin") };
                let msg = match action.as_str() {
                    "reboot" | "poweroff" => {
                        self.shutdown_at = Some((now + 1000, action == "poweroff"));
                        say!(sys, "webadmin: {} requested\n", action);
                        "on its way"
                    }
                    "perf_reset" => {
                        a.perf_reset();
                        "peaks reset"
                    }
                    "clear_crash" => {
                        a.clear_crash();
                        "crash record cleared"
                    }
                    _ => return error("400 Bad Request", "unknown action"),
                };
                json(&format!("{{\"ok\":true,\"out\":{}}}", js(msg)))
            }
            _ => error("404 Not Found", "no such page"),
        }
    }

    fn login(&mut self, sys: &mut dyn Sys, now: u64, r: &Request) -> Vec<u8> {
        if !r.custom {
            return error("403 Forbidden", "missing X-RustROS header");
        }
        if now < self.locked_until {
            return error("429 Too Many Requests", "too many failed logins: wait a minute");
        }
        let Some(pw) = self.pw else { return error("403 Forbidden", "no password set: cfg webadmin password <text>") };
        let form = core::str::from_utf8(r.body).unwrap_or("");
        let nonce = field(form, "nonce").and_then(|n| unhex16(&n));
        let proof = field(form, "proof").unwrap_or_default();
        self.challenges.retain(|c| c.1 > now);
        // each challenge works once
        let fresh = nonce.and_then(|n| self.challenges.iter().position(|c| c.0 == n)).map(|i| self.challenges.swap_remove(i));
        let ok = fresh.is_some_and(|(n, _)| {
            let mut h = Hmac::new(&pw);
            h.update(hex(&n).as_bytes());
            ct_eq(hex(&h.finish()).as_bytes(), proof.as_bytes())
        });
        if !ok {
            self.fails += 1;
            if self.fails >= MAX_FAILS {
                self.fails = 0;
                self.locked_until = now + LOCKOUT_MS;
                say!(sys, "webadmin: failed logins, pausing logins for a minute\n");
            }
            return error("403 Forbidden", "wrong password");
        }
        self.fails = 0;
        self.sessions.retain(|s| s.1 > now);
        if self.sessions.len() >= MAX_SESSIONS {
            self.sessions.remove(0);
        }
        let t = Self::token(sys);
        self.sessions.push((t, now + SESSION_MS));
        say!(sys, "webadmin: login\n");
        response("200 OK", "application/json", &format!("Set-Cookie: hs={}; Path=/; HttpOnly; SameSite=Strict\r\n", hex(&t)), b"{\"ok\":true}")
    }
}

fn status(sys: &mut dyn Sys) -> String {
    let mut o = format!("{{\"uptime\":{}", sys.now_ms() / 1000);
    if let Some(u) = sys.update_info() {
        let _ = write!(o, ",\"slot\":{},\"trial\":{},\"safe\":{},\"unstable\":{}", js(&u.slot.to_string()), u.trial, u.safe_mode, u.unstable_boots);
    }
    o += ",\"ifaces\":[";
    if let Some(net) = sys.net() {
        for i in 0..net.nic_count() {
            let Some(n) = net.nic_info(i) else { continue };
            let extra = net.extra_addrs(i);
            let _ = write!(
                o,
                "{}{{\"name\":{},\"ip\":\"{}/{}\",\"gw\":\"{}\",\"mtu\":{},\"extra\":{},\"rx\":{},\"tx\":{},\"rxd\":{},\"txd\":{}}}",
                if i > 0 { "," } else { "" },
                js(&net.nic_name(i)),
                IpFmt(n.ip),
                n.mask.count_ones(),
                IpFmt(n.gw),
                n.mtu,
                js(&fmt_ip_list(&extra)),
                n.rx,
                n.tx,
                n.rx_dropped,
                n.tx_dropped
            );
        }
    }
    o += "]";
    let perf = sys.admin().map(|a| a.perf_report()).unwrap_or_default();
    let _ = write!(o, ",\"perf\":{}", js(&perf));
    let running: Vec<String> = sys.modules().iter().map(|m| js(m)).collect();
    let _ = write!(o, ",\"running\":[{}]", running.join(","));
    let storage = sys.kv().and_then(|k| k.storage_info()).map_or(String::from("none"), |s| format!("{} MiB partition, {} bytes live", s.partition_bytes >> 20, s.live_bytes));
    let _ = write!(o, ",\"storage\":{},\"crash\":{}}}", js(&storage), js(&sys.last_crash().unwrap_or_default()));
    o
}

fn net_state(sys: &mut dyn Sys) -> String {
    let show = rustros_util::netcmd::show_text(sys);
    let cand = rustros_util::netcmd::run(sys, &["cand"]).unwrap_or_else(|e| e);
    let Some(a) = sys.admin() else { return String::from("{}") };
    let has_cand = a.net_candidate().is_some();
    format!(
        "{{\"show\":{},\"cand\":{},\"has_cand\":{},\"applied\":{},\"pending\":{}}}",
        js(&show),
        js(&cand),
        has_cand,
        a.net_applied(),
        a.net_pending().map_or(String::from("null"), |s| s.to_string())
    )
}

/// Whether setting `key` is one `pattern` describes (`Param`): `<x>` is one
/// dotted part (all the rest at the end), `[<i>.]` an optional one.
fn key_matches(pattern: &str, key: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("[<i>.]") {
        return key_matches(rest, key) || key.split_once('.').is_some_and(|(_, k)| key_matches(rest, k));
    }
    match pattern.find('<') {
        None => pattern == key,
        Some(i) => {
            let Some(k) = key.strip_prefix(&pattern[..i]) else { return false };
            let Some(end) = pattern[i..].find('>') else { return false };
            let rest = &pattern[i + end + 1..];
            if rest.is_empty() {
                return !k.is_empty();
            }
            match k.find('.') {
                Some(d) if d > 0 => key_matches(rest, &k[d..]),
                _ => false,
            }
        }
    }
}

fn modules(sys: &mut dyn Sys) -> String {
    let builtin: Vec<String> = sys.modules().iter().map(|m| js(m)).collect();
    let Some(a) = sys.admin() else { return String::from("{}") };
    let mut o = format!("{{\"running\":[{}],\"modules\":[", builtin.join(","));
    for (i, m) in a.module_list().iter().enumerate() {
        let secret = |k: &str| rustros_util::secret::is_secret(k) || m.params.iter().any(|p| p.kind == "secret" && key_matches(&p.key, k));
        let cfg: Vec<String> = a
            .module_config(&m.name)
            .iter()
            .map(|(k, v)| {
                // passwords (and the password hash) are nobody's business
                let v = if secret(k) { "(set)" } else { v.as_str() };
                format!("[{},{}]", js(k), js(v))
            })
            .collect();
        let params: Vec<String> = m.params.iter().map(|p| format!("[{},{},{},{}]", js(&p.key), js(&p.kind), js(&p.default), js(&p.help))).collect();
        let _ = write!(
            o,
            "{}{{\"name\":{},\"running\":{},\"state\":{},\"preferred\":{},\"native\":{},\"wasm\":{},\"restarts\":{},\"off\":{},\"config\":[{}],\"params\":[{}]}}",
            if i > 0 { "," } else { "" },
            js(&m.name),
            m.running.map_or(String::from("null"), |k| js(k.as_str())),
            js(&m.state),
            js(m.preferred.as_str()),
            m.native_bytes.map_or(String::from("null"), |b| b.to_string()),
            m.wasm_bytes.map_or(String::from("null"), |b| b.to_string()),
            m.restarts,
            m.native_off.as_deref().map_or(String::from("null"), js),
            cfg.join(","),
            params.join(",")
        );
    }
    o += "]}";
    o
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "password", kind: "secret", default: "", help: "the login password (stored hashed)" },
    Param { key: "port", kind: "number", default: "8080", help: "listening port" },
    Param { key: "allow", kind: "list", default: "networks of interfaces without a gateway", help: "who may connect: interfaces or networks" },
];

impl Module for WebAdmin {
    fn name(&self) -> &'static str {
        "webadmin"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::ADMIN
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.reload(sys);
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if let Some((t, off)) = self.shutdown_at {
            if now >= t {
                if let Some(a) = sys.admin() {
                    if off {
                        a.poweroff();
                    }
                    a.reboot();
                }
            }
        }
        if now >= self.reload_at {
            self.reload(sys);
            self.reload_at = now + RELOAD_MS;
        }
        if let (Some((l, _)), Some(net)) = (self.listener, sys.net()) {
            while let Ok((s, peer)) = net.tcp_accept(l) {
                if self.allowed(peer.ip) && self.conns.len() < 32 {
                    self.conns.push(Conn::new(s, peer));
                } else {
                    net.tcp_abort(s);
                }
            }
        }
        let mut conns = core::mem::take(&mut self.conns);
        conns.retain_mut(|c| {
            let Some(net) = sys.net() else { return false };
            if !c.pump(net, MAX_HEAD + MAX_BODY) {
                return false;
            }
            if c.queued() > 0 {
                return true; // the answer is on its way
            }
            let reply = match parse(&c.inbuf) {
                None if c.eof || c.inbuf.len() >= MAX_HEAD + MAX_BODY => Some(error("400 Bad Request", "bad request")),
                None => None,
                Some(Err(e)) => Some(error("400 Bad Request", e)),
                Some(Ok(r)) => Some(self.handle(sys, &r)),
            };
            if let Some(reply) = reply {
                c.write(&reply);
                c.inbuf.clear();
                c.close();
                if let Some(net) = sys.net() {
                    c.pump(net, 0);
                }
            }
            true
        });
        self.conns = conns;
    }

    fn status(&self) -> String {
        format!("{} sessions{}", self.sessions.len(), if self.pw.is_none() { ", no password set" } else { "" })
    }
}
