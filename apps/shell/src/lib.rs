//! Console shell: network status, ping, A/B slot management.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod curl;

use alloc::string::String;
use alloc::vec::Vec;

use rustros_util::conn::Conn;
use rustros_util::netcmd;
use rustros_util::secret;
use rustros_util::wire::PROTO_ICMP;
use rustros_util::wire::{Ip, IpFmt, MacFmt, be16, checksum, parse_ip};
use rustros_api::{Admin, Caps, Kv, Module, ModuleInfo, ModuleKind, Net, RawSocket, SocketAddr, Sys, say};

/// Bytes of an HTTP response echoed to the console; the rest is only counted.
const HTTP_SHOW: usize = 1024;
const HTTP_TIMEOUT_MS: u64 = 15_000;

struct HttpGet {
    conn: Conn,
    started: u64,
    connected: bool,
    total: usize,
}

struct Ping {
    dst: Ip,
    /// our source address (0: the outgoing interface's)
    src: Ip,
    id: u16,
    /// requests sent so far, and how many to send
    sent: u32,
    count: u32,
    received: u32,
    /// between requests (0: back to back), µs
    interval_us: u64,
    /// only the summary
    quiet: bool,
    /// Ctrl-C: the summary now, without waiting for answers
    stopped: bool,
    next_at: u64,
    /// (sequence number, when sent in µs) of requests not answered yet
    sent_at: Vec<(u16, u64)>,
    /// round trips: least, most, sum (µs)
    rtt: (u64, u64, u64),
}

/// µs as milliseconds with three decimals.
fn ms3(us: u64) -> alloc::string::String {
    alloc::format!("{}.{:03}", us / 1000, us % 1000)
}

/// One line about an installed module (same format as the updater's report).
fn updater_describe(m: &ModuleInfo) -> String {
    let size = |b: Option<usize>| b.map_or(String::from("-"), |b| alloc::format!("{} KiB", b.div_ceil(1024)));
    let mut s = alloc::format!(
        "{:<12} {:<20} prefers {:<6} native {:<8} wasm {:<8} {} restarts",
        m.name,
        match m.running {
            Some(k) => alloc::format!("{} {}", k.as_str(), m.state),
            None => String::from("not running"),
        },
        m.preferred.as_str(),
        size(m.native_bytes),
        size(m.wasm_bytes),
        m.restarts
    );
    if let Some(why) = &m.native_off {
        s += &alloc::format!("\n             native switched off after a crash: {why}");
    }
    s
}

// The shell is built in and declares NET | KV | ADMIN, so it always has them.
fn net(sys: &mut dyn Sys) -> &mut dyn Net {
    sys.net().expect("shell is granted NET")
}
fn kv(sys: &mut dyn Sys) -> &mut dyn Kv {
    sys.kv().expect("shell is granted KV")
}
fn admin(sys: &mut dyn Sys) -> &mut dyn Admin {
    sys.admin().expect("shell is granted ADMIN")
}

#[derive(Default)]
pub struct Shell {
    edit: rustros_util::lineedit::LineEdit,
    ask: Option<netcmd::Ask>,
    icmp: Option<RawSocket>,
    ping: Option<Ping>,
    http: Option<HttpGet>,
    greeted: bool,
    curl: Option<curl::Curl>,
    /// asking for a secret setting: (module, key, the first entry)
    secret: Option<(String, String, Option<String>)>,
}

impl Shell {
    pub fn new() -> Shell {
        Shell::default()
    }

    fn prompt(&self, sys: &mut dyn Sys) {
        say!(sys, "rustros> ");
    }

    fn command(&mut self, sys: &mut dyn Sys, line: &str) {
        let mut args = line.split_ascii_whitespace();
        let Some(cmd) = args.next() else { return };
        match cmd {
            "help" => say!(
                sys,
                "commands:\n  ip                  all NICs: addresses and counters\n  ip [nicN] <a.b.c.d/n> [gw] | none   set an address (until reboot, see save)\n  ip [nicN] add|del <a.b.c.d>   extra addresses (NAT egress)\n  mtu [nicN] <n>      set MTU\n  cand ip|mtu ...     change the candidate only (cand: show it and the changes)\n  apply [s]           candidate in effect, then asks; reverted unless kept in s (10)\n  revert              back to what ran before (apply again at will)\n  confirm / discard   keep what apply did / drop the candidate\n  save                keep the running network settings across reboots and updates\n  arp                 show ARP cache\n  conns               show TCP connections\n  modules             list running modules\n  ping [-c n] [-i s] [-q] [-I nicN|ip] <ip>   ICMP echo (Ctrl-C stops; -i 0:\n                      back to back; -I: the interface or our address to\n                      send from, an extra one too)\n  http <ip> [port] [path]  HTTP GET (TCP connect test)\n  curl [-i] [-I] [-v] [-m s] [--interface nicN|ip] [--dns-servers ip] [http[s]://]host[:port][/path]\n                      HTTP from the command line (DNS: cfg shell dns <ip>, default 1.1.1.1)\n  kv [prefix]         list stored keys (shell's own namespace)\n  kv get|set|del <key> [value]\n  df                  storage usage\n  crash [clear]       show (or clear) the last recorded crash\n  crash panic|hang|freeze  test panic reboot / software / hardware watchdog\n  mod                 installed modules (native / wasm)\n  mod rm <name> [kind]  remove a module (or one form of it)\n  mod switch <name> native|wasm\n  cfg <module> [key [value | -]]  module settings (- removes; a password key\n                      without a value asks for it, hidden)\n  uptime\n  date                the time (UTC, from the real-time clock)\n  slot                show A/B boot slot\n  confirm             make the running kernel the default\n  log [prev|this|<boot> [lines]]  console log of a boot (40 lines)\n  reboot / poweroff\n"
            ),
            "cfg" => match (args.next(), args.next(), args.next()) {
                (Some(m), None, _) => {
                    for (k, v) in admin(sys).module_config(m) {
                        say!(sys, "{} = {}\n", k, if secret::is_secret(&k) { "(set)" } else { v.as_str() });
                    }
                }
                // a password: asked for on its own line, not shown
                (Some(m), Some(k), None) if secret::is_secret(k) => {
                    say!(sys, "{} {} (not shown, empty cancels): ", m, k);
                    self.edit.hidden = true;
                    self.secret = Some((String::from(m), String::from(k), None));
                }
                (Some(m), Some(k), None) => {
                    for (_, v) in admin(sys).module_config(m).into_iter().filter(|(x, _)| x == k) {
                        say!(sys, "{}\n", v);
                    }
                }
                (Some(m), Some(k), Some(first)) => {
                    let v = core::iter::once(first).chain(args).collect::<Vec<_>>().join(" ");
                    match admin(sys).module_config_set(m, k, Some(v.as_str()).filter(|v| *v != "-")) {
                        Ok(()) => say!(sys, "ok\n"),
                        Err(e) => say!(sys, "{}\n", e),
                    }
                }
                _ => say!(sys, "usage: cfg <module> [key [value | -]]\n"),
            },

            "arp" => {
                for (ip, mac, age) in net(sys).arp_table() {
                    say!(sys, "{:<16} {}  {}s ago\n", IpFmt(ip), MacFmt(mac), age / 1000);
                }
            }
            "conns" => {
                for c in net(sys).tcp_connections() {
                    say!(sys, ":{:<5} <- {:<21} {:<12} {}\n", c.local_port, c.remote, c.state, c.owner.unwrap_or("-"));
                }
            }
            "modules" => {
                let apps = sys.modules();
                say!(sys, "{}\n", apps.join(", "));
            }
            "ping" => {
                const USAGE: &str = "usage: ping [-c count] [-i secs] [-q] [-I nicN|a.b.c.d] a.b.c.d [count]\n";
                if self.icmp.is_none() {
                    say!(sys, "ping: no ICMP socket\n");
                    return;
                }
                let (mut dst, mut count, mut src, mut interval_us, mut quiet) = (None, 4u32, 0, 1_000_000u64, false);
                while let Some(a) = args.next() {
                    if let Some(ip) = parse_ip(a).filter(|_| dst.is_none()) {
                        dst = Some(ip);
                        continue;
                    }
                    if let Ok(c) = a.parse() {
                        count = c;
                        continue;
                    }
                    if a == "-q" {
                        quiet = true;
                        continue;
                    }
                    let Some(v) = args.next().filter(|_| matches!(a, "-c" | "-i" | "-I" | "src" | "interface" | "dev")) else {
                        say!(sys, "ping: unknown option '{}'\n{}", a, USAGE);
                        return;
                    };
                    if a == "-i" {
                        // seconds, fractions too (0: back to back)
                        let (whole, frac) = v.split_once('.').unwrap_or((v, ""));
                        let frac_us = match frac.len() {
                            0 => Some(0),
                            n if n <= 6 => frac.parse::<u64>().ok().map(|f| f * 10u64.pow(6 - n as u32)),
                            _ => None,
                        };
                        match (if whole.is_empty() { Ok(0) } else { whole.parse::<u64>() }, frac_us) {
                            (Ok(w), Some(f)) if w < 3600 => interval_us = w * 1_000_000 + f,
                            _ => {
                                say!(sys, "ping: bad interval '{}'\n", v);
                                return;
                            }
                        }
                        continue;
                    }
                    if a == "-c" {
                        match v.parse() {
                            Ok(c) => count = c,
                            Err(_) => {
                                say!(sys, "ping: bad count '{}'\n", v);
                                return;
                            }
                        }
                        continue;
                    }
                    // an interface or one of our addresses (an extra one too)
                    match curl::our_address(sys, v) {
                        Ok(ip) => src = ip,
                        Err(e) => {
                            say!(sys, "ping: {}\n", e);
                            return;
                        }
                    }
                }
                let Some(dst) = dst else {
                    say!(sys, "{}", USAGE);
                    return;
                };
                if src != 0 && sys.packet().is_none() {
                    say!(sys, "ping: no packet access for a chosen source\n");
                    return;
                }
                if src != 0 {
                    say!(sys, "PING {} from {}\n", IpFmt(dst), IpFmt(src));
                } else {
                    say!(sys, "PING {}\n", IpFmt(dst));
                }
                self.ping = Some(Ping { dst, src, id: sys.random() as u16, sent: 0, count: count.max(1), received: 0, interval_us, quiet, stopped: false, next_at: 0, sent_at: Vec::new(), rtt: (0, 0, 0) });
            }
            "date" => match sys.unix_time() {
                0 => say!(sys, "date: unknown (no real-time clock)\n"),
                t => {
                    let (days, secs) = (t / 86400, t % 86400);
                    // civil from days (H. Hinnant)
                    let z = days + 719468;
                    let (era, doe) = (z / 146097, z % 146097);
                    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                    let mp = (5 * doy + 2) / 153;
                    let d = doy - (153 * mp + 2) / 5 + 1;
                    let m = if mp < 10 { mp + 3 } else { mp - 9 };
                    let y = yoe + era * 400 + (m <= 2) as u64;
                    say!(sys, "{}-{:02}-{:02} {:02}:{:02}:{:02} UTC\n", y, m, d, secs / 3600, secs / 60 % 60, secs % 60);
                }
            },
            "curl" => {
                let rest: Vec<&str> = args.collect();
                match curl::Curl::start(sys, &rest) {
                    Ok(c) => self.curl = Some(c),
                    Err(e) => say!(sys, "{}", e),
                }
            }
            "http" => {
                let Some(ip) = args.next().and_then(parse_ip) else {
                    say!(sys, "usage: http a.b.c.d [port] [path]\n");
                    return;
                };
                let port = args.next().and_then(|p| p.parse().ok()).unwrap_or(80);
                let path = args.next().unwrap_or("/");
                match net(sys).tcp_connect(SocketAddr { ip, port }) {
                    Ok(s) => {
                        let mut conn = Conn::new(s, SocketAddr { ip, port });
                        // written before the handshake completes; sent once it does
                        conn.write(alloc::format!("GET {path} HTTP/1.0\r\nHost: {}\r\nUser-Agent: RustROS\r\n\r\n", IpFmt(ip)).as_bytes());
                        say!(sys, "connecting to {}...\n", conn.peer);
                        self.http = Some(HttpGet { conn, started: sys.now_ms(), connected: false, total: 0 });
                    }
                    Err(e) => say!(sys, "http: {:?}\n", e),
                }
            }
            "kv" => match (args.next(), args.next()) {
                (Some("get"), Some(k)) => match kv(sys).get(k) {
                    Some(v) => say!(sys, "{}\n", String::from_utf8_lossy(&v)),
                    None => say!(sys, "(not found)\n"),
                },
                (Some("set"), Some(k)) => {
                    let v: Vec<&str> = args.collect();
                    match kv(sys).put(k, v.join(" ").as_bytes()) {
                        Ok(()) => say!(sys, "ok\n"),
                        Err(e) => say!(sys, "kv: {:?}\n", e),
                    }
                }
                (Some("del"), Some(k)) => match kv(sys).delete(k) {
                    Ok(true) => say!(sys, "deleted\n"),
                    Ok(false) => say!(sys, "(not found)\n"),
                    Err(e) => say!(sys, "kv: {:?}\n", e),
                },
                (prefix, None) if !matches!(prefix, Some("get" | "set" | "del")) => {
                    for k in kv(sys).keys(prefix.unwrap_or("")) {
                        let len = kv(sys).get(&k).map_or(0, |v| v.len());
                        say!(sys, "{:<40} {} bytes\n", k, len);
                    }
                }
                _ => say!(sys, "usage: kv [prefix] | kv get <key> | kv set <key> <value> | kv del <key>\n"),
            },
            "df" => match kv(sys).storage_info() {
                Some(i) => say!(
                    sys,
                    "data partition {} MiB, key-value store {} MiB\nlive data {} bytes, log {} KiB of {} KiB\n",
                    i.partition_bytes >> 20,
                    i.store_bytes >> 20,
                    i.live_bytes,
                    i.log_bytes >> 10,
                    i.store_bytes / 2 >> 10
                ),
                None => say!(sys, "no storage (no boot disk or no free space on it)\n"),
            },
            "crash" => match args.next() {
                None => match sys.last_crash() {
                    Some(c) => say!(sys, "{}\n", c),
                    None => say!(sys, "no crash recorded\n"),
                },
                Some("clear") => {
                    let ok = admin(sys).clear_crash();
                    say!(sys, "{}\n", if ok { "cleared" } else { "failed" });
                }
                Some("panic") => panic!("test panic requested on the console"),
                Some("hang") => {
                    say!(sys, "looping forever; the software watchdog should reboot\n");
                    #[allow(clippy::empty_loop)]
                    loop {}
                }
                Some("freeze") => admin(sys).debug_freeze(),
                Some(_) => say!(sys, "usage: crash [clear|panic|hang|freeze]\n"),
            },
            "mod" => match (args.next(), args.next(), args.next()) {
                (None, _, _) => {
                    let list = admin(sys).module_list();
                    if list.is_empty() {
                        say!(sys, "no modules installed (rustros-update.py module-install)\n");
                    }
                    for m in list {
                        let line = updater_describe(&m);
                        say!(sys, "{}\n", line);
                    }
                }
                (Some("rm"), Some(name), kind) => match kind.map(ModuleKind::parse) {
                    Some(None) => say!(sys, "kind must be native or wasm\n"),
                    kind => {
                        let ok = admin(sys).module_remove(name, kind.flatten());
                        say!(sys, "{}\n", if ok { "removed" } else { "no such module" });
                    }
                },
                (Some("switch"), Some(name), Some(kind)) => match ModuleKind::parse(kind) {
                    Some(kind) => match admin(sys).module_switch(name, kind) {
                        Ok(()) => say!(sys, "switching {} to {}\n", name, kind.as_str()),
                        Err(e) => say!(sys, "{}\n", e),
                    },
                    None => say!(sys, "kind must be native or wasm\n"),
                },
                _ => say!(sys, "usage: mod | mod rm <name> [native|wasm] | mod switch <name> native|wasm\n"),
            },
            "uptime" => {
                let s = sys.now_ms() / 1000;
                say!(sys, "up {}d {:02}:{:02}:{:02}\n", s / 86400, s / 3600 % 24, s / 60 % 60, s % 60);
            }
            "slot" => match sys.update_info() {
                Some(i) => say!(
                    sys,
                    "running slot {}{}, max image {} KiB\n",
                    i.slot,
                    if i.trial { " (trial boot, not confirmed)" } else { "" },
                    i.max_bytes / 1024
                ),
                None => say!(sys, "online update not available\n"),
            },
            "confirm" => {
                // keeps what runs: a network apply waiting for confirmation, and the kernel
                if admin(sys).net_confirm() {
                    say!(sys, "network change confirmed (save keeps it across reboots)\n");
                }
                let ok = admin(sys).confirm_boot();
                say!(sys, "{}\n", if ok { "confirmed" } else { "failed" });
            }
            "log" => {
            let words: Vec<&str> = args.collect();
            let out = rustros_util::logcmd::run(sys, &words, 40).unwrap_or_else(|e| e);
            sys.print(&out);
        }
        "reboot" => admin(sys).reboot(),
            "poweroff" | "shutdown" => admin(sys).poweroff(),
            _ => say!(sys, "unknown command '{}', try help\n", cmd),
        }
    }

    fn http_poll(&mut self, sys: &mut dyn Sys) {
        let Some(h) = self.http.as_mut() else { return };
        let now = sys.now_ms();
        if !h.connected && net(sys).tcp_is_connected(h.conn.stream) == Ok(true) {
            h.connected = true;
            say!(sys, "connected in {} ms\n", now - h.started);
        }
        let alive = h.conn.pump(net(sys), 64 * 1024);
        if !h.conn.inbuf.is_empty() {
            let data = core::mem::take(&mut h.conn.inbuf);
            if h.total < HTTP_SHOW {
                let show = &data[..data.len().min(HTTP_SHOW - h.total)];
                say!(sys, "{}", String::from_utf8_lossy(show));
            }
            h.total += data.len();
        }
        let done = !alive || h.conn.eof;
        let timed_out = now - h.started > HTTP_TIMEOUT_MS;
        if done || timed_out {
            if timed_out && !done {
                h.conn.abort(net(sys));
            } else if alive {
                h.conn.close();
                h.conn.pump(net(sys), 0);
            }
            let why = if h.total > 0 || h.conn.eof {
                "closed"
            } else if timed_out {
                "timed out"
            } else {
                "refused or reset"
            };
            say!(sys, "\n--- {} bytes from {} in {} ms ({})\n", h.total, h.conn.peer, now - h.started, why);
            self.http = None;
            self.prompt(sys);
        }
    }

    fn ping_poll(&mut self, sys: &mut dyn Sys) {
        let Some(sock) = self.icmp else { return };
        // replies
        let mut buf = [0u8; 1500];
        while let Ok((n, src, ttl)) = net(sys).raw_recv(sock, &mut buf) {
            let m = &buf[..n];
            let Some(p) = self.ping.as_mut() else { continue };
            if m.len() < 8 || m[0] != 0 || src != p.dst || be16(m, 4) != p.id {
                continue;
            }
            let seq = be16(m, 6);
            if let Some(i) = p.sent_at.iter().position(|e| e.0 == seq) {
                let (_, t) = p.sent_at.swap_remove(i);
                p.received += 1;
                let us = sys.now_us().saturating_sub(t);
                p.rtt = (if p.received == 1 { us } else { p.rtt.0.min(us) }, p.rtt.1.max(us), p.rtt.2 + us);
                if !p.quiet {
                    say!(sys, "{} bytes from {}: icmp_seq={} ttl={} time={} ms\n", n, IpFmt(src), seq, ttl, ms3(us));
                }
            }
        }
        // requests
        let now = sys.now_us();
        let Some(p) = self.ping.as_mut() else { return };
        if now < p.next_at && !p.stopped {
            return;
        }
        // after the last one: wait for the answers (a second at most)
        if p.sent >= p.count {
            if !p.stopped && p.received < p.sent && now < p.next_at + 1_000_000 - p.interval_us.min(1_000_000) {
                return;
            }
            let mut sum = alloc::format!(
                "--- {}: {} sent, {} received, {}% loss",
                IpFmt(p.dst),
                p.sent,
                p.received,
                (p.sent - p.received) as u64 * 100 / p.sent.max(1) as u64
            );
            if p.received > 0 {
                sum += &alloc::format!(", rtt min/avg/max {}/{}/{} ms", ms3(p.rtt.0), ms3(p.rtt.2 / p.received as u64), ms3(p.rtt.1));
            }
            say!(sys, "{}\n", sum);
            self.ping = None;
            self.prompt(sys);
            return;
        }
        p.sent += 1;
        let seq = p.sent as u16;
        // forget requests that will not be answered any more
        p.sent_at.retain(|e| now - e.1 < 10_000_000);
        let mut m = Vec::with_capacity(64);
        m.extend_from_slice(&[8, 0, 0, 0]);
        m.extend_from_slice(&p.id.to_be_bytes());
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend((0..56u8).map(|i| i.wrapping_add(0x20)));
        let c = checksum(&m, 0);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        p.sent_at.push((seq, now));
        p.next_at = now + p.interval_us;
        let (dst, src) = (p.dst, p.src);
        if src != 0 {
            // a whole IP packet from the chosen address, routed by it
            let mut ip = alloc::vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_ICMP, 0, 0];
            ip[2..4].copy_from_slice(&((20 + m.len()) as u16).to_be_bytes());
            ip[4..6].copy_from_slice(&seq.to_be_bytes());
            ip.extend_from_slice(&src.to_be_bytes());
            ip.extend_from_slice(&dst.to_be_bytes());
            let c = checksum(&ip, 0);
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&m);
            if !sys.packet().is_some_and(|pk| pk.send_packet(&ip)) {
                say!(sys, "ping: no route from {}\n", IpFmt(src));
            }
        } else if let Err(e) = net(sys).raw_send(sock, dst, &m) {
            say!(sys, "ping: {:?}\n", e);
        }
    }
}

impl Module for Shell {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn caps(&self) -> Caps {
        // PACKET: pings from a chosen source address
        Caps::NET | Caps::KV | Caps::ADMIN | Caps::CONSOLE | Caps::PACKET
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.icmp = net(sys).raw_open(PROTO_ICMP).ok();
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        if self.ask.is_some() {
            netcmd::console_tick(sys, &mut self.ask);
            if self.ask.is_none() {
                self.prompt(sys);
            }
        }
        if !self.greeted {
            // after every app has printed its startup messages
            self.greeted = true;
            say!(sys, "\ntype 'help' for commands\n");
            if sys.update_info().is_some_and(|u| u.trial) {
                say!(sys, "*** trial boot: run 'confirm' (or rustros-update.py confirm) to keep this kernel\n");
            }
            self.prompt(sys);
        }
        self.ping_poll(sys);
        self.http_poll(sys);
        if self.curl.as_mut().is_some_and(|c| c.poll(sys)) {
            self.curl = None;
            self.prompt(sys);
        }
    }

    fn key(&mut self, sys: &mut dyn Sys, c: u8) {
        match c {
            3 if self.secret.is_some() => {
                self.secret = None;
                self.edit.hidden = false;
                say!(sys, "^C");
                let _ = self.edit.key(sys, b'\n', "", &|_, _| Vec::new()); // drop what was typed
                self.prompt(sys);
            }
            3 => {
                // a ping ends with its summary, as on Linux
                if let Some(p) = self.ping.as_mut() {
                    p.count = p.sent.max(1);
                    p.stopped = true;
                    say!(sys, "^C\n");
                    return;
                }
                let http = self.http.take().map(|mut h| h.conn.abort(net(sys))).is_some();
                let curl = self.curl.take().map(|mut c| c.abort(sys)).is_some();
                if http | curl {
                    say!(sys, "^C\n");
                    self.prompt(sys);
                }
            }
            _ => {
                const COMMANDS: &[&str] = &[
                    "help", "ip", "mtu", "cand", "apply", "revert", "confirm", "discard", "save", "arp", "conns", "modules", "ping", "http", "curl", "date", "kv", "df", "crash",
                    "mod", "cfg", "uptime", "slot", "log", "reboot", "poweroff",
                ];
                if let Some(line) = self.edit.key(sys, c, "rustros> ", &|s, w| netcmd::complete(s, w, COMMANDS)) {
                    if let Some((m, k, first)) = self.secret.take() {
                        match first {
                            _ if line.is_empty() => say!(sys, "cancelled\n"),
                            None => {
                                say!(sys, "again: ");
                                self.edit.hidden = true;
                                self.secret = Some((m, k, Some(line)));
                                return;
                            }
                            Some(f) if f != line => say!(sys, "the two entries differ, nothing changed\n"),
                            Some(_) => match admin(sys).module_config_set(&m, &k, Some(line.as_str())) {
                                Ok(()) => say!(sys, "ok\n"),
                                Err(e) => say!(sys, "{}\n", e),
                            },
                        }
                        self.prompt(sys);
                        return;
                    }
                    if !netcmd::console_line(sys, &mut self.ask, &line) {
                        self.command(sys, &line);
                    }
                    if self.ping.is_none() && self.http.is_none() && self.curl.is_none() && self.ask.is_none() && self.secret.is_none() {
                        self.prompt(sys);
                    }
                }
            }
        }
    }
}
