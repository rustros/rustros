//! Online kernel update service (TCP port 9000).
//!
//! ```text
//! server -> "RRS1" nonce[16] slot('a'|'b') trial(0|1)
//! client -> cmd(1) len(u32 BE) hdr_mac[32]       hdr_mac  = HMAC(key, nonce | "H" | cmd | len)
//!           payload[len] mac[32]                 mac      = HMAC(key, nonce | cmd | len | payload)
//! server -> "OK\n" | "ERR <reason>\n"
//! ```
//! cmd: 'U' upload kernel image, 'C' confirm the running (trial) kernel,
//! 'R' reboot, 'P' power off, 'I' status report (text, then the connection closes),
//! 'W' install a module, native or WebAssembly (payload: name_len u8, name,
//! image), 'X' remove a module (payload: "name" or "name native|wasm"),
//! 'S' switch a module's form (payload: "name native|wasm"),
//! 'K' set a module setting (payload: "name\nkey\nvalue"; no value: remove),
//! 'Q' list a module's settings (payload: "name"; secret values masked),
//! 'E' encrypted command: payload = inner cmd byte + inner payload, XORed
//! with HMAC(key, nonce | "E" | counter) blocks; the MAC covers the
//! ciphertext (encrypt-then-MAC). Inner commands: K, Q, X, S.
//! 'L' console logs kept on disk (payload: "" lists the boots, "prev",
//! "this" or a boot number, optionally followed by a number of lines),
//! 'N' network commands as on the console (payload: "ip ...", "cand ip ...",
//! "apply 5", "confirm", "save", ...; see rustros_util::netcmd). "boot" lists the settings stored
//! for the next boot, "boot <key> <value | ->" changes one of them without
//! touching the running network.
//! The header MAC is checked before anything touches the disk;
//! the image only becomes bootable after the final MAC matches.
//!
//! The key is `key=` on the kernel command line; without it the service is off.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use rustros_util::conn::Conn;
use rustros_util::netcmd;
use rustros_util::sha256::{Hmac, ct_eq};
use rustros_util::wire::{IpFmt, cmdline_get};
use rustros_api::{Caps, Module, ModuleInfo, ModuleKind, Sys, TcpListener, say};

const PORT: u16 = 9000;
const CHUNK: usize = 64 * 1024;
/// Concurrent sessions (status checks may overlap an upload).
const MAX_SESSIONS: usize = 4;
/// Drop a session that has sent nothing for this long.
const IDLE_MS: u64 = 60_000;
/// Largest module install payload (the store keeps values up to 1 MiB).
const MAX_MODULE: u32 = 1 << 20;

enum Phase {
    Header,
    /// `buf` collects the payload of W/X; kernel images stream to disk instead.
    Body { cmd: u8, left: u32, mac: Hmac, first: bool, buf: Option<Vec<u8>> },
    Mac { cmd: u8, mac: Hmac, payload: Vec<u8> },
    Done,
}

struct Session {
    conn: Conn,
    nonce: [u8; 16],
    phase: Phase,
    /// (bytes received, time) when we last saw progress
    progress: (u64, u64),
    /// This session is writing a kernel image (only one may at a time).
    uploading: bool,
}

#[derive(Default)]
pub struct Updater {
    key: Vec<u8>,
    listener: Option<TcpListener>,
    sessions: Vec<Session>,
    /// (when, power off instead of reboot)
    reboot_at: Option<(u64, bool)>,
}

impl Updater {
    pub fn new() -> Updater {
        Updater::default()
    }
}

impl Session {
    fn finish(&mut self, msg: &str) {
        self.conn.write(msg.as_bytes());
        self.conn.close();
        self.phase = Phase::Done;
    }

    fn mac_base(&self, key: &[u8]) -> Hmac {
        let mut m = Hmac::new(key);
        m.update(&self.nonce);
        m
    }

    /// Advance the protocol; returns a reboot request when one was made.
    /// `busy`: another session is uploading a kernel.
    fn step(&mut self, sys: &mut dyn Sys, key: &[u8], busy: bool) -> Option<(u64, bool)> {
        loop {
            let input = &mut self.conn.inbuf;
            match &mut self.phase {
                Phase::Done => return None,
                Phase::Header => {
                    if input.len() < 37 {
                        if self.conn.eof {
                            self.conn.close();
                            self.phase = Phase::Done;
                        }
                        return None;
                    }
                    let head: Vec<u8> = input.drain(..37).collect();
                    let (cmd, len) = (head[0], u32::from_be_bytes([head[1], head[2], head[3], head[4]]));
                    let mut hm = self.mac_base(key);
                    hm.update(b"H");
                    hm.update(&head[..5]);
                    if !ct_eq(&hm.finish(), &head[5..37]) {
                        say!(sys, "updater: bad header MAC from {}, rejected\n", self.conn.peer);
                        self.finish("ERR auth\n");
                        return None;
                    }
                    let mut mac = self.mac_base(key);
                    mac.update(&head[..5]);
                    match cmd {
                        b'U' => {
                            if busy {
                                self.finish("ERR another upload is in progress\n");
                                return None;
                            }
                            let Some(info) = sys.update_info() else {
                                self.finish("ERR no update slot\n");
                                return None;
                            };
                            if info.trial {
                                self.finish("ERR confirm the running trial kernel first\n");
                                return None;
                            }
                            if len as u64 > info.max_bytes || len < 64 {
                                self.finish("ERR bad image size\n");
                                return None;
                            }
                            if !sys.admin().is_some_and(|a| a.update_begin()) {
                                self.finish("ERR cannot start update\n");
                                return None;
                            }
                            self.uploading = true;
                            let target = if info.slot == 'a' { 'b' } else { 'a' };
                            say!(sys, "updater: receiving {} bytes into slot {}\n", len, target);
                            self.phase = Phase::Body { cmd, left: len, mac, first: true, buf: None };
                        }
                        b'W' | b'X' | b'S' | b'K' | b'Q' | b'E' | b'N' if (1..=MAX_MODULE).contains(&len) => {
                            self.phase = Phase::Body { cmd, left: len, mac, first: false, buf: Some(Vec::new()) };
                        }
                        b'L' if (1..=64).contains(&len) => self.phase = Phase::Body { cmd, left: len, mac, first: false, buf: Some(Vec::new()) },
                        b'C' | b'R' | b'P' | b'I' | b'L' if len == 0 => self.phase = Phase::Mac { cmd, mac, payload: Vec::new() },
                        _ => {
                            self.finish("ERR bad command\n");
                            return None;
                        }
                    }
                }
                Phase::Body { cmd, left, mac, first, buf } => {
                    if input.is_empty() {
                        if self.conn.eof {
                            self.conn.close();
                            self.phase = Phase::Done;
                        }
                        return None;
                    }
                    let n = input.len().min(*left as usize);
                    let chunk: Vec<u8> = input.drain(..n).collect();
                    if *first && !chunk.starts_with(b"\x7fELF") {
                        self.finish("ERR not an ELF image\n");
                        return None;
                    }
                    *first = false;
                    mac.update(&chunk);
                    *left -= n as u32;
                    match buf {
                        Some(b) => b.extend_from_slice(&chunk),
                        None => {
                            if !sys.admin().is_some_and(|a| a.update_write(&chunk)) {
                                self.finish("ERR disk write failed\n");
                                return None;
                            }
                        }
                    }
                    if *left == 0 {
                        let (cmd, mac, payload) = (*cmd, mac.clone(), buf.take().unwrap_or_default());
                        self.phase = Phase::Mac { cmd, mac, payload };
                    }
                }
                Phase::Mac { cmd, mac, payload } => {
                    if input.len() < 32 {
                        if self.conn.eof {
                            self.conn.close();
                            self.phase = Phase::Done;
                        }
                        return None;
                    }
                    let tag: Vec<u8> = input.drain(..32).collect();
                    let (mut cmd, ok, mut payload) = (*cmd, ct_eq(&mac.clone().finish(), &tag), core::mem::take(payload));
                    if !ok {
                        say!(sys, "updater: bad MAC from {}, rejected\n", self.conn.peer);
                        self.finish("ERR auth\n");
                        return None;
                    }
                    if cmd == b'E' {
                        // authenticated ciphertext: decrypt, then run the inner command
                        keystream_xor(key, &self.nonce, &mut payload);
                        match payload.first() {
                            Some(&c @ (b'K' | b'Q' | b'X' | b'S' | b'D' | b'B' | b'd' | b'b' | b'M')) if payload.len() > 1 => {
                                cmd = c;
                                payload.remove(0);
                            }
                            _ => {
                                self.finish("ERR bad encrypted command\n");
                                return None;
                            }
                        }
                    }
                    let reboot = sys.now_ms() + 1000; // let the reply get out first
                    match cmd {
                        b'U' => {
                            if !sys.admin().is_some_and(|a| a.update_commit()) {
                                self.finish("ERR commit failed\n");
                                return None;
                            }
                            say!(sys, "updater: new kernel written, rebooting into it for a trial boot\n");
                            self.finish("OK\n");
                            return Some((reboot, false));
                        }
                        b'C' => {
                            let ok = sys.admin().is_some_and(|a| a.confirm_boot());
                            if ok {
                                say!(sys, "updater: running kernel confirmed as default\n");
                            }
                            self.finish(if ok { "OK\n" } else { "ERR confirm failed\n" });
                            return None;
                        }
                        b'I' => {
                            let report = info(sys);
                            self.finish(&report);
                            return None;
                        }
                        b'W' => {
                            let n = payload[0] as usize;
                            let (Some(name), Some(module)) =
                                (payload.get(1..1 + n).and_then(|b| core::str::from_utf8(b).ok()), payload.get(1 + n..))
                            else {
                                self.finish("ERR bad payload\n");
                                return None;
                            };
                            match sys.admin().map_or(Err(String::from("not permitted")), |a| a.module_install(name, module)) {
                                Ok(kind) => {
                                    say!(sys, "updater: installed module {} ({}, {} bytes)\n", name, kind.as_str(), module.len());
                                    self.finish("OK\n");
                                }
                                Err(e) => self.finish(&alloc::format!("ERR {e}\n")),
                            }
                            return None;
                        }
                        b'L' => {
                            let text = String::from_utf8_lossy(&payload).into_owned();
                            let words: Vec<&str> = text.split_whitespace().collect();
                            let reply = rustros_util::logcmd::run(sys, &words, 0).unwrap_or_else(|e| alloc::format!("ERR {e}"));
                            self.finish(&reply);
                            return None;
                        }
                        b'N' => {
                            let text = String::from_utf8_lossy(&payload).into_owned();
                            let words: Vec<&str> = text.split_whitespace().collect();
                            let reply = match words.split_first() {
                                Some((&"boot", [])) => {
                                    let l: String = sys.admin().map(|a| a.boot_net()).unwrap_or_default().iter().map(|(k, v)| alloc::format!("{k} = {v}\n")).collect();
                                    if l.is_empty() { String::from("(nothing stored)\n") } else { l }
                                }
                                Some((&"boot", [k, v])) => {
                                    let v = if *v == "-" { "" } else { *v };
                                    let ok = sys.admin().is_some_and(|a| a.boot_net_set(k, v));
                                    String::from(if ok { "OK (from the next boot on)\n" } else { "ERR key must be net*, or no boot disk\n" })
                                }
                                _ => netcmd::run(sys, &words).unwrap_or_else(|e| alloc::format!("ERR {e}")),
                            };
                            if !reply.starts_with("ERR") {
                                say!(sys, "updater: net {}\n", text);
                            }
                            self.finish(&reply);
                            return None;
                        }
                        // ESP sectors (encrypted only): 'D' lba(8) count(2) -> "OK <hex
                        // of the sectors, encrypted for the reply>"; 'B' lba(8) data.
                        // The boot area likewise: 'd' reads any of it, 'b' writes
                        // only where no partition is (esp-grow builds the new EFI
                        // partition there)
                        b'D' | b'B' | b'd' | b'b' => {
                            let lba = payload.get(..8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                            let Some(admin) = sys.admin() else {
                                self.finish("ERR not permitted\n");
                                return None;
                            };
                            let reply = if cmd == b'D' || cmd == b'd' {
                                let n = payload.get(8..10).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize);
                                match if cmd == b'D' { admin.esp_read(lba, n) } else { admin.boot_read(lba, n) } {
                                    Some(mut data) => {
                                        keystream_xor(key, &[&self.nonce[..], b"R"].concat(), &mut data);
                                        alloc::format!("OK {}\n", data.iter().map(|b| alloc::format!("{b:02x}")).collect::<String>())
                                    }
                                    None => String::from("ERR outside the area, or read failed\n"),
                                }
                            } else if cmd == b'b' {
                                if payload.len() > 8 && admin.boot_write(lba, &payload[8..]) {
                                    String::from("OK\n")
                                } else {
                                    String::from("ERR not free space in the boot area, or write failed\n")
                                }
                            } else if payload.len() > 8 && admin.esp_write(lba, &payload[8..]) {
                                say!(sys, "updater: wrote {} sectors of the EFI partition at {}\n", (payload.len() - 8) / 512, lba);
                                String::from("OK\n")
                            } else {
                                String::from("ERR outside the EFI partition, or write failed\n")
                            };
                            self.finish(&reply);
                            return None;
                        }
                        // move the EFI partition (encrypted only): 'M' first(8) last(8)
                        b'M' => {
                            let at = |o: usize| payload.get(o..o + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                            let reply = match sys.admin().map(|a| a.esp_move(at(0), at(8))) {
                                Some(Ok(())) => {
                                    say!(sys, "updater: the EFI partition moves to sectors {}-{} (next boot)\n", at(0), at(8));
                                    String::from("OK\n")
                                }
                                Some(Err(e)) => alloc::format!("ERR {e}\n"),
                                None => String::from("ERR not permitted\n"),
                            };
                            self.finish(&reply);
                            return None;
                        }
                        b'K' | b'Q' => {
                            let text = String::from_utf8_lossy(&payload);
                            let mut parts = text.splitn(3, '\n');
                            let (name, key, value) = (parts.next().unwrap_or(""), parts.next(), parts.next());
                            let Some(admin) = sys.admin() else {
                                self.finish("ERR not permitted\n");
                                return None;
                            };
                            let reply = match (cmd, key) {
                                (b'K', Some(key)) => match admin.module_config_set(name, key, value) {
                                    Ok(()) => {
                                        say!(sys, "updater: {} setting {} {}\n", name, key, if value.is_some() { "set" } else { "removed" });
                                        String::from("OK\n")
                                    }
                                    Err(e) => alloc::format!("ERR {e}\n"),
                                },
                                (b'K', None) => String::from("ERR no key\n"),
                                _ => {
                                    let l: String = admin
                                        .module_config(name)
                                        .into_iter()
                                        .map(|(k, v)| alloc::format!("{k} = {}\n", if rustros_util::secret::is_secret(&k) { "***" } else { v.as_str() }))
                                        .collect();
                                    if l.is_empty() { String::from("(no settings)\n") } else { l }
                                }
                            };
                            self.finish(&reply);
                            return None;
                        }
                        b'X' | b'S' => {
                            // "<name>" or "<name> <native|wasm>"
                            let text = String::from_utf8_lossy(&payload);
                            let mut w = text.split_whitespace();
                            let (name, kind) = (w.next().unwrap_or(""), w.next().map(ModuleKind::parse));
                            let reply = match (cmd, kind) {
                                (_, Some(None)) => String::from("ERR kind must be native or wasm\n"),
                                (b'X', kind) => {
                                    let ok = sys.admin().is_some_and(|a| a.module_remove(name, kind.flatten()));
                                    String::from(if ok { "OK\n" } else { "ERR no such module\n" })
                                }
                                (_, Some(Some(kind))) => match sys.admin().map(|a| a.module_switch(name, kind)) {
                                    Some(Ok(())) => String::from("OK\n"),
                                    Some(Err(e)) => alloc::format!("ERR {e}\n"),
                                    None => String::from("ERR not permitted\n"),
                                },
                                _ => String::from("ERR switch needs native or wasm\n"),
                            };
                            self.finish(&reply);
                            return None;
                        }
                        _ => {
                            self.finish("OK\n");
                            return Some((reboot, cmd == b'P'));
                        }
                    }
                }
            }
        }
    }
}

/// XOR `data` with HMAC-SHA256(key, nonce | "E" | counter) blocks.
pub fn keystream_xor(key: &[u8], nonce: &[u8], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(32).enumerate() {
        let mut h = Hmac::new(key);
        h.update(nonce);
        h.update(b"E");
        h.update(&(i as u32).to_be_bytes());
        for (b, k) in chunk.iter_mut().zip(h.finish()) {
            *b ^= k;
        }
    }
}

/// One line about an installed module.
pub fn describe(m: &ModuleInfo) -> String {
    let size = |b: Option<usize>| b.map_or(String::from("-"), |b| alloc::format!("{} KiB", b.div_ceil(1024)));
    let mut s = alloc::format!(
        "{}: {} (prefers {}; native {}, wasm {}; {} restarts)",
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
        s += &alloc::format!(" [native switched off after a crash: {why}]");
    }
    s
}

/// Status report for the 'I' command.
fn info(sys: &mut dyn Sys) -> String {
    let mut r = String::new();
    if sys.net().is_none() {
        return String::new();
    }
    let up = sys.now_ms() / 1000;
    let _ = writeln!(r, "uptime   {}d {:02}:{:02}:{:02}", up / 86400, up / 3600 % 24, up / 60 % 60, up % 60);
    if let Some(u) = sys.update_info() {
        let _ = writeln!(r, "slot     {}{}", u.slot, if u.trial { " (trial, not confirmed)" } else { "" });
        let _ = writeln!(
            r,
            "boot     {}{}",
            if u.safe_mode { "SAFE MODE, " } else { "" },
            if u.unstable_boots > 1 { alloc::format!("{} unstable boots in a row", u.unstable_boots) } else { String::from("normal") }
        );
    }
    if let Some(net) = sys.net() {
        for i in 0..net.nic_count() {
            if let Some(m) = net.nic_info(i) {
                let _ = writeln!(r, "{:<8} {}/{} gw {} mtu {}", net.nic_name(i), IpFmt(m.ip), m.mask.count_ones(), IpFmt(m.gw), m.mtu);
            }
            let extra = net.extra_addrs(i);
            if !extra.is_empty() {
                let _ = writeln!(r, "extra    {} ({}) {}", net.nic_name(i), extra.len(), rustros_util::wire::fmt_ip_list(&extra));
            }
            if let Some(m) = net.nic_info(i) {
                let _ = writeln!(r, "traffic  {} rx {} tx {} frames, dropped rx {} tx {}", net.nic_name(i), m.rx, m.tx, m.rx_dropped, m.tx_dropped);
            }
        }
    }
    if let Some(a) = sys.admin() {
        for (i, l) in a.perf_report().lines().enumerate() {
            let _ = writeln!(r, "{}{}", if i == 0 { "perf     " } else { "         " }, l);
        }
    }
    let _ = writeln!(r, "running  {}", sys.modules().join(", "));
    match sys.kv().and_then(|k| k.storage_info()) {
        Some(s) => {
            let _ = writeln!(r, "storage  {} MiB partition, {} bytes live", s.partition_bytes >> 20, s.live_bytes);
        }
        None => r.push_str("storage  none\n"),
    }
    for m in sys.admin().map(|a| a.module_list()).unwrap_or_default() {
        let _ = writeln!(r, "module   {}", describe(&m));
    }
    let _ = writeln!(r, "crash    {}", sys.last_crash().unwrap_or_else(|| String::from("none recorded")));
    r
}

impl Module for Updater {
    fn name(&self) -> &'static str {
        "updater"
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::ADMIN
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.key = cmdline_get(sys.cmdline(), "key").unwrap_or("").as_bytes().to_vec();
        if self.key.is_empty() || sys.update_info().is_none() {
            say!(sys, "updater: disabled (needs key= and an update slot)\n");
            return;
        }
        let Some(net) = sys.net() else { return };
        match net.tcp_listen(PORT) {
            Ok(l) => self.listener = Some(l),
            Err(e) => say!(sys, "updater: cannot listen on {}: {:?}\n", PORT, e),
        }
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        if let Some((t, off)) = self.reboot_at {
            if sys.now_ms() >= t {
                if let Some(a) = sys.admin() {
                    if off {
                        a.poweroff();
                    }
                    a.reboot();
                }
            }
        }
        let Some(l) = self.listener else { return };
        while let Some(Ok((s, peer))) = sys.net().map(|n| n.tcp_accept(l)) {
            if self.sessions.len() >= MAX_SESSIONS {
                if let Some(n) = sys.net() {
                    n.tcp_abort(s);
                }
                continue;
            }
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&sys.random().to_le_bytes());
            nonce[8..].copy_from_slice(&sys.random().to_le_bytes());
            let info = sys.update_info();
            let mut conn = Conn::new(s, peer);
            conn.write(b"RRS1");
            conn.write(&nonce);
            conn.write(&[info.as_ref().map_or(b'?', |i| i.slot as u8), info.is_some_and(|i| i.trial) as u8]);
            self.sessions.push(Session {
                conn,
                nonce,
                phase: Phase::Header,
                progress: (0, sys.now_ms()),
                uploading: false,
            });
        }
        let now = sys.now_ms();
        let key = &self.key;
        let mut reboot_at = None;
        for i in 0..self.sessions.len() {
            let busy = self.sessions.iter().enumerate().any(|(j, o)| j != i && o.uploading);
            let s = &mut self.sessions[i];
            let Some(net) = sys.net() else { return };
            if s.conn.received != s.progress.0 {
                s.progress = (s.conn.received, now);
            } else if now - s.progress.1 > IDLE_MS {
                say!(net, "updater: {} idle, dropped\n", s.conn.peer);
                s.conn.abort(net);
                s.phase = Phase::Done;
            }
            if s.conn.pump(net, CHUNK) {
                if let Some(t) = s.step(sys, key, busy) {
                    reboot_at = Some(t);
                }
                if let Some(net) = sys.net() {
                    s.conn.pump(net, CHUNK);
                }
            }
        }
        if reboot_at.is_some() {
            self.reboot_at = reboot_at;
        }
        // pump reports false once a connection is closed (and flushed) or failed
        let Some(net) = sys.net() else { return };
        self.sessions.retain_mut(|s| s.conn.pump(net, 0));
    }
}
