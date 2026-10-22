//! `warp`: a Cloudflare WARP account for a WireGuard interface in one go:
//! new keys made here, the device registered and switched on, the tunnel
//! written into `cfg wireguard <if>.*` (the private key never leaves the
//! machine). The account's id and token stay in the shell's store
//! (`warp/<if>/...`) for the other subcommands.
//!
//! ```text
//! warp [<if>]                 register (if: warp)
//! warp <if> license <key>     put a WARP+ license on the account
//! warp <if> show              the account
//! warp <if> remove            unregister, drop the tunnel's settings
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Sys, say};
use rustros_util::base64;

use crate::curl::{Curl, Request};

pub const USAGE: &str = "usage: warp [<if>] | warp <if> license <key> | warp <if> show | warp <if> remove\n";
const API: &str = "https://api.cloudflareclient.com/v0a2158/reg";
/// The peer's port (the API gives its addresses with port 0).
const PORT: u16 = 2408;
/// Our peer's name in the WireGuard settings.
const PEER: &str = "cf";

enum Step {
    Register { private: [u8; 32] },
    Enable { private: [u8; 32], reg: Json },
    License,
    Show,
    Remove,
}

pub struct Warp {
    iface: String,
    step: Step,
    curl: Curl,
}

// ------------------------------------------------------------- a little JSON

#[derive(Debug)]
enum Json {
    Str(String),
    Num(String),
    Bool(bool),
    Null,
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &[u8]) -> Option<Json> {
        let mut p = 0;
        let v = value(text, &mut p)?;
        Some(v)
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn at(&self, i: usize) -> Option<&Json> {
        match self {
            Json::Arr(a) => a.get(i),
            _ => None,
        }
    }

    fn path(&self, keys: &[&str]) -> Option<&Json> {
        keys.iter().try_fold(self, |v, k| v.get(k))
    }

    fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// For showing: a string as it is, anything else in its JSON form.
    fn text(&self) -> String {
        match self {
            Json::Str(s) => s.clone(),
            Json::Num(n) => n.clone(),
            Json::Bool(b) => format!("{b}"),
            Json::Null => String::from("null"),
            _ => String::from("..."),
        }
    }
}

fn ws(t: &[u8], p: &mut usize) {
    while t.get(*p).is_some_and(|c| c.is_ascii_whitespace()) {
        *p += 1;
    }
}

fn value(t: &[u8], p: &mut usize) -> Option<Json> {
    ws(t, p);
    match *t.get(*p)? {
        b'{' => {
            *p += 1;
            let mut m = Vec::new();
            loop {
                ws(t, p);
                match *t.get(*p)? {
                    b'}' => {
                        *p += 1;
                        return Some(Json::Obj(m));
                    }
                    b',' => *p += 1,
                    _ => {
                        let Json::Str(k) = value(t, p)? else { return None };
                        ws(t, p);
                        if *t.get(*p)? != b':' {
                            return None;
                        }
                        *p += 1;
                        m.push((k, value(t, p)?));
                    }
                }
            }
        }
        b'[' => {
            *p += 1;
            let mut a = Vec::new();
            loop {
                ws(t, p);
                match *t.get(*p)? {
                    b']' => {
                        *p += 1;
                        return Some(Json::Arr(a));
                    }
                    b',' => *p += 1,
                    _ => a.push(value(t, p)?),
                }
            }
        }
        b'"' => {
            *p += 1;
            let mut s = Vec::new();
            loop {
                let c = *t.get(*p)?;
                *p += 1;
                match c {
                    b'"' => return Some(Json::Str(String::from_utf8_lossy(&s).into_owned())),
                    b'\\' => {
                        let e = *t.get(*p)?;
                        *p += 1;
                        match e {
                            b'n' => s.push(b'\n'),
                            b't' => s.push(b'\t'),
                            b'r' => s.push(b'\r'),
                            b'b' | b'f' => {}
                            b'u' => {
                                let h = core::str::from_utf8(t.get(*p..*p + 4)?).ok()?;
                                *p += 4;
                                let c = char::from_u32(u32::from_str_radix(h, 16).ok()?).unwrap_or('?');
                                s.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                            }
                            e => s.push(e),
                        }
                    }
                    c => s.push(c),
                }
            }
        }
        b't' if t[*p..].starts_with(b"true") => {
            *p += 4;
            Some(Json::Bool(true))
        }
        b'f' if t[*p..].starts_with(b"false") => {
            *p += 5;
            Some(Json::Bool(false))
        }
        b'n' if t[*p..].starts_with(b"null") => {
            *p += 4;
            Some(Json::Null)
        }
        _ => {
            let start = *p;
            while t.get(*p).is_some_and(|c| matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                *p += 1;
            }
            (*p > start).then(|| Json::Num(String::from_utf8_lossy(&t[start..*p]).into_owned()))
        }
    }
}

/// The API puts its answer under "result" (v4 style) or at the top.
fn result(j: Json) -> Json {
    match j {
        Json::Obj(mut m) => match m.iter().position(|(k, _)| k == "result") {
            Some(i) if matches!(m[i].1, Json::Obj(_)) => m.swap_remove(i).1,
            _ => Json::Obj(m),
        },
        j => j,
    }
}

// ------------------------------------------------------------- the command

/// "2026-10-22T06:00:40.000Z"
fn iso_time(unix: u64) -> String {
    let (days, secs) = (unix / 86400, unix % 86400);
    // civil from days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as u64;
    format!("{y}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", secs / 3600, secs / 60 % 60, secs % 60)
}

fn kv_key(iface: &str, what: &str) -> String {
    format!("warp/{iface}/{what}")
}

fn stored(sys: &mut dyn Sys, iface: &str, what: &str) -> Option<String> {
    let v = sys.kv()?.get(&kv_key(iface, what))?;
    String::from_utf8(v).ok()
}

fn api(sys: &mut dyn Sys, method: &str, url: String, token: Option<&str>, body: Option<String>) -> Result<Curl, String> {
    let mut headers = alloc::vec![String::from("User-Agent: okhttp/3.12.1"), String::from("CF-Client-Version: a-6.10-2158")];
    if body.is_some() {
        headers.push(String::from("Content-Type: application/json"));
    }
    if let Some(t) = token {
        headers.push(format!("Authorization: Bearer {t}"));
    }
    Curl::request(sys, Request { method, url: &url, headers, body: body.map(String::into_bytes), src: 0, max_secs: 20 }).map_err(|e| format!("warp: {}", e.trim_start_matches("curl: ")))
}

/// The account's id and token, from an earlier `warp <if>`.
fn account(sys: &mut dyn Sys, iface: &str) -> Result<(String, String), String> {
    match (stored(sys, iface, "id"), stored(sys, iface, "token")) {
        (Some(id), Some(token)) => Ok((id, token)),
        _ => Err(format!("warp: no account for {iface} (register with: warp {iface})\n")),
    }
}

impl Warp {
    pub fn start(sys: &mut dyn Sys, args: &[&str]) -> Result<Warp, String> {
        let iface = String::from(*args.first().unwrap_or(&"warp"));
        if iface.is_empty() || iface.contains('.') || iface.starts_with('-') {
            return Err(String::from(USAGE));
        }
        if sys.unix_time() == 0 {
            return Err(String::from("warp: no clock (the real-time clock was not readable): certificates cannot be checked\n"));
        }
        let (step, curl) = match args.get(1).copied() {
            None => {
                if stored(sys, &iface, "id").is_some() {
                    return Err(format!("warp: {iface} already has an account (warp {iface} show; warp {iface} remove first for a new one)\n"));
                }
                // fresh hardware randomness for the key (curl seeds it too)
                let mut seed = [0u8; 32];
                for c in seed.chunks_mut(8) {
                    c.copy_from_slice(&sys.random().to_le_bytes());
                }
                tls::seed(seed);
                let mut private = [0u8; 32];
                if !tls::random(&mut private) {
                    return Err(String::from("warp: no random numbers\n"));
                }
                private[0] &= 248;
                private[31] = (private[31] & 127) | 64;
                let public = base64::encode(&tls::x25519_public(private));
                let body = format!(
                    "{{\"key\":\"{public}\",\"install_id\":\"\",\"fcm_token\":\"\",\"tos\":\"{}\",\"model\":\"PC\",\"serial_number\":\"\",\"locale\":\"en_US\"}}",
                    iso_time(sys.unix_time())
                );
                say!(sys, "warp: registering a device for {}...\n", iface);
                (Step::Register { private }, api(sys, "POST", String::from(API), None, Some(body))?)
            }
            Some("license") => {
                let Some(key) = args.get(2) else { return Err(String::from(USAGE)) };
                let (id, token) = account(sys, &iface)?;
                (Step::License, api(sys, "PUT", format!("{API}/{id}/account"), Some(&token), Some(format!("{{\"license\":\"{key}\"}}")))?)
            }
            Some("show") => {
                let (id, token) = account(sys, &iface)?;
                (Step::Show, api(sys, "GET", format!("{API}/{id}/account"), Some(&token), None)?)
            }
            Some("remove") => {
                let (id, token) = account(sys, &iface)?;
                (Step::Remove, api(sys, "DELETE", format!("{API}/{id}"), Some(&token), None)?)
            }
            Some(_) => return Err(String::from(USAGE)),
        };
        Ok(Warp { iface, step, curl })
    }

    pub fn abort(&mut self, sys: &mut dyn Sys) {
        self.curl.abort(sys);
    }

    /// Work on it; true once finished.
    pub fn poll(&mut self, sys: &mut dyn Sys) -> bool {
        if !self.curl.poll(sys) {
            return false;
        }
        let iface = self.iface.clone();
        let answer = self.curl.answer();
        let (status, body) = match answer {
            Ok(a) => a,
            Err(e) => {
                say!(sys, "warp: {}\n", e.trim_start_matches("curl: "));
                return true;
            }
        };
        let json = Json::parse(&body).map(result);
        if !(200..300).contains(&status) {
            let why = json.as_ref().and_then(|j| j.path(&["errors"])).and_then(|e| e.at(0)).and_then(|e| e.get("message")).map(Json::text);
            say!(sys, "warp: the API said {}{}\n", status, why.map(|w| format!(": {w}")).unwrap_or_default());
            return true;
        }
        match core::mem::replace(&mut self.step, Step::Show) {
            Step::Register { private } => {
                let Some(reg) = json else {
                    say!(sys, "warp: unreadable answer\n");
                    return true;
                };
                let (Some(id), Some(token)) = (reg.get("id").and_then(Json::str), reg.get("token").and_then(Json::str)) else {
                    say!(sys, "warp: no id or token in the answer\n");
                    return true;
                };
                let (id, token) = (String::from(id), String::from(token));
                let saved = sys.kv().is_some_and(|kv| kv.put(&kv_key(&iface, "id"), id.as_bytes()).is_ok() && kv.put(&kv_key(&iface, "token"), token.as_bytes()).is_ok());
                if !saved {
                    say!(sys, "warp: (no storage: the account is not kept for show/license/remove)\n");
                }
                if let Some(c) = reg.path(&["config", "client_id"]).and_then(Json::str) {
                    if let Some(kv) = sys.kv() {
                        let _ = kv.put(&kv_key(&iface, "client_id"), c.as_bytes());
                    }
                }
                match api(sys, "PATCH", format!("{API}/{id}"), Some(&token), Some(String::from("{\"warp_enabled\":true}"))) {
                    Ok(c) => {
                        self.curl = c;
                        self.step = Step::Enable { private, reg };
                        return false;
                    }
                    Err(e) => say!(sys, "{}\n", e),
                }
            }
            Step::Enable { private, reg } => {
                let on = json.as_ref().and_then(|j| j.get("warp_enabled")).is_some_and(|v| matches!(v, Json::Bool(true)));
                let peer = reg.path(&["config", "peers"]).and_then(|p| p.at(0));
                let public = peer.and_then(|p| p.get("public_key")).and_then(Json::str);
                let endpoint = peer.and_then(|p| p.path(&["endpoint", "v4"])).and_then(Json::str).map(|e| e.rsplit_once(':').map_or(e, |(h, _)| h));
                let address = reg.path(&["config", "interface", "addresses", "v4"]).and_then(Json::str);
                let (Some(public), Some(endpoint), Some(address)) = (public, endpoint, address) else {
                    say!(sys, "warp: the answer lacks the peer or our address\n");
                    return true;
                };
                let settings = [
                    (String::from("private"), base64::encode(&private)),
                    (String::from("address"), format!("{address}/32")),
                    (format!("peer.{PEER}.public"), String::from(public)),
                    (format!("peer.{PEER}.endpoint"), format!("{endpoint}:{PORT}")),
                    (format!("peer.{PEER}.allowed"), String::from("0.0.0.0/0")),
                    (format!("peer.{PEER}.keepalive"), String::from("25")),
                ];
                let Some(admin) = sys.admin() else { return true };
                for (k, v) in &settings {
                    if let Err(e) = admin.module_config_set("wireguard", &format!("{iface}.{k}"), Some(v)) {
                        say!(sys, "warp: cannot set wireguard {}.{}: {}\n", iface, k, e);
                        return true;
                    }
                }
                say!(
                    sys,
                    "warp: {} registered{}; tunnel {} -> {}:{} written to cfg wireguard {}.*\n\
                     warp: send LAN hosts through it: cfg wireguard {}.hosts 10.9.0.5,10.9.1.0/24\n",
                    iface,
                    if on { " and enabled" } else { " (enabling it failed: try again with warp show)" },
                    address,
                    endpoint,
                    PORT,
                    iface,
                    iface
                );
            }
            Step::License => {
                let j = json.as_ref();
                say!(
                    sys,
                    "warp: {}: license accepted; account type {}\n",
                    iface,
                    j.and_then(|j| j.get("account_type")).map(Json::text).unwrap_or_else(|| String::from("?"))
                );
            }
            Step::Show => {
                let Some(j) = json else {
                    say!(sys, "warp: unreadable answer\n");
                    return true;
                };
                say!(sys, "warp {}:\n", iface);
                for k in ["account_type", "warp_plus", "premium_data", "quota", "usage", "referral_count", "created", "ttl"] {
                    if let Some(v) = j.get(k) {
                        say!(sys, "  {:<15} {}\n", k, v.text());
                    }
                }
            }
            Step::Remove => {
                if let Some(kv) = sys.kv() {
                    for w in ["id", "token", "client_id"] {
                        let _ = kv.delete(&kv_key(&iface, w));
                    }
                }
                let keys: Vec<String> = sys.admin().map(|a| a.module_config("wireguard")).unwrap_or_default().into_iter().map(|(k, _)| k).filter(|k| k.starts_with(&format!("{iface}."))).collect();
                if let Some(admin) = sys.admin() {
                    for k in &keys {
                        let _ = admin.module_config_set("wireguard", k, None);
                    }
                }
                say!(sys, "warp: {}: unregistered, {} settings removed\n", iface, keys.len());
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json() {
        let j = Json::parse(br#"{"result":{"id":"t-1","config":{"peers":[{"public_key":"k\/x","endpoint":{"v4":"1.2.3.4:0"}}]},"n":-1.5e3,"ok":true}}"#).map(result).unwrap();
        assert_eq!(j.get("id").and_then(Json::str), Some("t-1"));
        assert_eq!(j.path(&["config", "peers"]).and_then(|p| p.at(0)).and_then(|p| p.path(&["endpoint", "v4"])).and_then(Json::str), Some("1.2.3.4:0"));
        assert_eq!(j.path(&["config", "peers"]).and_then(|p| p.at(0)).and_then(|p| p.get("public_key")).and_then(Json::str), Some("k/x"));
        assert_eq!(j.get("n").map(Json::text).as_deref(), Some("-1.5e3"));
        assert_eq!(iso_time(1_792_634_440), "2026-10-22T02:00:40.000Z");
    }
}
