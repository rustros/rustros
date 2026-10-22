//! The panel app: this machine as a node of the panel (its document 79),
//! over HTTPS the node opens itself; nothing listens here.
//!
//! - Not claimed yet: it asks the panel for a claim code, prints it on the
//!   console (again every few minutes) and waits (long polls) until someone
//!   enters it in the panel; the panel then gives the server number, a
//!   token and its Ed25519 key, kept in this app's store.
//! - Claimed: it long-polls for jobs. A job is base64url(payload) "."
//!   base64url(signature); one that is not signed by the panel's key, is
//!   for another server, has run out, or is not after the last one run is
//!   refused. The payload is {"server","id","exp","op","args"}: an
//!   instruction, never a script. The answer goes back as {"id","code",
//!   "stdout","stderr"}; every minute the node reports what it measures.
//! - A trial kernel (after `update`) and an applied network change (after
//!   `net`) are confirmed once the panel is reached again; otherwise they
//!   are rolled back by themselves.
//!
//! Where the panel is: `rustros.panel=https://host[:port]` on the kernel
//! command line, or `cfg panel url ...`.
//!
//! ```text
//! url    https://panel.example.com    the panel (overrides the command line)
//! ca     PEM                          also trust this CA (a private panel)
//! name   rustros-a1b2c3               the name asked for (default from the MAC)
//! dns    1.1.1.1                      resolver for the panel's name
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod https;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Caps, ModuleKind, Module, Param, Sys, say};
use rustros_util::json::{Json, quote};
use rustros_util::wire::{Ip, IpFmt, parse_cidr, parse_ip};

use https::{Call, Done, Request, Url};

pub const BUILD: &str = match option_env!("RUSTROS_BUILD") {
    Some(b) => b,
    None => env!("CARGO_PKG_VERSION"),
};
const ARCH: &str = "x86_64";
const DNS_DEFAULT: Ip = 0x0101_0101;
const RELOAD_MS: u64 = 5000;
/// The panel holds a long poll up to 15 s.
const POLL_MS: u64 = 40_000;
const CALL_MS: u64 = 30_000;
const METRICS_MS: u64 = 60_000;
/// The claim code is printed again this often.
const REPRINT_MS: u64 = 120_000;
const MAX_MODULE: usize = 1 << 20;
const MAX_KERNEL: usize = 256 * 1024;
/// A network change from the panel is reverted unless the panel is reached
/// again within this.
const NET_CONFIRM_S: u32 = 120;

/// What the node keeps (its own store, not `cfg/`).
#[derive(Default, Clone)]
struct Node {
    server: u64,
    token: String,
    public_key: [u8; 32],
    panel: String,
    last_job: u64,
}

/// What the call on its way is for.
enum Purpose {
    /// asking for a claim code
    Code,
    /// waiting with the claim's secret
    Claim,
    Jobs,
    /// a file a job needs
    File(Job),
    Result,
    Metrics,
}

#[derive(Clone, Debug)]
struct Job {
    id: u64,
    op: String,
    args: Json,
}

/// Done after the job's answer reached the panel.
enum After {
    Reboot,
    Poweroff,
}

pub struct Panel {
    url: Option<Url>,
    ca: String,
    dns: Ip,
    name: String,
    machine_id: String,
    node: Option<Node>,
    /// (claim code, secret, expires unix s)
    claim: Option<(String, String, u64)>,
    call: Option<(Call, Purpose)>,
    /// answers to send: (job id, body)
    results: Vec<(u64, String)>,
    after: Option<After>,
    next_at: u64,
    backoff_s: u64,
    metrics_at: u64,
    printed_at: u64,
    reload_at: u64,
    /// a network change waits to be confirmed by reaching the panel
    net_pending: Option<bool>,
    last_error: String,
    /// unauthorized answers in a row (the panel may have dropped this server)
    unauthorized: u32,
}

impl Default for Panel {
    fn default() -> Panel {
        Panel {
            url: None,
            ca: String::new(),
            dns: DNS_DEFAULT,
            name: String::new(),
            machine_id: String::new(),
            node: None,
            claim: None,
            call: None,
            results: Vec::new(),
            after: None,
            next_at: 0,
            backoff_s: 0,
            metrics_at: 0,
            printed_at: 0,
            reload_at: 0,
            net_pending: None,
            last_error: String::new(),
            unauthorized: 0,
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn kv_get(sys: &mut dyn Sys, k: &str) -> Option<String> {
    sys.kv()?.get(k).and_then(|v| String::from_utf8(v).ok())
}

fn kv_put(sys: &mut dyn Sys, k: &str, v: &str) -> bool {
    sys.kv().is_some_and(|kv| kv.put(k, v.as_bytes()).is_ok())
}

/// A job from the panel, if it is to be run (else why not).
fn verify(token: &str, key: &[u8; 32], server: u64, last: u64, now_unix: u64) -> Result<Job, String> {
    let (body, sig) = token.trim().split_once('.').ok_or("not a job")?;
    let body = rustros_util::base64::decode(body).ok_or("not a job")?;
    let sig = rustros_util::base64::decode(sig).ok_or("not a job")?;
    if !tls::ed25519_verify(key, &body, &sig) {
        return Err(String::from("the job is not the panel's"));
    }
    let j = Json::parse(&body).ok_or("the job cannot be read")?;
    let s = j.get("server").and_then(Json::u64).ok_or("the job has no server")?;
    if s != server {
        return Err(format!("the job is server {s}'s"));
    }
    if j.get("exp").and_then(Json::u64).unwrap_or(0) <= now_unix {
        return Err(String::from("the job has run out"));
    }
    let id = j.get("id").and_then(Json::u64).ok_or("the job has no id")?;
    if id <= last {
        return Err(format!("job {id} is not after the last one run ({last})"));
    }
    if j.get("script").is_some() {
        return Err(String::from("scripts are not run here"));
    }
    let op = String::from(j.get("op").and_then(Json::str).ok_or("the job has no op")?);
    Ok(Job { id, op, args: j.get("args").cloned().unwrap_or(Json::Obj(Vec::new())) })
}

fn arg<'a>(j: &'a Job, k: &str) -> Option<&'a Json> {
    j.args.get(k)
}

fn arg_str<'a>(j: &'a Job, k: &str) -> Option<&'a str> {
    arg(j, k).and_then(Json::str)
}

fn result_body(id: u64, code: i32, stdout: &str, stderr: &str) -> String {
    format!("{{\"id\":{id},\"code\":{code},\"stdout\":{},\"stderr\":{}}}", quote(stdout), quote(stderr))
}

impl Panel {
    pub fn new() -> Panel {
        Panel::default()
    }

    fn agent() -> String {
        format!("rustros-node/{BUILD}")
    }

    fn load(&mut self, sys: &mut dyn Sys) {
        let cfg = |sys: &mut dyn Sys, k: &str| kv_get(sys, &format!("cfg/{k}")).map(|v| String::from(v.trim())).filter(|v| !v.is_empty());
        let url = cfg(sys, "url").or_else(|| rustros_util::wire::cmdline_get(sys.cmdline(), "rustros.panel").map(String::from));
        let url = url.and_then(|u| Url::parse(&u));
        if url != self.url {
            match &url {
                Some(u) => say!(sys, "panel: the panel is https://{}:{}\n", u.host, u.port),
                None => say!(sys, "panel: no panel set (rustros.panel=https://... on the kernel command line, or cfg panel url)\n"),
            }
            self.url = url;
        }
        self.ca = cfg(sys, "ca").map(|v| rustros_util::pem::normalize(&v)).unwrap_or_default();
        self.dns = cfg(sys, "dns").and_then(|v| parse_ip(&v)).unwrap_or(DNS_DEFAULT);
        let mac = sys.net().map(|n| n.net_info().mac).unwrap_or_default();
        self.name = cfg(sys, "name").unwrap_or_else(|| format!("rustros-{:02x}{:02x}{:02x}", mac[3], mac[4], mac[5]));
    }

    fn load_node(&mut self, sys: &mut dyn Sys) {
        self.machine_id = match kv_get(sys, "machine_id") {
            Some(m) if m.len() == 32 => m,
            _ => {
                let mut b = [0u8; 16];
                if !tls::random(&mut b) {
                    for c in b.chunks_mut(8) {
                        c.copy_from_slice(&sys.random().to_le_bytes());
                    }
                }
                let m = hex(&b);
                kv_put(sys, "machine_id", &m);
                m
            }
        };
        let get = |sys: &mut dyn Sys, k: &str| kv_get(sys, &format!("node/{k}"));
        let node = (|| {
            let key: [u8; 32] = rustros_util::base64::decode(&get(sys, "public_key")?)?.try_into().ok()?;
            Some(Node {
                server: get(sys, "server")?.parse().ok()?,
                token: get(sys, "token")?,
                public_key: key,
                panel: get(sys, "panel").unwrap_or_default(),
                last_job: get(sys, "last_job").and_then(|v| v.parse().ok()).unwrap_or(0),
            })
        })();
        self.node = node;
    }

    fn save_node(&self, sys: &mut dyn Sys, n: &Node) -> bool {
        kv_put(sys, "node/server", &format!("{}", n.server))
            && kv_put(sys, "node/token", &n.token)
            && kv_put(sys, "node/public_key", &rustros_util::base64::encode(&n.public_key))
            && kv_put(sys, "node/panel", &n.panel)
            && kv_put(sys, "node/last_job", &format!("{}", n.last_job))
    }

    fn forget_node(&mut self, sys: &mut dyn Sys) {
        if let Some(kv) = sys.kv() {
            for k in ["server", "token", "public_key", "panel", "last_job"] {
                let _ = kv.delete(&format!("node/{k}"));
            }
        }
        self.node = None;
    }

    fn start_call(&mut self, sys: &mut dyn Sys, method: &'static str, path: String, body: String, purpose: Purpose, wait_ms: u64) {
        let Some(url) = self.url.clone() else { return };
        let bearer = self.node.as_ref().map(|n| format!("{}.{}", n.server, n.token));
        let now = sys.now_ms();
        let Some(net) = sys.net() else { return };
        let req = Request { method, path, bearer, body: body.into_bytes(), deadline: now + wait_ms };
        let call = Call::start(net, &url, &self.ca, &Self::agent(), self.dns, req);
        self.call = Some((call, purpose));
    }

    /// Something went wrong reaching the panel: try again later (1, 2, 4 … 60 s).
    fn trouble(&mut self, sys: &mut dyn Sys, why: String) {
        self.backoff_s = (self.backoff_s * 2).clamp(1, 60);
        self.next_at = sys.now_ms() + self.backoff_s * 1000;
        if why != self.last_error {
            say!(sys, "panel: {} (again in {} s)\n", why, self.backoff_s);
            self.last_error = why;
        }
    }

    fn reached(&mut self, sys: &mut dyn Sys) {
        if !self.last_error.is_empty() {
            say!(sys, "panel: reached again\n");
            self.last_error.clear();
        }
        self.backoff_s = 0;
        self.next_at = 0;
    }

    /// The next call, if none is on its way.
    fn next_call(&mut self, sys: &mut dyn Sys, now: u64) {
        if self.url.is_none() || now < self.next_at {
            return;
        }
        let Some(node) = self.node.clone() else {
            match &self.claim {
                None => {
                    let body = format!("{{\"machine_id\":{},\"name\":{},\"arch\":\"{ARCH}\",\"build\":{}}}", quote(&self.machine_id), quote(&self.name), quote(BUILD));
                    self.start_call(sys, "POST", String::from("/api/node/claim"), body, Purpose::Code, CALL_MS);
                }
                Some((_, secret, _)) => {
                    let body = format!("{{\"secret\":{}}}", quote(secret));
                    self.start_call(sys, "POST", String::from("/api/node/claim"), body, Purpose::Claim, POLL_MS);
                }
            }
            return;
        };
        if let Some((_, body)) = self.results.first() {
            let body = body.clone();
            self.start_call(sys, "POST", String::from("/api/node/jobs/result"), body, Purpose::Result, CALL_MS);
        } else if now >= self.metrics_at {
            let body = self.metrics(sys);
            self.start_call(sys, "POST", String::from("/api/node/metrics"), body, Purpose::Metrics, CALL_MS);
        } else {
            let _ = node;
            self.start_call(sys, "GET", String::from("/api/node/jobs"), String::new(), Purpose::Jobs, POLL_MS);
        }
    }

    fn done(&mut self, sys: &mut dyn Sys, purpose: Purpose, r: Done) {
        let now = sys.now_ms();
        let (status, body) = match r {
            Ok(x) => x,
            Err(e) => return self.trouble(sys, e),
        };
        if status == 401 || status == 403 {
            self.unauthorized += 1;
            if self.unauthorized >= 3 && self.node.is_some() {
                say!(sys, "panel: the panel does not know this server any more; asking for a claim code again\n");
                self.forget_node(sys);
                self.claim = None;
                self.unauthorized = 0;
            }
            return self.trouble(sys, format!("the panel said {status}"));
        }
        self.unauthorized = 0;
        match purpose {
            Purpose::Code => match status {
                200 => {
                    let j = Json::parse(&body);
                    let get = |k: &str| j.as_ref().and_then(|j| j.get(k)).and_then(Json::str).map(String::from);
                    match (get("claim"), get("secret")) {
                        (Some(c), Some(s)) => {
                            let exp = j.as_ref().and_then(|j| j.get("expires")).and_then(Json::u64).unwrap_or(0);
                            self.claim = Some((c, s, exp));
                            self.printed_at = 0;
                            self.reached(sys);
                        }
                        _ => self.trouble(sys, String::from("the claim code could not be read")),
                    }
                }
                429 => {
                    self.backoff_s = 30;
                    self.trouble(sys, String::from("too many unclaimed codes from this address"));
                }
                s => self.trouble(sys, format!("asking for a claim code: the panel said {s}")),
            },
            Purpose::Claim => match status {
                204 => self.reached(sys),
                200 => match self.enrolled(&body) {
                    Some(n) => {
                        if !self.save_node(sys, &n) {
                            say!(sys, "panel: claimed, but this machine has no storage: the claim is lost at reboot\n");
                        }
                        say!(sys, "panel: claimed: server {} on {}\n", n.server, if n.panel.is_empty() { "the panel" } else { n.panel.as_str() });
                        self.node = Some(n);
                        self.claim = None;
                        self.metrics_at = now;
                        self.reached(sys);
                    }
                    None => self.trouble(sys, String::from("the claim's answer could not be read")),
                },
                410 => {
                    say!(sys, "panel: the claim code ran out; asking for a new one\n");
                    self.claim = None;
                    self.reached(sys);
                }
                429 => {
                    self.backoff_s = 30;
                    self.trouble(sys, String::from("the panel asks to wait (429)"));
                }
                s => self.trouble(sys, format!("waiting for the claim: the panel said {s}")),
            },
            Purpose::Jobs => {
                if !matches!(status, 200 | 204) {
                    return self.trouble(sys, format!("asking for jobs: the panel said {status}"));
                }
                self.reached(sys);
                self.confirm_pending(sys);
                if status == 200 {
                    self.job(sys, &String::from_utf8_lossy(&body));
                }
            }
            Purpose::File(job) => {
                if status != 200 {
                    let id = job.id;
                    self.answer(sys, id, 1, "", &format!("fetching the file: the panel said {status}"));
                    return;
                }
                self.reached(sys);
                self.run_with_file(sys, job, &body);
            }
            Purpose::Result => {
                if !matches!(status, 200 | 204) {
                    return self.trouble(sys, format!("sending a job's answer: the panel said {status}"));
                }
                self.reached(sys);
                if !self.results.is_empty() {
                    self.results.remove(0);
                }
                if self.results.is_empty() {
                    match self.after.take() {
                        Some(After::Reboot) => {
                            say!(sys, "panel: rebooting as asked\n");
                            if let Some(a) = sys.admin() {
                                a.reboot();
                            }
                        }
                        Some(After::Poweroff) => {
                            say!(sys, "panel: powering off as asked\n");
                            if let Some(a) = sys.admin() {
                                a.poweroff();
                            }
                        }
                        None => {}
                    }
                }
            }
            Purpose::Metrics => {
                self.metrics_at = now + METRICS_MS;
                if matches!(status, 200 | 204) {
                    self.reached(sys);
                } else {
                    self.trouble(sys, format!("sending metrics: the panel said {status}"));
                }
            }
        }
    }

    fn enrolled(&self, body: &[u8]) -> Option<Node> {
        let j = Json::parse(body)?;
        let key: [u8; 32] = rustros_util::base64::decode(j.get("public_key")?.str()?)?.try_into().ok()?;
        Some(Node {
            server: j.get("server")?.u64()?,
            token: String::from(j.get("token")?.str()?),
            public_key: key,
            panel: j.get("panel").and_then(Json::str).map(String::from).unwrap_or_default(),
            last_job: 0,
        })
    }

    /// The panel was reached after a kernel update or a network change: keep them.
    fn confirm_pending(&mut self, sys: &mut dyn Sys) {
        if sys.update_info().is_some_and(|u| u.trial) {
            if let Some(a) = sys.admin() {
                if a.confirm_boot() {
                    say!(sys, "panel: the new kernel reached the panel: confirmed\n");
                }
            }
        }
        if let Some(save) = self.net_pending.take() {
            let Some(a) = sys.admin() else { return };
            a.net_confirm();
            let saved = save && a.net_save();
            say!(sys, "panel: the network change reached the panel: kept{}\n", if saved { " and saved" } else { "" });
        }
    }

    fn answer(&mut self, sys: &mut dyn Sys, id: u64, code: i32, stdout: &str, stderr: &str) {
        if code != 0 {
            say!(sys, "panel: job {} failed: {}\n", id, stderr);
        }
        self.results.push((id, result_body(id, code, stdout, stderr)));
    }

    fn job(&mut self, sys: &mut dyn Sys, token: &str) {
        let Some(node) = self.node.clone() else { return };
        let job = match verify(token, &node.public_key, node.server, node.last_job, sys.unix_time()) {
            Ok(j) => j,
            Err(e) => {
                say!(sys, "panel: a job refused: {}\n", e);
                return;
            }
        };
        // kept before it runs: after a reboot it is not run again
        if let Some(n) = self.node.as_mut() {
            n.last_job = job.id;
        }
        kv_put(sys, "node/last_job", &format!("{}", job.id));
        say!(sys, "panel: job {} {}\n", job.id, job.op);
        // a file first, for those that need one
        if matches!(job.op.as_str(), "module-install" | "update") {
            let Some(file) = arg(&job, "file").and_then(|f| f.u64().map(|n| format!("{n}")).or_else(|| f.str().map(String::from))) else {
                return self.answer(sys, job.id, 1, "", "no file given");
            };
            self.start_call(sys, "GET", format!("/api/node/files/{file}"), String::new(), Purpose::File(job), CALL_MS * 2);
            return;
        }
        let (code, out, err) = self.run(sys, &job);
        self.answer(sys, job.id, code, &out, &err);
    }

    fn run_with_file(&mut self, sys: &mut dyn Sys, job: Job, data: &[u8]) {
        let want = arg_str(&job, "sha256").and_then(unhex);
        let got = rustros_util::sha256::Sha256::digest(data);
        if want.as_deref() != Some(&got[..]) {
            return self.answer(sys, job.id, 1, "", "the file's SHA-256 does not match");
        }
        let r = match job.op.as_str() {
            "module-install" => {
                let Some(name) = arg_str(&job, "name") else { return self.answer(sys, job.id, 1, "", "no name") };
                if data.len() > MAX_MODULE {
                    Err(String::from("a module is at most 1 MiB"))
                } else {
                    match sys.admin().map(|a| a.module_install(name, data)) {
                        Some(Ok(k)) => Ok(format!("{{\"name\":{},\"kind\":\"{}\"}}", quote(name), k.as_str())),
                        Some(Err(e)) => Err(e),
                        None => Err(String::from("not permitted")),
                    }
                }
            }
            "update" => {
                if data.len() > MAX_KERNEL {
                    Err(String::from("a kernel is at most 256 KiB"))
                } else {
                    match sys.admin() {
                        Some(a) => {
                            if a.update_begin() && a.update_write(data) && a.update_commit() {
                                // the answer first, then the trial boot; it confirms itself once it reaches the panel
                                self.after = Some(After::Reboot);
                                Ok(String::from("{\"trial\":true}"))
                            } else {
                                Err(String::from("writing the kernel failed"))
                            }
                        }
                        None => Err(String::from("not permitted")),
                    }
                }
            }
            _ => Err(String::from("unknown op")),
        };
        match r {
            Ok(out) => self.answer(sys, job.id, 0, &out, ""),
            Err(e) => self.answer(sys, job.id, 1, "", &e),
        }
    }

    /// An instruction without a file: (code, stdout, stderr).
    fn run(&mut self, sys: &mut dyn Sys, job: &Job) -> (i32, String, String) {
        let ok = |s: String| (0, s, String::new());
        let fail = |s: &str| (1, String::new(), String::from(s));
        match job.op.as_str() {
            "info" => ok(info(sys)),
            "reboot" => {
                self.after = Some(After::Reboot);
                ok(String::from("{}"))
            }
            "poweroff" => {
                self.after = Some(After::Poweroff);
                ok(String::from("{}"))
            }
            "confirm" => match sys.admin().map(|a| a.confirm_boot()) {
                Some(true) => ok(String::from("{}")),
                _ => fail("nothing to confirm"),
            },
            "module-remove" => {
                let Some(name) = arg_str(job, "name") else { return fail("no name") };
                if name == "panel" {
                    return fail("the panel app is not removed by the panel");
                }
                let kind = arg_str(job, "kind").and_then(ModuleKind::parse);
                match sys.admin().map(|a| a.module_remove(name, kind)) {
                    Some(true) => ok(String::from("{}")),
                    _ => fail("no such module"),
                }
            }
            "module-switch" => {
                let (Some(name), Some(kind)) = (arg_str(job, "name"), arg_str(job, "kind").and_then(ModuleKind::parse)) else { return fail("name and kind (native or wasm)") };
                match sys.admin().map(|a| a.module_switch(name, kind)) {
                    Some(Ok(())) => ok(String::from("{}")),
                    Some(Err(e)) => fail(&e),
                    None => fail("not permitted"),
                }
            }
            "module-config" => {
                let (Some(name), Some(key)) = (arg_str(job, "name"), arg_str(job, "key")) else { return fail("name and key") };
                let value = arg(job, "value").and_then(Json::str);
                match sys.admin().map(|a| a.module_config_set(name, key, value)) {
                    Some(Ok(())) => ok(String::from("{}")),
                    Some(Err(e)) => fail(&e),
                    None => fail("not permitted"),
                }
            }
            "net" => match self.net(sys, job) {
                Ok(()) => ok(format!("{{\"confirm_within\":{NET_CONFIRM_S}}}")),
                Err(e) => fail(&e),
            },
            _ => fail("unknown op"),
        }
    }

    /// `net`: {nic?, ip, mask, gw?, mtu?, save?} applied now, kept once the
    /// panel is reached again (else reverted by itself).
    fn net(&mut self, sys: &mut dyn Sys, job: &Job) -> Result<(), String> {
        let nic = arg_str(job, "nic").unwrap_or("nic0");
        let ip = arg_str(job, "ip").ok_or("no ip")?;
        let (ip, mask) = match arg_str(job, "mask").and_then(parse_ip) {
            Some(m) => (parse_ip(ip).ok_or("bad ip")?, m),
            None => parse_cidr(ip).ok_or("bad ip")?,
        };
        let gw = arg_str(job, "gw").map(|g| parse_ip(g).ok_or("bad gw")).transpose()?.unwrap_or(0);
        let mut cmds = alloc::vec![format!("ip {nic} {}/{} {}", IpFmt(ip), mask.count_ones(), IpFmt(gw))];
        if let Some(m) = arg(job, "mtu").and_then(Json::u64) {
            cmds.push(format!("mtu {nic} {m}"));
        }
        let save = arg(job, "save").and_then(Json::bool).unwrap_or(false);
        let a = sys.admin().ok_or("not permitted")?;
        let mut conf = a.net_running();
        for c in &cmds {
            let w: Vec<&str> = c.split_whitespace().collect();
            let r = match w.as_slice() {
                ["ip", rest @ ..] => rustros_util::netcmd::edit_ip(&mut conf, rest),
                ["mtu", rest @ ..] => rustros_util::netcmd::edit_mtu(&mut conf, rest),
                _ => Ok(()),
            };
            r.map_err(|e| String::from(e.trim_end()))?;
        }
        a.net_set_candidate(Some(conf));
        a.net_apply(NET_CONFIRM_S)?;
        self.net_pending = Some(save);
        Ok(())
    }

    fn metrics(&self, sys: &mut dyn Sys) -> String {
        let up = sys.now_ms() / 1000;
        let mut o = format!("{{\"seconds\":60,\"uptime\":{up}");
        if let Some(a) = sys.admin() {
            let (rx, tx) = a.nic_bytes().iter().fold((0u64, 0u64), |s, b| (s.0 + b.0, s.1 + b.1));
            o += &format!(",\"cpu_pct\":{},\"rx_bytes\":{rx},\"tx_bytes\":{tx}", a.cpu_pct());
        }
        if let Some(s) = sys.kv().and_then(|k| k.storage_info()) {
            o += &format!(",\"disk_total\":{},\"disk_used\":{}", s.partition_bytes, s.live_bytes);
        }
        o.push('}');
        o
    }

    fn print_claim(&mut self, sys: &mut dyn Sys, now: u64) {
        let Some((code, _, exp)) = &self.claim else { return };
        if self.printed_at != 0 && now - self.printed_at < REPRINT_MS {
            return;
        }
        self.printed_at = now.max(1);
        let left = exp.saturating_sub(sys.unix_time()) / 60;
        let panel = self.url.as_ref().map(|u| u.host.clone()).unwrap_or_default();
        say!(sys, "\npanel: *** claim this machine in the panel ({}) with the code  {}  (valid {} more minutes) ***\n\n", panel, code, left);
    }
}

/// `info`: what the panel shows of this machine.
fn info(sys: &mut dyn Sys) -> String {
    let mut o = format!("{{\"build\":{},\"arch\":\"{ARCH}\",\"uptime\":{}", quote(BUILD), sys.now_ms() / 1000);
    if let Some(u) = sys.update_info() {
        o += &format!(",\"slot\":\"{}\",\"trial\":{},\"unstable_boots\":{}", u.slot, u.trial, u.unstable_boots);
    }
    o += ",\"net\":[";
    if let Some(net) = sys.net() {
        let mut first = true;
        for i in 0..net.nic_count() {
            let Some(n) = net.nic_info(i) else { continue };
            let extra: Vec<String> = net.extra_addrs(i).iter().map(|a| quote(&format!("{}", IpFmt(*a)))).collect();
            o += &format!(
                "{}{{\"nic\":{},\"ip\":\"{}\",\"mask\":\"{}\",\"gw\":\"{}\",\"mtu\":{},\"extra\":[{}]}}",
                if first { "" } else { "," },
                quote(&net.nic_name(i)),
                IpFmt(n.ip),
                IpFmt(n.mask),
                IpFmt(n.gw),
                n.mtu,
                extra.join(",")
            );
            first = false;
        }
    }
    o.push(']');
    if let Some(s) = sys.kv().and_then(|k| k.storage_info()) {
        o += &format!(",\"storage\":{{\"total\":{},\"used\":{}}}", s.partition_bytes, s.live_bytes);
    }
    o += ",\"modules\":[";
    if let Some(a) = sys.admin() {
        let list: Vec<String> = a
            .module_list()
            .iter()
            .map(|m| {
                format!(
                    "{{\"name\":{},\"running\":{},\"preferred\":\"{}\",\"native\":{},\"wasm\":{},\"native_off\":{},\"state\":{}}}",
                    quote(&m.name),
                    m.running.map_or(String::from("null"), |k| format!("\"{}\"", k.as_str())),
                    m.preferred.as_str(),
                    m.native_bytes.is_some(),
                    m.wasm_bytes.is_some(),
                    m.native_off.as_deref().map_or(String::from("null"), quote),
                    quote(&m.state)
                )
            })
            .collect();
        o += &list.join(",");
    }
    o.push(']');
    o += &format!(",\"crash\":{}}}", sys.last_crash().as_deref().map_or(String::from("null"), quote));
    o
}

/// The settings, for user interfaces (`Module::params`).
const PARAMS: &[Param] = &[
    Param { key: "url", kind: "text", default: "", help: "the panel, https://host[:port] (default: rustros.panel= on the kernel command line)" },
    Param { key: "ca", kind: "text", default: "", help: "also trust this CA certificate, PEM (a private panel)" },
    Param { key: "name", kind: "text", default: "rustros-<MAC>", help: "the name this machine asks for" },
    Param { key: "dns", kind: "address", default: "1.1.1.1", help: "resolver for the panel's name" },
];

impl Module for Panel {
    fn name(&self) -> &'static str {
        "panel"
    }

    fn params(&self) -> &'static [Param] {
        PARAMS
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::ADMIN
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        tls::set_time(sys.unix_time());
        let mut seed = [0u8; 32];
        for c in seed.chunks_mut(8) {
            c.copy_from_slice(&sys.random().to_le_bytes());
        }
        tls::seed(seed);
        self.load(sys);
        self.load_node(sys);
        match &self.node {
            Some(n) => say!(sys, "panel: server {} (last job {})\n", n.server, n.last_job),
            None => say!(sys, "panel: not claimed yet (machine {})\n", self.machine_id),
        }
        self.reload_at = sys.now_ms() + RELOAD_MS;
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let now = sys.now_ms();
        if now >= self.reload_at {
            tls::set_time(sys.unix_time());
            self.load(sys);
            self.reload_at = now + RELOAD_MS;
        }
        self.print_claim(sys, now);
        if let Some((mut call, purpose)) = self.call.take() {
            let Some(net) = sys.net() else { return };
            match call.poll(net, now) {
                None => self.call = Some((call, purpose)),
                Some(r) => self.done(sys, purpose, r),
            }
            return;
        }
        self.next_call(sys, now);
    }

    fn status(&self) -> String {
        let state = match (&self.node, &self.claim, &self.url) {
            (_, _, None) => String::from("no panel set"),
            (Some(n), _, _) => format!("server {}, last job {}", n.server, n.last_job),
            (None, Some((c, _, _)), _) => format!("waiting to be claimed with code {c}"),
            (None, None, _) => String::from("asking for a claim code"),
        };
        if self.last_error.is_empty() { state } else { format!("{state}; {}", self.last_error) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// panel-node's shared vectors (testdata/node-vectors.json): the panel's
    /// test key, and a job it signed for server 12.
    const PUBLIC: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const JOB: &str = "eyJleHAiOjE4MDAwMDAwNjAsImlkIjoxNzkyMjAyMDQwOTg4NzA4NDYzLCJzY3JpcHQiOiJlY2hvIGRvbmU9MVxuIiwic2VydmVyIjoxMn0.kRnyAF7_R5jqN1W7eh50qTSq5D0YX2M9H1MrdRW4WkrM85O5SDUH-ra1D8WXjiaiqcUJg-743nh6cGZuHSLiBA";

    #[test]
    fn jobs_are_checked() {
        if PUBLIC.is_empty() {
            return;
        }
        let key: [u8; 32] = rustros_util::base64::decode(PUBLIC).unwrap().try_into().unwrap();
        // the vector carries a script: verified, then refused for it
        assert_eq!(verify(JOB, &key, 12, 0, 1_800_000_000).err().as_deref(), Some("scripts are not run here"));
        assert!(verify(JOB, &key, 13, 0, 1_800_000_000).unwrap_err().contains("server 12's"));
        assert!(verify(JOB, &key, 12, 0, 1_900_000_000).unwrap_err().contains("run out"));
        assert!(verify(JOB, &key, 12, u64::MAX, 1_800_000_000).unwrap_err().contains("not after"));
        let mut bad = String::from(JOB);
        bad.pop();
        bad.push('A');
        assert!(verify(&bad, &key, 12, 0, 1_800_000_000).is_err());
    }
}
