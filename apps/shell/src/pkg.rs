//! `pkg`: apps (and the kernel) from the release repository, as the panel
//! installs them. The manifest is trusted only with the release key's
//! Ed25519 signature; every file only with the SHA-256 the manifest gives.
//!
//! ```text
//! pkg update               fetch and check the manifest (kept for the others)
//! pkg list                 the apps: installed, available, which to upgrade
//! pkg info <app>
//! pkg install <app>...     install (native x86_64; wasm where there is no native)
//! pkg upgrade              every installed app with a newer version
//! pkg upgrade kernel       the kernel into the spare slot, for a trial boot
//! pkg remove <app>
//! ```
//!
//! `cfg shell repo <url of latest.json>` and `cfg shell repo_key <base64>`
//! point it elsewhere (a test repository).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{ModuleKind, Sys, say};
use rustros_util::json::Json;

use crate::curl::{Curl, Request};

pub const USAGE: &str = "usage: pkg update | list | info <app> | install <app>... | upgrade [kernel] | remove <app>\n";
const REPO: &str = "https://rustros.com/releases/latest.json";
/// The release key (its public half; the private one signs releases).
const RELEASE_KEY: &str = "5JddaWkdvKjJte+tGwE9kn6f33EOUj2ixVBBOj45s38=";
const ARCH: &str = "x86_64";
const MAX_MODULE: usize = 1 << 20;
const MAX_KERNEL: usize = 256 * 1024;

enum Step {
    /// the manifest, then its signature
    Manifest,
    Signature(Vec<u8>),
    /// downloading the next of `todo`
    Fetch,
}

/// One thing to install: (name, url, sha256 hex, size), name "kernel" for the kernel.
type Item = (String, String, String, u64);

pub struct Pkg {
    step: Step,
    curl: Option<Curl>,
    todo: Vec<Item>,
    /// after the update: what to do (the command's own work)
    then: Then,
    done: usize,
}

#[derive(Clone)]
enum Then {
    Nothing,
    Install(Vec<String>),
    Upgrade,
    Kernel,
}

fn cfg(sys: &mut dyn Sys, k: &str) -> Option<String> {
    let v = sys.kv()?.get(&format!("cfg/{k}"))?;
    String::from_utf8(v).ok().map(|s| String::from(s.trim())).filter(|s| !s.is_empty())
}

fn manifest(sys: &mut dyn Sys) -> Option<Json> {
    let b = sys.kv()?.get("pkg/manifest")?;
    Json::parse(&b)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// The download of an app for this machine: native for its architecture, else wasm.
fn file_of(m: &Json, name: &str) -> Option<Item> {
    let e = m.path(&["modules", name])?;
    let f = e.path(&["native", ARCH]).or_else(|| e.get("wasm"))?;
    Some((String::from(name), String::from(f.get("url")?.str()?), String::from(f.get("sha256")?.str()?), f.get("size")?.u64()?))
}

fn installed(sys: &mut dyn Sys) -> Vec<(String, String)> {
    sys.admin().map(|a| a.module_list().into_iter().map(|m| (m.name, m.version)).collect()).unwrap_or_default()
}

fn newer(a: &str, b: &str) -> bool {
    let p = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    p(a) > p(b)
}

impl Pkg {
    pub fn start(sys: &mut dyn Sys, args: &[&str]) -> Result<Option<Pkg>, String> {
        let then = match args {
            ["update"] => Then::Nothing,
            ["list"] => {
                list(sys)?;
                return Ok(None);
            }
            ["info", name] => {
                info(sys, name)?;
                return Ok(None);
            }
            ["remove", name] => {
                if *name == "panel" || *name == "shell" {
                    return Err(format!("pkg: {name} is not removed this way (mod rm {name} if you mean it)\n"));
                }
                return match sys.admin().map(|a| a.module_remove(name, None)) {
                    Some(true) => {
                        say!(sys, "pkg: {} removed\n", name);
                        Ok(None)
                    }
                    _ => Err(format!("pkg: {name} is not installed\n")),
                };
            }
            ["install", names @ ..] if !names.is_empty() => Then::Install(names.iter().map(|n| String::from(*n)).collect()),
            ["upgrade"] => Then::Upgrade,
            ["upgrade", "kernel"] => Then::Kernel,
            _ => return Err(String::from(USAGE)),
        };
        // every command that installs reads the manifest afresh
        let mut p = Pkg { step: Step::Manifest, curl: None, todo: Vec::new(), then, done: 0 };
        let url = cfg(sys, "repo").unwrap_or_else(|| String::from(REPO));
        say!(sys, "pkg: reading {}\n", url);
        p.curl = Some(get(sys, &url)?);
        Ok(Some(p))
    }

    pub fn abort(&mut self, sys: &mut dyn Sys) {
        if let Some(c) = self.curl.as_mut() {
            c.abort(sys);
        }
    }

    /// True once finished.
    pub fn poll(&mut self, sys: &mut dyn Sys) -> bool {
        let Some(c) = self.curl.as_mut() else { return true };
        if !c.poll(sys) {
            return false;
        }
        let r = c.answer();
        self.curl = None;
        let (status, body) = match r {
            Ok(x) => x,
            Err(e) => {
                say!(sys, "pkg: {}\n", e.trim_start_matches("curl: "));
                return true;
            }
        };
        if status != 200 {
            say!(sys, "pkg: the repository said {}\n", status);
            return true;
        }
        match core::mem::replace(&mut self.step, Step::Fetch) {
            Step::Manifest => {
                let url = format!("{}.sig", cfg(sys, "repo").unwrap_or_else(|| String::from(REPO)));
                match get(sys, &url) {
                    Ok(c) => {
                        self.curl = Some(c);
                        self.step = Step::Signature(body);
                        false
                    }
                    Err(e) => {
                        say!(sys, "{}", e);
                        true
                    }
                }
            }
            Step::Signature(m) => {
                let key = cfg(sys, "repo_key").unwrap_or_else(|| String::from(RELEASE_KEY));
                let key: Option<[u8; 32]> = rustros_util::base64::decode(&key).and_then(|k| k.try_into().ok());
                let sig = rustros_util::base64::decode(String::from_utf8_lossy(&body).trim());
                let ok = matches!((&key, &sig), (Some(k), Some(s)) if tls::ed25519_verify(k, &m, s));
                if !ok {
                    say!(sys, "pkg: the manifest's signature does not check out: nothing changed\n");
                    return true;
                }
                let Some(j) = Json::parse(&m) else {
                    say!(sys, "pkg: the manifest cannot be read\n");
                    return true;
                };
                let version = j.get("version").and_then(Json::str).unwrap_or("?");
                say!(sys, "pkg: release {} ({} apps), signature checked\n", version, j.get("modules").map(|m| if let Json::Obj(o) = m { o.len() } else { 0 }).unwrap_or(0));
                if sys.kv().is_none_or(|kv| kv.put("pkg/manifest", &m).is_err()) {
                    say!(sys, "pkg: (the manifest could not be kept)\n");
                }
                self.plan(sys, &j)
            }
            Step::Fetch => {
                let item = self.todo.remove(0);
                let want = unhex(&item.2);
                if want.as_deref() != Some(&rustros_util::sha256::Sha256::digest(&body)[..]) || body.len() as u64 != item.3 {
                    say!(sys, "pkg: {}: the download does not match the manifest (SHA-256): not installed\n", item.0);
                } else if item.0 == "kernel" {
                    let ok = sys.admin().is_some_and(|a| a.update_begin() && a.update_write(&body) && a.update_commit());
                    if ok {
                        say!(sys, "pkg: the new kernel is in the spare slot: reboot to try it, then confirm (unconfirmed, the old one comes back)\n");
                    } else {
                        say!(sys, "pkg: writing the kernel failed\n");
                    }
                } else {
                    match sys.admin().map(|a| a.module_install(&item.0, &body)) {
                        Some(Ok(k)) => {
                            self.done += 1;
                            say!(sys, "pkg: {} installed ({}, {} KiB)\n", item.0, if k == ModuleKind::Native { "native" } else { "wasm" }, body.len() / 1024);
                        }
                        Some(Err(e)) => say!(sys, "pkg: {}: {}\n", item.0, e),
                        None => say!(sys, "pkg: not permitted\n"),
                    }
                }
                self.next(sys)
            }
        }
    }

    /// What the command does with the checked manifest.
    fn plan(&mut self, sys: &mut dyn Sys, m: &Json) -> bool {
        let have = installed(sys);
        match self.then.clone() {
            Then::Nothing => return true,
            Then::Install(names) => {
                for n in names {
                    match file_of(m, &n) {
                        Some(i) if i.3 as usize <= MAX_MODULE => self.todo.push(i),
                        Some(_) => say!(sys, "pkg: {}: too big for a module\n", n),
                        None => say!(sys, "pkg: no app {} in this release\n", n),
                    }
                }
            }
            Then::Upgrade => {
                for (name, v) in &have {
                    let Some(e) = m.path(&["modules", name]) else { continue };
                    let nv = e.get("version").and_then(Json::str).unwrap_or("");
                    if newer(nv, v) {
                        if let Some(i) = file_of(m, name) {
                            say!(sys, "pkg: {} {} -> {}\n", name, if v.is_empty() { "?" } else { v.as_str() }, nv);
                            self.todo.push(i);
                        }
                    }
                }
                if self.todo.is_empty() {
                    say!(sys, "pkg: everything installed is up to date\n");
                }
            }
            Then::Kernel => {
                let running = String::from(sys.kernel_version());
                let k = m.path(&["kernel", ARCH]);
                let nv = m.path(&["kernel", "version"]).and_then(Json::str).unwrap_or("");
                match k {
                    Some(k) if newer(nv, &running) => {
                        let (Some(url), Some(sha), Some(size)) = (k.get("url").and_then(Json::str), k.get("sha256").and_then(Json::str), k.get("size").and_then(Json::u64)) else {
                            say!(sys, "pkg: the manifest's kernel entry is incomplete\n");
                            return true;
                        };
                        if size as usize > MAX_KERNEL {
                            say!(sys, "pkg: the kernel is too big for a slot\n");
                            return true;
                        }
                        say!(sys, "pkg: kernel {} -> {}\n", running, nv);
                        self.todo.push((String::from("kernel"), String::from(url), String::from(sha), size));
                    }
                    Some(_) => say!(sys, "pkg: the kernel is up to date ({})\n", running),
                    None => say!(sys, "pkg: no kernel for {} in this release\n", ARCH),
                }
            }
        }
        self.next(sys)
    }

    fn next(&mut self, sys: &mut dyn Sys) -> bool {
        let Some(item) = self.todo.first() else {
            if self.done > 1 {
                say!(sys, "pkg: {} apps installed\n", self.done);
            }
            return true;
        };
        let url = item.1.clone();
        match get(sys, &url) {
            Ok(c) => {
                self.curl = Some(c);
                false
            }
            Err(e) => {
                say!(sys, "{}", e);
                true
            }
        }
    }
}

fn get(sys: &mut dyn Sys, url: &str) -> Result<Curl, String> {
    let headers = alloc::vec![format!("User-Agent: rustros-pkg/{}", rustros_api::BUILD)];
    Curl::request(sys, Request { method: "GET", url, headers, body: None, src: 0, max_secs: 120 }).map_err(|e| format!("pkg: {}", e.trim_start_matches("curl: ")))
}

fn list(sys: &mut dyn Sys) -> Result<(), String> {
    let m = manifest(sys).ok_or_else(|| String::from("pkg: no manifest yet (pkg update)\n"))?;
    let have = installed(sys);
    say!(sys, "release {}\n", m.get("version").and_then(Json::str).unwrap_or("?"));
    say!(sys, "  {:<11} {:<14} {:<14} {}\n", "app", "installed", "available", "");
    let Some(Json::Obj(mods)) = m.get("modules") else { return Ok(()) };
    for (name, e) in mods {
        let nv = e.get("version").and_then(Json::str).unwrap_or("");
        let v = have.iter().find(|h| &h.0 == name).map(|h| h.1.as_str());
        let note = match v {
            None => "",
            Some(v) if newer(nv, v) => "upgrade",
            Some(_) => "",
        };
        say!(sys, "  {:<11} {:<14} {:<14} {}\n", name, v.map(|v| if v.is_empty() { "?" } else { v }).unwrap_or("-"), nv, note);
    }
    let running = String::from(sys.kernel_version());
    say!(sys, "  {:<11} {:<14} {:<14} {}\n", "kernel", running, m.path(&["kernel", "version"]).and_then(Json::str).unwrap_or("-"), "");
    Ok(())
}

fn info(sys: &mut dyn Sys, name: &str) -> Result<(), String> {
    let m = manifest(sys).ok_or_else(|| String::from("pkg: no manifest yet (pkg update)\n"))?;
    let e = m.path(&["modules", name]).ok_or_else(|| format!("pkg: no app {name} in this release\n"))?;
    say!(sys, "{} {}: {}\n", name, e.get("version").and_then(Json::str).unwrap_or("?"), e.get("description").and_then(Json::str).unwrap_or(""));
    if let Some((_, url, sha, size)) = file_of(&m, name) {
        say!(sys, "  {} ({} KiB)\n  sha256 {}\n", url, size / 1024, sha);
    }
    Ok(())
}
