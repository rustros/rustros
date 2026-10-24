//! The installed modules' bookkeeping (a boot module's service,
//! `rustros_api::module::ModManager`): native modules and WebAssembly
//! instances, next to the built-in apps. The kernel loads and runs them.
//!
//! An installed module may be stored in both forms under `sys/app/<name>/`:
//! `native` (module ELF), `wasm`, `prefer` (which form to run),
//! `native-off` (the native form crashed the system; set at boot from the
//! crash record, so the module falls back to its WebAssembly form) and
//! `role` (`service`: it replaces services of the boot image, started
//! before anything else; `fs`: a file system driver, started next). Its settings are
//! `<name>/cfg/<key>`. Changes are queued and applied by the kernel's main
//! loop between passes.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::module::{ModHost, ModManager, ModOp, ROLE_FS, ROLE_SERVICE, RUNTIME};
use rustros_api::{ModuleInfo, ModuleKind};
use rustros_util::snap::{Bad, R, W};

const PREFIX: &str = "sys/app/";
/// Old location of WebAssembly modules (before native modules existed).
const LEGACY_WASM: &str = "sys/wasm/";
/// What a module is besides an app (`ROLE_SERVICE`, `ROLE_FS`).
const ROLE: &str = "role";
/// The state handed to the next version (hot replacement).
const TAG: &[u8; 4] = b"MODM";

#[derive(Default)]
pub struct Manager {
    ops: VecDeque<ModOp>,
}

impl Manager {
    pub fn new() -> Manager {
        Manager::default()
    }

    fn queued(&self, name: &str) -> bool {
        self.ops.iter().any(|o| matches!(o, ModOp::Start(n) | ModOp::Stop(n) if n == name))
    }
}

fn key(name: &str, part: &str) -> String {
    format!("{PREFIX}{name}/{part}")
}

fn get(h: &mut dyn ModHost, key: &str) -> Option<Vec<u8>> {
    h.store()?.kv_get(key).map(|v| v.to_vec())
}

fn put(h: &mut dyn ModHost, key: &str, value: &[u8]) -> Result<(), String> {
    let s = h.store().ok_or_else(|| String::from("no storage for applications"))?;
    s.kv_put(key, value).map_err(|e| format!("cannot store: {e:?}"))
}

fn delete(h: &mut dyn ModHost, key: &str) -> bool {
    h.store().is_some_and(|s| s.kv_delete(key).unwrap_or(false))
}

fn installed(h: &mut dyn ModHost) -> Vec<String> {
    let Some(s) = h.store() else { return Vec::new() };
    let mut names: Vec<String> = s
        .kv_keys(PREFIX)
        .iter()
        .filter_map(|key| key[PREFIX.len()..].split_once('/').map(|(n, _)| String::from(n)))
        .collect();
    names.dedup();
    names
}

fn other(kind: ModuleKind) -> ModuleKind {
    match kind {
        ModuleKind::Native => ModuleKind::Wasm,
        ModuleKind::Wasm => ModuleKind::Native,
    }
}

fn preferred(h: &mut dyn ModHost, name: &str) -> ModuleKind {
    get(h, &key(name, "prefer")).and_then(|p| ModuleKind::parse(core::str::from_utf8(&p).ok()?)).unwrap_or(ModuleKind::Native)
}

fn check_name(h: &dyn ModHost, name: &str) -> Result<(), String> {
    let valid = (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name != "sys";
    if !valid {
        return Err(String::from("name must be 1-32 chars of a-z 0-9 - _ (and not \"sys\")"));
    }
    if h.is_builtin(name) {
        return Err(format!("\"{name}\" is a built-in app"));
    }
    Ok(())
}

impl ModManager for Manager {
    fn install(&mut self, h: &mut dyn ModHost, name: &str, image: &[u8]) -> Result<ModuleKind, String> {
        check_name(h, name)?;
        let kind = h.check(image)?;
        put(h, &key(name, kind.as_str()), image)?;
        put(h, &key(name, "prefer"), kind.as_str().as_bytes())?;
        if kind == ModuleKind::Native {
            delete(h, &key(name, "native-off"));
            match h.role(image) {
                Some(r) => put(h, &key(name, ROLE), r.as_bytes())?,
                None => {
                    delete(h, &key(name, ROLE));
                }
            }
        }
        self.ops.push_back(ModOp::Start(String::from(name)));
        Ok(kind)
    }

    fn remove(&mut self, h: &mut dyn ModHost, name: &str, kind: Option<ModuleKind>) -> bool {
        match kind {
            None => {
                let mut existed = false;
                for part in ["native", "wasm", "prefer", "native-off", ROLE] {
                    existed |= delete(h, &key(name, part));
                }
                if existed {
                    self.ops.push_back(ModOp::Stop(String::from(name)));
                }
                existed
            }
            Some(kind) => {
                if !delete(h, &key(name, kind.as_str())) {
                    return false;
                }
                if kind == ModuleKind::Native {
                    delete(h, &key(name, "native-off"));
                }
                if preferred(h, name) == kind {
                    let _ = put(h, &key(name, "prefer"), other(kind).as_str().as_bytes());
                }
                // keeps running in the other form, if there is one
                self.ops.push_back(ModOp::Start(String::from(name)));
                true
            }
        }
    }

    fn switch(&mut self, h: &mut dyn ModHost, name: &str, kind: ModuleKind) -> Result<(), String> {
        if get(h, &key(name, kind.as_str())).is_none() {
            return Err(format!("no {} image of \"{name}\" is installed", kind.as_str()));
        }
        put(h, &key(name, "prefer"), kind.as_str().as_bytes())?;
        if kind == ModuleKind::Native {
            delete(h, &key(name, "native-off"));
        }
        self.ops.push_back(ModOp::Start(String::from(name)));
        Ok(())
    }

    fn list(&self, h: &mut dyn ModHost, mut running: Vec<ModuleInfo>) -> Vec<ModuleInfo> {
        installed(h)
            .into_iter()
            .map(|name| {
                let size = |h: &mut dyn ModHost, part| get(h, &key(&name, part)).map(|v| v.len());
                let (native_bytes, wasm_bytes) = (size(h, "native"), size(h, "wasm"));
                let preferred = preferred(h, &name);
                let native_off = get(h, &key(&name, "native-off")).map(|v| String::from_utf8_lossy(&v).into_owned());
                let st = running.iter().position(|s| s.name == name).map(|i| running.swap_remove(i));
                match st {
                    Some(st) => ModuleInfo { native_bytes, wasm_bytes, preferred, native_off, ..st },
                    None => ModuleInfo {
                        name,
                        native_bytes,
                        wasm_bytes,
                        preferred,
                        running: None,
                        state: String::from("not running"),
                        restarts: 0,
                        native_off,
                        params: Vec::new(),
                        version: String::new(),
                    },
                }
            })
            .collect()
    }

    fn config(&self, h: &mut dyn ModHost, name: &str) -> Vec<(String, String)> {
        let prefix = format!("{name}/cfg/");
        let Some(b) = h.store() else { return Vec::new() };
        b.kv_keys(&prefix)
            .into_iter()
            .map(|k| (String::from(&k[prefix.len()..]), String::from_utf8_lossy(b.kv_get(&k).unwrap_or(b"")).into_owned()))
            .collect()
    }

    fn config_set(&mut self, h: &mut dyn ModHost, name: &str, key: &str, value: Option<&str>) -> Result<(), String> {
        let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_graphic() && c != b'/');
        if !ok(name) || !ok(key) {
            return Err(String::from("bad module or key name"));
        }
        let k = format!("{name}/cfg/{key}");
        let b = h.store().ok_or_else(|| String::from("no storage"))?;
        match value {
            Some(v) => b.kv_put(&k, v.as_bytes()).map_err(|e| format!("{e:?}")),
            None => b.kv_delete(&k).map(|_| ()).map_err(|e| format!("{e:?}")),
        }
    }

    /// Switch off a native module that crashed the last boot, move old
    /// WebAssembly modules to the new layout, then queue every installed
    /// module: file system drivers first (apps find their files mounted),
    /// then the runtime (WebAssembly modules need it).
    fn boot(&mut self, h: &mut dyn ModHost) {
        let crashed = h.store().and_then(|b| b.env("crash_app")).map(String::from);
        if let Some(name) = crashed {
            let why = h.store().and_then(|b| b.env("last_panic")).map(String::from).unwrap_or_default();
            if put(h, &key(&name, "native-off"), why.as_bytes()).is_ok() {
                h.log(&format!("modules: native {} crashed the last boot; switched off (its WebAssembly form runs instead, if installed)", name));
            }
            if let Some(b) = h.store() {
                b.env_set(&[("crash_app", "")]);
            }
        }
        let legacy: Vec<String> = h.store().map(|s| s.kv_keys(LEGACY_WASM)).unwrap_or_default();
        for old in legacy {
            let name = &old[LEGACY_WASM.len()..];
            if let Some(image) = get(h, &old) {
                if put(h, &key(name, "wasm"), &image).is_ok() && put(h, &key(name, "prefer"), b"wasm").is_ok() {
                    delete(h, &old);
                }
            }
        }
        // what the image carries is installed first, so it starts in order too
        install_bundled(self, h);
        self.ops.clear();
        let mut order: Vec<(u8, bool, String)> = Vec::new();
        for n in installed(h) {
            let first = match get(h, &key(&n, ROLE)).as_deref() {
                Some(r) if r == ROLE_SERVICE.as_bytes() => 0,
                Some(r) if r == ROLE_FS.as_bytes() => 1,
                _ => 2,
            };
            order.push((first, n != RUNTIME, n));
        }
        rustros_util::sort::sort(&mut order);
        self.ops.extend(order.into_iter().map(|(_, _, n)| ModOp::Start(n)));
    }

    fn next_op(&mut self) -> Option<ModOp> {
        self.ops.pop_front()
    }

    /// The preferred form if stored (and, for native, not switched off),
    /// else the other.
    fn choose(&mut self, h: &mut dyn ModHost, name: &str) -> Option<(ModuleKind, Vec<u8>)> {
        let first = preferred(h, name);
        for kind in [first, other(first)] {
            if kind == ModuleKind::Native && get(h, &key(name, "native-off")).is_some() {
                if name == RUNTIME {
                    h.log(&format!("modules: the {} runtime is switched off after a crash", RUNTIME));
                }
                continue;
            }
            if kind == ModuleKind::Wasm && (!h.has_runtime() || name == RUNTIME) {
                continue;
            }
            if let Some(image) = get(h, &key(name, kind.as_str())) {
                return Some((kind, image));
            }
        }
        None
    }

    fn is_filesystem(&mut self, h: &mut dyn ModHost, name: &str) {
        if get(h, &key(name, ROLE)).as_deref() != Some(ROLE_FS.as_bytes()) {
            let _ = put(h, &key(name, ROLE), ROLE_FS.as_bytes());
        }
    }

    fn state_version(&self) -> u32 {
        1
    }

    /// Format 1: the queued operations (0: start, 1: stop; the name).
    fn save_state(&self, version: u32) -> Option<Vec<u8>> {
        if version != 1 {
            return None;
        }
        let mut w = W::new(TAG, 1);
        w.n(self.ops.len());
        for op in &self.ops {
            let (ModOp::Start(n) | ModOp::Stop(n)) = op;
            w.u8(matches!(op, ModOp::Stop(_)) as u8);
            w.bytes(n.as_bytes());
        }
        Some(w.0)
    }

    fn load_state(&mut self, state: &[u8]) -> Result<(), String> {
        let (mut r, v) = R::new(state, TAG)?;
        if v != 1 {
            return Err(format!("state format {v}: this version reads 1"));
        }
        let ops = r.list(|r| {
            let stop = r.bool()?;
            let n = String::from_utf8(r.bytes()?).map_err(|_| Bad)?;
            Ok(if stop { ModOp::Stop(n) } else { ModOp::Start(n) })
        })?;
        r.end()?;
        self.ops = ops.into();
        Ok(())
    }

    fn runtime_changed(&mut self, h: &mut dyn ModHost, mut restart: Vec<String>) {
        // every installed module that is not running (and not about to be
        // started anyway) gets another chance on the new runtime
        for n in installed(h) {
            if n != RUNTIME && !h.is_running(&n) {
                restart.push(n);
            }
        }
        restart.retain(|n| !self.queued(n));
        rustros_util::sort::sort(&mut restart);
        restart.dedup();
        self.ops.extend(restart.into_iter().map(ModOp::Start));
    }
}

/// The modules the boot image carries (`rustros.bundle=<lba>`, written by
/// mkimg after the image): each installed once, at the first boot that
/// finds it neither installed nor installed from the bundle before (so one
/// the owner removed stays removed).
fn install_bundled(m: &mut Manager, h: &mut dyn ModHost) {
    const MAGIC: &[u8; 8] = b"RRSBNDL1";
    const HEAD: usize = 4096;
    const ENTRY: usize = 80;
    let Some(lba) = rustros_util::wire::cmdline_get(h.cmdline(), "rustros.bundle").and_then(|v| v.parse::<u64>().ok()) else { return };
    let mut head = alloc::vec![0u8; HEAD];
    if !h.store().is_some_and(|b| b.boot_area_read(lba, &mut head)) || &head[..8] != MAGIC {
        h.log(&format!("modules: no bundle at LBA {}", lba));
        return;
    }
    let count = (u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize).min((HEAD - 16) / ENTRY);
    let have = installed(h);
    for i in 0..count {
        let e = &head[16 + i * ENTRY..16 + (i + 1) * ENTRY];
        let name = String::from(String::from_utf8_lossy(&e[..32]).trim_end_matches('\0'));
        let at = u32::from_le_bytes([e[32], e[33], e[34], e[35]]) as u64;
        let len = u32::from_le_bytes([e[36], e[37], e[38], e[39]]) as usize;
        let sha: [u8; 32] = e[40..72].try_into().unwrap_or([0; 32]);
        let marker = format!("sys/bundle/{name}");
        if name.is_empty() || get(h, &marker).is_some() {
            continue;
        }
        if have.contains(&name) {
            let _ = put(h, &marker, &sha);
            continue;
        }
        let mut data = alloc::vec![0u8; len.div_ceil(512) * 512];
        if !h.store().is_some_and(|b| b.boot_area_read(lba + at, &mut data)) {
            h.log(&format!("modules: bundled {}: unreadable", name));
            continue;
        }
        data.truncate(len);
        if rustros_util::sha256::Sha256::digest(&data) != sha {
            h.log(&format!("modules: bundled {}: damaged (SHA-256), not installed", name));
            continue;
        }
        match m.install(h, &name, &data) {
            Ok(kind) => {
                let _ = put(h, &marker, &sha);
                h.log(&format!("modules: installed {} from the boot image ({}, {} KiB)", name, kind.as_str(), len / 1024));
            }
            Err(e) => h.log(&format!("modules: bundled {}: {}", name, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handover() {
        let mut m = Manager::new();
        m.ops.extend([ModOp::Start(String::from("netstack")), ModOp::Stop(String::from("echo"))]);
        let state = m.save_state(1).unwrap();
        let mut next = Manager::new();
        assert!(next.load_state(&state[..state.len() - 1]).is_err());
        next.load_state(&state).unwrap();
        assert!(matches!(next.next_op(), Some(ModOp::Start(n)) if n == "netstack"));
        assert!(matches!(next.next_op(), Some(ModOp::Stop(n)) if n == "echo"));
        assert!(next.next_op().is_none());
    }
}
