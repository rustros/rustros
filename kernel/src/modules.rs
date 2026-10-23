//! Installed applications: native modules and runtime-hosted (WebAssembly)
//! instances, next to the built-in apps.
//!
//! An installed app may be stored in both forms under `sys/app/<name>/`:
//! `native` (module ELF), `wasm`, `prefer` (which form to run) and
//! `native-off` (the native form crashed the system; set at boot from the
//! crash record, so the app falls back to its WebAssembly form). Changes are
//! queued and applied by the main loop between passes.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rustros_api::module::Export;
use rustros_api::{Module, ModuleInfo, ModuleKind, Caps};

use crate::loader;
use crate::sys::{Ctx, Kernel};
use crate::{Global, arch, kprintln};

const PREFIX: &str = "sys/app/";
/// The WebAssembly runtime is the native module installed under this name.
pub const RUNTIME: &str = "wasm";
/// Old location of WebAssembly modules (before native modules existed).
const LEGACY_WASM: &str = "sys/wasm/";

/// An entry of the app table; the index is the app id.
pub enum Slot {
    Builtin(Box<dyn Module>),
    /// An app from the boot modules' binary (which stays loaded for good).
    Boot(Box<dyn Module>),
    Native(loader::Module),
    /// An instance created by a runtime (WebAssembly).
    Hosted(Box<dyn Module>),
    Empty,
}

impl Slot {
    pub fn app(&mut self) -> Option<&mut dyn Module> {
        match self {
            Slot::Builtin(a) | Slot::Boot(a) | Slot::Hosted(a) => Some(a.as_mut()),
            Slot::Native(m) => match m.export.as_mut() {
                Some(Export::Module(a)) => Some(a.as_mut()),
                _ => None,
            },
            Slot::Empty => None,
        }
    }

    fn kind(&self) -> Option<ModuleKind> {
        match self {
            Slot::Native(_) => Some(ModuleKind::Native),
            Slot::Hosted(_) => Some(ModuleKind::Wasm),
            _ => None,
        }
    }
}

pub enum ModuleOp {
    /// (Re)start the app in its preferred available form.
    Start(String),
    Stop(String),
}

/// Kept by the main loop for `module_list`.
pub struct ModuleStatus {
    pub name: &'static str,
    pub kind: ModuleKind,
    pub state: String,
    pub restarts: u32,
    pub params: Vec<rustros_api::ParamInfo>,
    pub version: &'static str,
}

// ---------------------------------------------------------------- crash attribution

/// The native module being called right now, so a crash can be pinned on it.
static CURRENT_NATIVE: Global<Option<&'static str>> = Global::new(None);

pub fn current_native() -> Option<&'static str> {
    // Safety: single core; written only by the main loop around app calls.
    unsafe { *CURRENT_NATIVE.get() }
}

/// The native module the next calls go into; returns the one before.
pub fn set_current_native(n: Option<&'static str>) -> Option<&'static str> {
    // Safety: as above
    unsafe { core::mem::replace(CURRENT_NATIVE.get(), n) }
}

/// Call into app `id` (with crash attribution and housekeeping afterwards).
pub fn call(k: &mut Kernel, slots: &mut [Slot], id: usize, f: impl FnOnce(&mut dyn Module, &mut Ctx)) {
    // a hosted (WebAssembly) app runs inside the runtime module's code
    let culprit = match slots[id] {
        Slot::Native(_) | Slot::Boot(_) => k.names.get(id).copied(),
        Slot::Hosted(_) => Some(RUNTIME),
        _ => None,
    };
    let Some(app) = slots[id].app() else { return };
    unsafe { *CURRENT_NATIVE.get() = culprit };
    let t = crate::arch::rdtsc();
    f(app, &mut Ctx { k: &mut *k, id });
    k.perf.charge(id, crate::arch::rdtsc() - t);
    unsafe { *CURRENT_NATIVE.get() = None };
    after_call(k, &mut slots[id], id);
}

/// An app that restarted itself loses the sockets it held.
fn after_call(k: &mut Kernel, slot: &mut Slot, id: usize) {
    if let Some(app) = slot.app() {
        if app.take_restart() {
            let (st, mut link) = k.net();
            st.release_owner(id, &mut link);
        }
    }
}

// ---------------------------------------------------------------- storage

fn key(name: &str, part: &str) -> String {
    format!("{PREFIX}{name}/{part}")
}

fn get(k: &Kernel, key: &str) -> Option<Vec<u8>> {
    k.boot.as_ref()?.kv_get(key).map(|v| v.to_vec())
}

fn put(k: &mut Kernel, key: &str, value: &[u8]) -> Result<(), String> {
    let s = k.boot.as_mut().ok_or_else(|| String::from("no storage for applications"))?;
    s.kv_put(key, value).map_err(|e| format!("cannot store: {e:?}"))
}

fn delete(k: &mut Kernel, key: &str) -> bool {
    k.boot.as_mut().is_some_and(|s| s.kv_delete(key).unwrap_or(false))
}

fn installed(k: &Kernel) -> Vec<String> {
    let Some(s) = k.boot.as_ref() else { return Vec::new() };
    let mut names: Vec<String> = s
        .kv_keys(PREFIX)
        .iter()
        .filter_map(|key| key[PREFIX.len()..].split_once('/').map(|(n, _)| String::from(n)))
        .collect();
    names.dedup();
    names
}

fn image_key(kind: ModuleKind) -> &'static str {
    kind.as_str()
}

fn other(kind: ModuleKind) -> ModuleKind {
    match kind {
        ModuleKind::Native => ModuleKind::Wasm,
        ModuleKind::Wasm => ModuleKind::Native,
    }
}

fn preferred(k: &Kernel, name: &str) -> ModuleKind {
    get(k, &key(name, "prefer")).and_then(|p| ModuleKind::parse(core::str::from_utf8(&p).ok()?)).unwrap_or(ModuleKind::Native)
}

fn check_name(k: &Kernel, name: &str) -> Result<(), String> {
    let valid = (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name != "sys";
    if !valid {
        return Err(String::from("name must be 1-32 chars of a-z 0-9 - _ (and not \"sys\")"));
    }
    if k.builtin_names.contains(&name) {
        return Err(format!("\"{name}\" is a built-in app"));
    }
    Ok(())
}

// ---------------------------------------------------------------- admin operations

pub fn install(k: &mut Kernel, name: &str, image: &[u8]) -> Result<ModuleKind, String> {
    check_name(k, name)?;
    let kind = if image.starts_with(b"\x7fELF") {
        loader::check(image)?;
        ModuleKind::Native
    } else if let Some(rt) = k.runtime_ref().filter(|r| r.accepts(image)) {
        rt.validate(image)?;
        ModuleKind::Wasm
    } else if image.starts_with(b"\0asm") {
        return Err(String::from("no WebAssembly runtime in this system"));
    } else {
        return Err(String::from("unknown image format (expected a native module ELF or WebAssembly)"));
    };
    put(k, &key(name, image_key(kind)), image)?;
    put(k, &key(name, "prefer"), kind.as_str().as_bytes())?;
    if kind == ModuleKind::Native {
        delete(k, &key(name, "native-off"));
    }
    k.app_ops.push(ModuleOp::Start(String::from(name)));
    Ok(kind)
}

pub fn remove(k: &mut Kernel, name: &str, kind: Option<ModuleKind>) -> bool {
    match kind {
        None => {
            let mut existed = false;
            for part in ["native", "wasm", "prefer", "native-off"] {
                existed |= delete(k, &key(name, part));
            }
            if existed {
                k.app_ops.push(ModuleOp::Stop(String::from(name)));
            }
            existed
        }
        Some(kind) => {
            if !delete(k, &key(name, image_key(kind))) {
                return false;
            }
            if kind == ModuleKind::Native {
                delete(k, &key(name, "native-off"));
            }
            if preferred(k, name) == kind {
                let _ = put(k, &key(name, "prefer"), other(kind).as_str().as_bytes());
            }
            // keeps running in the other form, if there is one
            k.app_ops.push(ModuleOp::Start(String::from(name)));
            true
        }
    }
}

pub fn switch(k: &mut Kernel, name: &str, kind: ModuleKind) -> Result<(), String> {
    if get(k, &key(name, image_key(kind))).is_none() {
        return Err(format!("no {} image of \"{name}\" is installed", kind.as_str()));
    }
    put(k, &key(name, "prefer"), kind.as_str().as_bytes())?;
    if kind == ModuleKind::Native {
        delete(k, &key(name, "native-off"));
    }
    k.app_ops.push(ModuleOp::Start(String::from(name)));
    Ok(())
}

pub fn list(k: &Kernel) -> Vec<ModuleInfo> {
    installed(k)
        .into_iter()
        .map(|name| {
            let size = |k: &Kernel, part| get(k, &key(&name, part)).map(|v| v.len());
            let (native_bytes, wasm_bytes) = (size(k, "native"), size(k, "wasm"));
            let preferred = preferred(k, &name);
            let native_off = get(k, &key(&name, "native-off")).map(|v| String::from_utf8_lossy(&v).into_owned());
            let st = k.app_status.iter().find(|s| s.name == name);
            ModuleInfo {
                running: st.map(|s| s.kind),
                state: st.map_or_else(|| String::from("not running"), |s| s.state.clone()),
                restarts: st.map_or(0, |s| s.restarts),
                name,
                native_bytes,
                wasm_bytes,
                preferred,
                native_off,
                params: st.map_or_else(Vec::new, |s| s.params.clone()),
                version: String::from(st.map_or("", |s| s.version)),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- main loop side

/// At boot: switch off a native module that crashed the last boot, move old
/// WebAssembly modules to the new layout, then queue every installed app.
pub fn boot(k: &mut Kernel) {
    let crashed = k.boot.as_ref().and_then(|b| b.env("crash_app")).map(String::from);
    if let Some(name) = crashed {
        let why = k.boot.as_ref().and_then(|b| b.env("last_panic")).map(String::from).unwrap_or_default();
        if put(k, &key(&name, "native-off"), why.as_bytes()).is_ok() {
            kprintln!("modules: native {} crashed the last boot; switched off (its WebAssembly form runs instead, if installed)", name);
        }
        if let Some(b) = k.boot.as_mut() {
            b.env_set(&[("crash_app", "")]);
        }
    }
    let legacy: Vec<String> = match k.boot.as_ref() {
        Some(s) => s.kv_keys(LEGACY_WASM),
        None => Vec::new(),
    };
    for old in legacy {
        let name = &old[LEGACY_WASM.len()..];
        if let Some(image) = get(k, &old) {
            if put(k, &key(name, "wasm"), &image).is_ok() && put(k, &key(name, "prefer"), b"wasm").is_ok() {
                delete(k, &old);
            }
        }
    }
    // file system drivers first (apps find their files mounted), then the
    // runtime (WebAssembly modules need it)
    let mut names = installed(k);
    let fs: Vec<bool> = names.iter().map(|n| get(k, &key(n, ROLE)).as_deref() == Some(ROLE_FS)).collect();
    let mut order: Vec<(bool, bool, String)> = names.drain(..).zip(fs).map(|(n, fs)| (!fs, n != RUNTIME, n)).collect();
    rustros_util::sort::sort(&mut order);
    let names: Vec<String> = order.into_iter().map(|(_, _, n)| n).collect();
    for name in names {
        k.app_ops.push(ModuleOp::Start(name));
    }
    install_bundled(k);
}

/// The modules the boot image carries (`rustros.bundle=<lba>`, written by
/// mkimg after the image): each installed once, at the first boot that
/// finds it neither installed nor installed from the bundle before (so one
/// the owner removed stays removed).
fn install_bundled(k: &mut Kernel) {
    const MAGIC: &[u8; 8] = b"RRSBNDL1";
    const HEAD: usize = 4096;
    const ENTRY: usize = 80;
    let Some(lba) = rustros_util::wire::cmdline_get(&k.cmdline, "rustros.bundle").and_then(|v| v.parse::<u64>().ok()) else { return };
    let mut head = alloc::vec![0u8; HEAD];
    if !k.boot.as_mut().is_some_and(|b| b.boot_area_read(lba, &mut head)) || &head[..8] != MAGIC {
        kprintln!("modules: no bundle at LBA {}", lba);
        return;
    }
    let count = (u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize).min((HEAD - 16) / ENTRY);
    let have = installed(k);
    for i in 0..count {
        let e = &head[16 + i * ENTRY..16 + (i + 1) * ENTRY];
        let name = String::from(String::from_utf8_lossy(&e[..32]).trim_end_matches('\0'));
        let at = u32::from_le_bytes([e[32], e[33], e[34], e[35]]) as u64;
        let len = u32::from_le_bytes([e[36], e[37], e[38], e[39]]) as usize;
        let sha: [u8; 32] = e[40..72].try_into().unwrap_or([0; 32]);
        let marker = format!("sys/bundle/{name}");
        if name.is_empty() || get(k, &marker).is_some() {
            continue;
        }
        if have.contains(&name) {
            let _ = put(k, &marker, &sha);
            continue;
        }
        let mut data = alloc::vec![0u8; len.div_ceil(512) * 512];
        if !k.boot.as_mut().is_some_and(|b| b.boot_area_read(lba + at, &mut data)) {
            kprintln!("modules: bundled {}: unreadable", name);
            continue;
        }
        data.truncate(len);
        if rustros_util::sha256::Sha256::digest(&data) != sha {
            kprintln!("modules: bundled {}: damaged (SHA-256), not installed", name);
            continue;
        }
        match install(k, &name, &data) {
            Ok(kind) => {
                let _ = put(k, &marker, &sha);
                kprintln!("modules: installed {} from the boot image ({}, {} KiB)", name, kind.as_str(), len / 1024);
            }
            Err(e) => kprintln!("modules: bundled {}: {}", name, e),
        }
    }
}

/// Stop every hosted (WebAssembly) instance; they run on the runtime's code.
fn stop_hosted(k: &mut Kernel, slots: &mut [Slot]) -> Vec<String> {
    let mut stopped = Vec::new();
    for id in 0..slots.len() {
        if let Slot::Hosted(_) = slots[id] {
            let (st, mut link) = k.net();
            st.release_owner(id, &mut link);
            slots[id] = Slot::Empty;
            let name = k.names.get(id).copied().unwrap_or("");
            k.app_status.retain(|s| s.name != name);
            stopped.push(String::from(name));
            set_slot(k, id, "", Caps::NONE);
        }
    }
    stopped
}

/// (Re)load or drop the runtime. The WebAssembly modules are restarted on
/// the new one (or fall back to their native form).
fn apply_runtime(k: &mut Kernel, slots: &mut [Slot], start: bool, pending: &[String]) {
    let mut restart = stop_hosted(k, slots);
    if k.runtime_module.take().is_some() {
        k.app_status.retain(|s| s.name != RUNTIME);
        kprintln!("modules: {} runtime stopped", RUNTIME);
    }
    if start {
        let image = if get(k, &key(RUNTIME, "native-off")).is_some() {
            kprintln!("modules: the {} runtime is switched off after a crash", RUNTIME);
            None
        } else {
            get(k, &key(RUNTIME, image_key(ModuleKind::Native)))
        };
        if let Some(image) = image {
            unsafe { *CURRENT_NATIVE.get() = Some(RUNTIME) };
            let r = loader::load(&image);
            unsafe { *CURRENT_NATIVE.get() = None };
            match r {
                Ok(m) if matches!(m.export, Some(Export::Runtime(_))) => {
                    k.runtime_module = Some(m);
                    kprintln!("modules: {} runtime started ({} KiB)", RUNTIME, image.len() / 1024);
                    k.app_status.push(ModuleStatus {
                        name: RUNTIME,
                        kind: ModuleKind::Native,
                        state: String::from("runtime"),
                        restarts: 0,
                        params: Vec::new(),
                        version: "",
                    });
                }
                Ok(_) => kprintln!("modules: \"{}\" must be a runtime module", RUNTIME),
                Err(e) => kprintln!("modules: {}: {}", RUNTIME, e),
            }
        }
    }
    // every installed module that is not running (and not about to be
    // started anyway) gets another chance on the new runtime
    restart.extend(installed(k).into_iter().filter(|n| n != RUNTIME && !k.names.iter().any(|r| r == n)));
    restart.retain(|n| !pending.contains(n));
    rustros_util::sort::sort(&mut restart);
    restart.dedup();
    k.app_ops.extend(restart.into_iter().map(ModuleOp::Start));
}

/// The form to run: the preferred one if stored (and, for native, not
/// switched off), else the other.
fn choose(k: &mut Kernel, name: &str) -> Option<(ModuleKind, Vec<u8>)> {
    let first = preferred(k, name);
    for kind in [first, other(first)] {
        if kind == ModuleKind::Native && get(k, &key(name, "native-off")).is_some() {
            continue;
        }
        if kind == ModuleKind::Wasm && (k.runtime_ref().is_none() || name == RUNTIME) {
            continue;
        }
        if let Some(image) = get(k, &key(name, image_key(kind))) {
            return Some((kind, image));
        }
    }
    None
}

fn set_slot(k: &mut Kernel, id: usize, name: &'static str, caps: Caps) {
    if k.names.len() <= id {
        k.names.resize(id + 1, "");
        k.caps.resize(id + 1, Caps::NONE);
    }
    k.names[id] = name;
    k.caps[id] = caps;
    k.stack.set_owner_names(k.names.clone());
}

/// Apply queued installs, switches and removals.
pub fn apply(k: &mut Kernel, slots: &mut Vec<Slot>) {
    let ops = core::mem::take(&mut k.app_ops);
    for (i, op) in ops.iter().enumerate() {
        let (ModuleOp::Start(name) | ModuleOp::Stop(name)) = op;
        let name = name.as_str();
        if name == RUNTIME {
            let pending: Vec<String> = ops[i + 1..]
                .iter()
                .map(|o| match o {
                    ModuleOp::Start(n) | ModuleOp::Stop(n) => n.clone(),
                })
                .collect();
            apply_runtime(k, slots, matches!(op, ModuleOp::Start(_)), &pending);
            continue;
        }
        // a file system driver of that name goes (unmounting what it had)
        let was_fs = drop_filesystem(k, name);
        if was_fs && matches!(op, ModuleOp::Stop(_)) {
            kprintln!("modules: {} stopped", name);
            continue;
        }
        // take down the running instance, whatever its form
        let existing = (0..slots.len()).find(|&i| slots[i].kind().is_some() && k.names.get(i) == Some(&name));
        if let Some(id) = existing {
            let (st, mut link) = k.net();
            st.release_owner(id, &mut link);
            slots[id] = Slot::Empty; // drops the app, then the module's code
            set_slot(k, id, "", Caps::NONE);
            k.app_status.retain(|s| s.name != name);
        }
        if let ModuleOp::Stop(_) = op {
            if existing.is_some() {
                kprintln!("modules: {} stopped", name);
            }
            continue;
        }
        let Some((kind, image)) = choose(k, name) else {
            kprintln!("modules: {}: nothing runnable installed", name);
            continue;
        };
        let leaked: &'static str = Box::leak(String::from(name).into_boxed_str());
        let id = slots.iter().position(|s| matches!(s, Slot::Empty)).unwrap_or_else(|| {
            slots.push(Slot::Empty);
            slots.len() - 1
        });
        let slot = match kind {
            ModuleKind::Native => {
                // a crash inside the module's init is pinned on it too
                unsafe { *CURRENT_NATIVE.get() = Some(leaked) };
                let r = loader::load(&image);
                unsafe { *CURRENT_NATIVE.get() = None };
                match r {
                    Ok(m) if matches!(m.export, Some(Export::Module(_))) => Slot::Native(m),
                    Ok(m) if matches!(m.export, Some(Export::Filesystem(_))) => {
                        add_filesystem(k, leaked, m, image.len());
                        continue;
                    }
                    Ok(_) => {
                        kprintln!("modules: {}: a runtime module must be installed as \"{}\"", name, RUNTIME);
                        Slot::Empty
                    }
                    Err(e) => {
                        kprintln!("modules: {}: {}", name, e);
                        Slot::Empty
                    }
                }
            }
            ModuleKind::Wasm => match k.runtime().map(|rt| rt.instantiate(leaked, &image)) {
                Some(Ok(app)) => Slot::Hosted(app),
                Some(Err(e)) => {
                    kprintln!("modules: {}: {}", name, e);
                    Slot::Empty
                }
                None => Slot::Empty,
            },
        };
        if matches!(slot, Slot::Empty) {
            continue;
        }
        slots[id] = slot;
        // what module_list reports, from the start (not only after the next refresh)
        let (caps, version, params) = slots[id].app().map_or((Caps::NONE, "", Vec::new()), |a| (a.caps(), a.version(), a.params().iter().map(rustros_api::ParamInfo::from).collect()));
        // WebAssembly apps never get ADMIN (it is not importable either)
        let caps = if kind == ModuleKind::Wasm { caps & (Caps::NET | Caps::KV | Caps::PACKET | Caps::CONSOLE) } else { caps };
        set_slot(k, id, leaked, caps);
        kprintln!("modules: {} started ({}, {} KiB)", name, kind.as_str(), image.len() / 1024);
        k.app_status.push(ModuleStatus { name: leaked, kind, state: String::from("running"), restarts: 0, params, version });
        call(k, slots, id, |app, ctx| app.start(ctx));
    }
}

/// Refresh what `module_list` reports.
pub fn refresh_status(k: &mut Kernel, slots: &mut [Slot]) {
    for (id, slot) in slots.iter_mut().enumerate() {
        if slot.kind().is_none() {
            continue;
        }
        let name = k.names.get(id).copied().unwrap_or("");
        if let (Some(app), Some(st)) = (slot.app(), k.app_status.iter_mut().find(|s| s.name == name)) {
            st.state = app.status();
            st.restarts = app.restarts();
            st.version = app.version();
            let params = app.params();
            if st.params.len() != params.len() || st.params.iter().zip(params).any(|(a, b)| a.key != b.key) {
                st.params = params.iter().map(rustros_api::ParamInfo::from).collect();
            }
        }
    }
}

// ---------------------------------------------------------------- file system drivers

/// The kv mark a file system driver gets once loaded (so it starts first later).
const ROLE: &str = "role";
const ROLE_FS: &[u8] = b"fs";

/// A file system driver loaded: kept, and the files partition mounted with
/// it if it is the one for it.
fn add_filesystem(k: &mut Kernel, name: &'static str, m: crate::loader::Module, size: usize) {
    let Some(Export::Filesystem(fs)) = m.export.as_ref() else { return };
    let (fs_name, version) = (fs.name(), fs.version());
    if get(k, &key(name, ROLE)).as_deref() != Some(ROLE_FS) {
        let _ = put(k, &key(name, ROLE), ROLE_FS);
    }
    k.filesystems.push((name, m));
    kprintln!("modules: {} started (file system {}, {} KiB)", name, fs_name, size / 1024);
    k.app_status.push(ModuleStatus { name, kind: ModuleKind::Native, state: format!("file system {fs_name}"), restarts: 0, params: Vec::new(), version });
    mount_files(k);
}

/// A driver going: the files partition unmounted first if it is its.
fn drop_filesystem(k: &mut Kernel, name: &str) -> bool {
    let Some(i) = k.filesystems.iter().position(|(n, _)| *n == name) else { return false };
    if k.files_fs == Some(i) {
        k.with_files(|fs, d| fs.close(d));
        k.files_fs = None;
        kprintln!("storage: files partition unmounted");
    } else if let Some(m) = k.files_fs.as_mut() {
        if *m > i {
            *m -= 1;
        }
    }
    k.filesystems.remove(i);
    k.app_status.retain(|s| s.name != name);
    true
}

/// The files partition mounted, if it is not yet, with the driver that
/// recognises it; a blank one is first made with the default (ext4).
fn mount_files(k: &mut Kernel) {
    if k.files_fs.is_some() || k.filesystems.is_empty() {
        return;
    }
    let Some(b) = k.boot.as_mut() else { return };
    let now = arch::unix_time() as u32;
    let filesystems = &mut k.filesystems;
    let mut found = None;
    b.files(&mut |d| {
        for (i, (name, m)) in filesystems.iter_mut().enumerate() {
            let Some(Export::Filesystem(fs)) = m.export.as_mut() else { continue };
            let before = set_current_native(Some(name));
            let mine = fs.probe(d);
            set_current_native(before);
            if mine {
                found = Some(i);
                return;
            }
        }
        // nothing recognises it: made anew only if it holds nothing at all
        let mut head = vec![0u8; 128 * 1024];
        if !d.read(0, &mut head) || head.iter().any(|&x| x != 0) {
            kprintln!("storage: files partition: no installed file system driver recognises it (left alone)");
            return;
        }
        let i = filesystems.iter().position(|(_, m)| matches!(m.export.as_ref(), Some(Export::Filesystem(fs)) if fs.name() == "ext4")).unwrap_or(0);
        let (name, m) = &mut filesystems[i];
        let Some(Export::Filesystem(fs)) = m.export.as_mut() else { return };
        let mut uuid = [0u8; 16];
        uuid[..8].copy_from_slice(&arch::rdtsc().to_le_bytes());
        uuid[8..].copy_from_slice(&arch::rdtsc().rotate_left(29).to_le_bytes());
        let before = set_current_native(Some(name));
        let r = fs.format(d, uuid, now);
        set_current_native(before);
        match r {
            Ok(()) => {
                kprintln!("storage: files partition formatted ({})", fs.name());
                found = Some(i);
            }
            Err(e) => kprintln!("storage: files partition: cannot format: {}", e),
        }
    });
    let Some(i) = found else { return };
    k.files_fs = Some(i);
    match k.with_files(|fs, d| fs.mount(d, now)) {
        Some(Ok(msg)) => {
            kprintln!("storage: files partition {}", msg);
            let name = k.filesystems[i].0;
            if let Some(st) = k.app_status.iter_mut().find(|s| s.name == name) {
                st.state.push_str(", files partition mounted");
            }
        }
        Some(Err(e)) => {
            kprintln!("storage: files partition: {}", e);
            k.files_fs = None;
        }
        None => k.files_fs = None,
    }
}
