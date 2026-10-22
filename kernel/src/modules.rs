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
use alloc::vec::Vec;

use rustros_api::module::Export;
use rustros_api::{Module, ModuleInfo, ModuleKind, Caps};

use crate::loader;
use crate::sys::{Ctx, Kernel};
use crate::{Global, kprintln};

const PREFIX: &str = "sys/app/";
/// The WebAssembly runtime is the native module installed under this name.
pub const RUNTIME: &str = "wasm";
/// Old location of WebAssembly modules (before native modules existed).
const LEGACY_WASM: &str = "sys/wasm/";

/// An entry of the app table; the index is the app id.
pub enum Slot {
    Builtin(Box<dyn Module>),
    Native(loader::Module),
    /// An instance created by a runtime (WebAssembly).
    Hosted(Box<dyn Module>),
    Empty,
}

impl Slot {
    pub fn app(&mut self) -> Option<&mut dyn Module> {
        match self {
            Slot::Builtin(a) | Slot::Hosted(a) => Some(a.as_mut()),
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
}

// ---------------------------------------------------------------- crash attribution

/// The native module being called right now, so a crash can be pinned on it.
static CURRENT_NATIVE: Global<Option<&'static str>> = Global::new(None);

pub fn current_native() -> Option<&'static str> {
    // Safety: single core; written only by the main loop around app calls.
    unsafe { *CURRENT_NATIVE.get() }
}

/// Call into app `id` (with crash attribution and housekeeping afterwards).
pub fn call(k: &mut Kernel, slots: &mut [Slot], id: usize, f: impl FnOnce(&mut dyn Module, &mut Ctx)) {
    // a hosted (WebAssembly) app runs inside the runtime module's code
    let culprit = match slots[id] {
        Slot::Native(_) => k.names.get(id).copied(),
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
    k.store_ref().and_then(|s| s.get(key).map(|v| v.to_vec()))
}

fn put(k: &mut Kernel, key: &str, value: &[u8]) -> Result<(), String> {
    let (s, d) = k.store().ok_or_else(|| String::from("no storage for applications"))?;
    s.put(d, key, value).map_err(|e| format!("cannot store: {e:?}"))
}

fn delete(k: &mut Kernel, key: &str) -> bool {
    k.store().is_some_and(|(s, d)| s.delete(d, key).unwrap_or(false))
}

fn installed(k: &Kernel) -> Vec<String> {
    let Some(s) = k.store_ref() else { return Vec::new() };
    let mut names: Vec<String> = s
        .keys(PREFIX)
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
            }
        })
        .collect()
}

// ---------------------------------------------------------------- main loop side

/// At boot: switch off a native module that crashed the last boot, move old
/// WebAssembly modules to the new layout, then queue every installed app.
pub fn boot(k: &mut Kernel) {
    let crashed = k.boot.as_ref().and_then(|b| b.upd.get("crash_app")).map(String::from);
    if let Some(name) = crashed {
        let why = k.boot.as_ref().and_then(|b| b.upd.get("last_panic")).map(String::from).unwrap_or_default();
        if put(k, &key(&name, "native-off"), why.as_bytes()).is_ok() {
            kprintln!("modules: native {} crashed the last boot; switched off (its WebAssembly form runs instead, if installed)", name);
        }
        if let Some(b) = k.boot.as_mut() {
            b.upd.set_vars(&mut *b.disk, &[("crash_app", "")]);
        }
    }
    let legacy: Vec<String> = match k.store_ref() {
        Some(s) => s.keys(LEGACY_WASM).map(String::from).collect(),
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
    // the runtime first: WebAssembly modules need it
    let mut names = installed(k);
    names.sort_by_key(|n| n != RUNTIME);
    for name in names {
        k.app_ops.push(ModuleOp::Start(name));
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
    restart.sort();
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
    k.stack.owner_names = k.names.clone();
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
        let caps = slots[id].app().map_or(Caps::NONE, |a| a.caps());
        // WebAssembly apps never get ADMIN (it is not importable either)
        let caps = if kind == ModuleKind::Wasm { caps & (Caps::NET | Caps::KV | Caps::PACKET | Caps::CONSOLE) } else { caps };
        set_slot(k, id, leaked, caps);
        kprintln!("modules: {} started ({}, {} KiB)", name, kind.as_str(), image.len() / 1024);
        k.app_status.push(ModuleStatus { name: leaked, kind, state: String::from("running"), restarts: 0, params: Vec::new() });
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
            let params = app.params();
            if st.params.len() != params.len() || st.params.iter().zip(params).any(|(a, b)| a.key != b.key) {
                st.params = params.iter().map(rustros_api::ParamInfo::from).collect();
            }
        }
    }
}
