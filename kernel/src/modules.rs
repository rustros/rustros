//! The modules the kernel runs: the built-in and boot apps, installed native
//! modules and runtime-hosted (WebAssembly) instances, the runtime and the
//! file system drivers. What is installed and which form runs is the module
//! manager's (a boot module's, `rustros_api::module::ModManager`); the main
//! loop applies the operations it queues, between passes.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rustros_api::module::{Export, ModHost, ModManager, ModOp, ROLE_FS, ROLE_SERVICE, RUNTIME, Storage};
use rustros_api::{Caps, Module, ModuleInfo, ModuleKind};

use crate::loader;
use crate::sys::{Ctx, Kernel};
use crate::{Global, arch, kprintln};

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

// ---------------------------------------------------------------- the module manager

/// What the module manager gets from the kernel.
struct Host<'a> {
    k: &'a mut Kernel,
}

impl ModHost for Host<'_> {
    fn store(&mut self) -> Option<&mut dyn Storage> {
        Some(&mut **self.k.boot.as_mut()?)
    }
    fn cmdline(&self) -> &str {
        &self.k.cmdline
    }
    fn log(&mut self, line: &str) {
        kprintln!("{}", line);
    }
    fn check(&self, image: &[u8]) -> Result<ModuleKind, String> {
        if image.starts_with(b"\x7fELF") {
            loader::check(image)?;
            Ok(ModuleKind::Native)
        } else if let Some(rt) = self.k.runtime_ref().filter(|r| r.accepts(image)) {
            rt.validate(image)?;
            Ok(ModuleKind::Wasm)
        } else if image.starts_with(b"\0asm") {
            Err(String::from("no WebAssembly runtime in this system"))
        } else {
            Err(String::from("unknown image format (expected a native module ELF or WebAssembly)"))
        }
    }
    fn role(&self, image: &[u8]) -> Option<&'static str> {
        if !image.starts_with(b"\x7fELF") {
            return None;
        }
        let m = loader::load(image, None).ok()?;
        if crate::services::is_service(&m) {
            Some(ROLE_SERVICE)
        } else if matches!(m.export, Some(Export::Filesystem(_))) {
            Some(ROLE_FS)
        } else {
            None
        }
    }
    fn has_runtime(&self) -> bool {
        self.k.runtime_ref().is_some()
    }
    fn is_builtin(&self, name: &str) -> bool {
        self.k.builtin_names.contains(&name)
    }
    fn is_running(&self, name: &str) -> bool {
        self.k.names.contains(&name) || crate::services::provides(self.k, name)
    }
}

/// Call the module manager; None if the boot modules have none.
pub fn manager<T>(k: &mut Kernel, f: impl FnOnce(&mut dyn ModManager, &mut dyn ModHost) -> T) -> Option<T> {
    let mut m = k.manager.take()?;
    let r = f(&mut *m, &mut Host { k: &mut *k });
    k.manager = Some(m);
    Some(r)
}

/// The running installed modules, for `module_list`.
pub fn running(k: &Kernel) -> Vec<ModuleInfo> {
    let mut services = crate::services::running(k);
    let mut apps: Vec<ModuleInfo> = k.app_status
        .iter()
        .map(|s| ModuleInfo {
            name: String::from(s.name),
            native_bytes: None,
            wasm_bytes: None,
            preferred: ModuleKind::Native,
            running: Some(s.kind),
            state: s.state.clone(),
            restarts: s.restarts,
            native_off: None,
            params: s.params.clone(),
            version: String::from(s.version),
        })
        .collect();
    apps.append(&mut services);
    apps
}

// ---------------------------------------------------------------- main loop side

/// At boot: the manager queues every installed module.
pub fn boot(k: &mut Kernel) {
    if manager(k, |m, h| m.boot(h)).is_none() {
        kprintln!("modules: no module manager (boot modules), installed modules are not started");
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
fn apply_runtime(k: &mut Kernel, slots: &mut [Slot], start: bool) {
    let stopped = stop_hosted(k, slots);
    if k.runtime_module.take().is_some() {
        k.app_status.retain(|s| s.name != RUNTIME);
        kprintln!("modules: {} runtime stopped", RUNTIME);
    }
    if start {
        let image = manager(k, |m, h| m.choose(h, RUNTIME)).flatten().map(|(_, image)| image);
        if let Some(image) = image {
            unsafe { *CURRENT_NATIVE.get() = Some(RUNTIME) };
            let r = loader::load(&image, Some(RUNTIME));
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
    manager(k, |m, h| m.runtime_changed(h, stopped));
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
    while let Some(op) = manager(k, |m, _| m.next_op()).flatten() {
        let (ModOp::Start(name) | ModOp::Stop(name)) = &op;
        let name = name.as_str();
        if name == RUNTIME {
            apply_runtime(k, slots, matches!(op, ModOp::Start(_)));
            continue;
        }
        // a module that replaced services: the boot image's come back
        if matches!(op, ModOp::Stop(_)) && crate::services::provides(k, name) {
            match crate::services::revert(k, name) {
                Ok(()) => kprintln!("modules: {} stopped (the boot image's services are back)", name),
                Err(e) => kprintln!("modules: {}: cannot go back to the boot image's services: {}", name, e),
            }
            continue;
        }
        // a file system driver of that name goes (unmounting what it had)
        let was_fs = drop_filesystem(k, name);
        if was_fs && matches!(op, ModOp::Stop(_)) {
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
        if let ModOp::Stop(_) = op {
            if existing.is_some() {
                kprintln!("modules: {} stopped", name);
            }
            continue;
        }
        let Some((kind, image)) = manager(k, |m, h| m.choose(h, name)).flatten() else {
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
                let r = loader::load(&image, Some(leaked));
                unsafe { *CURRENT_NATIVE.get() = None };
                match r {
                    Ok(m) if matches!(m.export, Some(Export::Module(_))) => Slot::Native(m),
                    Ok(m) if crate::services::is_service(&m) => {
                        if let Err(e) = crate::services::start(k, leaked, m) {
                            kprintln!("modules: {}: {}", name, e);
                        }
                        continue;
                    }
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

/// A file system driver loaded: kept, and the files partition mounted with
/// it if it is the one for it.
fn add_filesystem(k: &mut Kernel, name: &'static str, m: crate::loader::Module, size: usize) {
    let Some(Export::Filesystem(fs)) = m.export.as_ref() else { return };
    let (fs_name, version) = (fs.name(), fs.version());
    manager(k, |m, h| m.is_filesystem(h, name));
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
