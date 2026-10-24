//! Loader for native modules: position-independent ELF64 images for
//! x86_64-unknown-none (see rustros_api::module and modules/).
//!
//! The image is copied into a fresh heap block (all memory is mapped
//! executable), its R_X86_64_RELATIVE relocations are applied and
//! `rustros_module_init` is called. Nothing else is supported: a module has no
//! dynamic dependencies or symbol imports, it reaches the kernel only through
//! the `HostTable` and the trait objects exchanged after the fingerprint check.

use alloc::alloc::{Layout, alloc_zeroed, dealloc, realloc};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::Global;

use rustros_api::API_FINGERPRINT;
use rustros_api::module::{Export, HostTable};

const MAX_IMAGE: usize = 32 << 20;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_JMPREL: u64 = 23;
const R_X86_64_RELATIVE: u32 = 8;

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

struct Seg {
    vaddr: usize,
    offset: usize,
    filesz: usize,
    memsz: usize,
}

/// What the headers say, all bounds-checked against the file.
struct Image {
    span: usize,
    entry: usize,
    loads: alloc::vec::Vec<Seg>,
    dynamic: Option<(usize, usize)>,
}

fn parse(img: &[u8]) -> Result<Image, String> {
    let bad = |what: &str| format!("not a RustROS module: {what}");
    if img.len() < 64 || &img[..4] != b"\x7fELF" || img[4] != 2 || img[5] != 1 {
        return Err(bad("not a little-endian ELF64 file"));
    }
    if u16_at(img, 16) != Some(3) || u16_at(img, 18) != Some(62) {
        return Err(bad("not a position-independent x86-64 image"));
    }
    let entry = u64_at(img, 24).ok_or_else(|| bad("header"))? as usize;
    let phoff = u64_at(img, 32).ok_or_else(|| bad("header"))? as usize;
    let phentsize = u16_at(img, 54).ok_or_else(|| bad("header"))? as usize;
    let phnum = u16_at(img, 56).ok_or_else(|| bad("header"))? as usize;
    if phentsize < 56 || phnum > 64 {
        return Err(bad("program headers"));
    }
    let mut loads = alloc::vec::Vec::new();
    let mut dynamic = None;
    let mut span = 0usize;
    for i in 0..phnum {
        let ph = phoff.checked_add(i * phentsize).ok_or_else(|| bad("program headers"))?;
        let ty = u32_at(img, ph).ok_or_else(|| bad("program headers"))?;
        let field = |o: usize| u64_at(img, ph + o).map(|v| v as usize).ok_or_else(|| bad("program headers"));
        let (offset, vaddr, filesz, memsz) = (field(8)?, field(16)?, field(32)?, field(40)?);
        match ty {
            PT_LOAD => {
                let end = vaddr.checked_add(memsz).filter(|&e| e <= MAX_IMAGE).ok_or_else(|| bad("segment too large"))?;
                if filesz > memsz || offset.checked_add(filesz).is_none_or(|e| e > img.len()) {
                    return Err(bad("segment outside the file"));
                }
                span = span.max(end);
                loads.push(Seg { vaddr, offset, filesz, memsz });
            }
            PT_DYNAMIC => dynamic = Some((vaddr, memsz)),
            _ => {}
        }
    }
    if loads.is_empty() || entry >= span {
        return Err(bad("no code"));
    }
    if let Some((v, n)) = dynamic {
        if v.checked_add(n).is_none_or(|e| e > span) {
            return Err(bad("dynamic section"));
        }
    }
    Ok(Image { span: span.div_ceil(4096) * 4096, entry, loads, dynamic })
}

/// Cheap check before an image is stored (does not run anything).
pub fn check(img: &[u8]) -> Result<(), String> {
    parse(img).map(|_| ())
}

/// A loaded module. Dropping it drops what it exported, then frees its code.
pub struct Module {
    base: *mut u8,
    layout: Layout,
    pub export: Option<Export>,
}

impl Drop for Module {
    fn drop(&mut self) {
        // the export's destructors are code inside the module
        drop(self.export.take());
        // Safety: single core, main loop only
        unsafe { LOADED.get() }.retain(|m| m.0 != self.base as usize);
        unsafe { dealloc(self.base, self.layout) };
    }
}

/// Installed modules in memory: (start, end, name).
static LOADED: Global<Vec<(usize, usize, &'static str)>> = Global::new(Vec::new());

/// The installed module whose image holds address `at` (a crash there is
/// pinned on it, whoever called it).
pub fn owner_of(at: u64) -> Option<&'static str> {
    // Safety: single core; the crash path only reads it
    unsafe { LOADED.get() }.iter().find(|m| (m.0..m.1).contains(&(at as usize))).map(|m| m.2)
}

/// Load a module; `name`: an installed module's (its crashes are pinned on
/// it by address), None for the boot modules' binary.
pub fn load(img: &[u8], name: Option<&'static str>) -> Result<Module, String> {
    let l = parse(img)?;
    let layout = Layout::from_size_align(l.span, 4096).map_err(|_| String::from("bad module size"))?;
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        return Err(String::from("out of memory for the module"));
    }
    // From here on `m` frees the block if we bail out.
    let mut m = Module { base, layout, export: None };
    // Safety: every copy and write below stays within [base, base + span),
    // which parse() checked against each segment and the dynamic section.
    let mem = unsafe { core::slice::from_raw_parts_mut(base, l.span) };
    for s in &l.loads {
        mem[s.vaddr..s.vaddr + s.filesz].copy_from_slice(&img[s.offset..s.offset + s.filesz]);
        let _ = s.memsz; // the rest of the segment (bss) is already zero
    }
    if let Some((dv, dn)) = l.dynamic {
        let (mut rela, mut relasz, mut relaent) = (0usize, 0usize, 24usize);
        let mut o = dv;
        while o + 16 <= dv + dn {
            let tag = u64_at(mem, o).unwrap_or(DT_NULL);
            let val = u64_at(mem, o + 8).unwrap_or(0) as usize;
            match tag {
                DT_NULL => break,
                DT_NEEDED | DT_JMPREL => return Err(String::from("module has dynamic imports; build it with rustros-module")),
                DT_RELA => rela = val,
                DT_RELASZ => relasz = val,
                DT_RELAENT => relaent = val,
                _ => {}
            }
            o += 16;
        }
        if relaent < 24 || rela.checked_add(relasz).is_none_or(|e| e > l.span) {
            return Err(String::from("bad relocation table"));
        }
        let mut r = rela;
        while r + 24 <= rela + relasz {
            let offset = u64_at(mem, r).unwrap_or(0) as usize;
            let info = u64_at(mem, r + 8).unwrap_or(0);
            let addend = u64_at(mem, r + 16).unwrap_or(0);
            if info as u32 != R_X86_64_RELATIVE {
                return Err(format!("unsupported relocation type {}", info as u32));
            }
            if offset.checked_add(8).is_none_or(|e| e > l.span) {
                return Err(String::from("relocation outside the module"));
            }
            mem[offset..offset + 8].copy_from_slice(&(base as u64).wrapping_add(addend).to_le_bytes());
            r += relaent;
        }
    }
    // a crash in its init is pinned on it too
    if let Some(name) = name {
        // Safety: single core, main loop only
        unsafe { LOADED.get() }.push((base as usize, base as usize + l.span, name));
    }
    type Init = extern "C" fn(*const HostTable, *mut Option<Export>) -> u64;
    // Safety: the entry point is inside the image (parse()); its signature is
    // the module ABI, and both sides only use C types until the fingerprints
    // have matched.
    let init: Init = unsafe { core::mem::transmute(base.add(l.entry)) };
    let mut out: Option<Export> = None;
    let fp = init(&HOST, &mut out);
    // Safety: as above (registered for good below, once it is loaded)
    unsafe { LOADED.get() }.retain(|m| m.0 != base as usize);
    if fp != API_FINGERPRINT {
        // the module did not touch `out`
        core::mem::forget(out);
        return Err(format!(
            "module built for another kernel API ({fp:#x}, this kernel is {API_FINGERPRINT:#x}); rebuild it with this kernel"
        ));
    }
    m.export = out;
    if m.export.is_none() {
        return Err(String::from("module exported nothing"));
    }
    if let Some(name) = name {
        // Safety: single core, main loop only
        unsafe { LOADED.get() }.push((base as usize, base as usize + l.span, name));
    }
    Ok(m)
}

extern "C" fn host_alloc(size: usize, align: usize) -> *mut u8 {
    match Layout::from_size_align(size, align) {
        Ok(l) => unsafe { alloc::alloc::alloc(l) },
        Err(_) => core::ptr::null_mut(),
    }
}

extern "C" fn host_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(l) = Layout::from_size_align(size, align) {
        unsafe { dealloc(ptr, l) }
    }
}

extern "C" fn host_realloc(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8 {
    match Layout::from_size_align(size, align) {
        Ok(l) => unsafe { realloc(ptr, l, new_size) },
        Err(_) => core::ptr::null_mut(),
    }
}

extern "C" fn host_crash(msg: *const u8, len: usize, at: usize) -> ! {
    // Safety: the module passes a buffer of its own; we only read it.
    let m = unsafe { core::slice::from_raw_parts(msg, len.min(4096)) };
    if let Some(name) = owner_of(at as u64) {
        crate::modules::set_current_native(Some(name));
    }
    crate::crash(format_args!("{}", core::str::from_utf8(m).unwrap_or("module crash")))
}

static HOST: HostTable = HostTable {
    fingerprint: API_FINGERPRINT,
    alloc: host_alloc,
    dealloc: host_dealloc,
    realloc: host_realloc,
    crash: host_crash,
};
