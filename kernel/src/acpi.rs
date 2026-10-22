//! Just enough ACPI to power off: find the FADT for the PM1 registers, take
//! the S5 sleep type from the DSDT's `_S5_` package, and watch the power
//! button status bit so the hypervisor's "shut down" works.

use crate::Global;
use crate::arch::{inb, inw, outb, outw};
use crate::mem::map_identity;

const SLP_EN: u16 = 1 << 13;
const SCI_EN: u16 = 1;
const PWRBTN: u16 = 1 << 8;

#[derive(Clone, Copy)]
struct Pm {
    pm1a_cnt: u16,
    pm1b_cnt: u16,
    pm1a_evt: u16,
    /// S5 sleep types for PM1a / PM1b
    s5: (u16, u16),
}

static PM: Global<Option<Pm>> = Global::new(None);
/// CPUs the firmware lists (MADT); 0 if unknown.
static CPUS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn cpu_count() -> u32 {
    CPUS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Enabled (or online-capable) processors in the MADT.
fn count_cpus(madt: &[u8]) -> u32 {
    let mut n = 0;
    let mut o = 44;
    while o + 2 <= madt.len() {
        let (ty, len) = (madt[o], madt[o + 1] as usize);
        if len < 2 || o + len > madt.len() {
            break;
        }
        let flags = match ty {
            0 if len >= 8 => le32(madt, o + 4),  // local APIC
            9 if len >= 16 => le32(madt, o + 8), // local x2APIC
            _ => 0,
        };
        if flags & 3 != 0 {
            n += 1;
        }
        o += len;
    }
    n
}

fn rd32(p: u64) -> u32 {
    unsafe { (p as *const u32).read_unaligned() }
}

fn rd64(p: u64) -> u64 {
    unsafe { (p as *const u64).read_unaligned() }
}

/// A mapped table at `addr`: (signature, whole table). None if it cannot be mapped.
fn table(addr: u64) -> Option<([u8; 4], &'static [u8])> {
    if addr == 0 || !map_identity(addr, 36) {
        return None;
    }
    let len = rd32(addr + 4) as u64;
    if !(36..=1 << 24).contains(&len) || !map_identity(addr, len) {
        return None;
    }
    let t = unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) };
    Some((t[..4].try_into().unwrap(), t))
}

fn le32(t: &[u8], o: usize) -> u32 {
    t.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// S5 sleep types from `Name(_S5_, Package() {a, b, ...})` in AML.
fn s5(dsdt: &[u8]) -> Option<(u16, u16)> {
    let at = dsdt.windows(4).position(|w| w == b"_S5_")?;
    let mut p = &dsdt[at + 4..];
    if p.first() != Some(&0x12) {
        return None; // not a PackageOp
    }
    let lead = *p.get(1)?;
    p = p.get(2 + (lead >> 6) as usize + 1..)?; // PkgLength, NumElements
    let mut val = || {
        let v = match p.first()? {
            0x0A => {
                let v = *p.get(1)?;
                p = &p[2..];
                v
            }
            &v @ (0 | 1) => {
                p = &p[1..];
                v
            }
            _ => return None,
        };
        Some(v as u16)
    };
    let a = val()?;
    let b = val().unwrap_or(0);
    Some((a, b))
}

/// Find the PM registers. `rsdp` is the RSDP copy from the multiboot2 info.
pub fn init(rsdp: Option<&[u8]>) {
    let Some(r) = rsdp.filter(|r| r.len() >= 20 && &r[..8] == b"RSD PTR ") else { return };
    let (root, entry) = if r[15] >= 2 && r.len() >= 32 {
        (u64::from_le_bytes(r[24..32].try_into().unwrap()), 8)
    } else {
        (le32(r, 16) as u64, 4)
    };
    let Some((_, sdt)) = table(root) else { return };
    let tables = || sdt[36..].chunks_exact(entry).map(|e| if entry == 8 { u64::from_le_bytes(e.try_into().unwrap()) } else { le32(e, 0) as u64 }).filter_map(table);
    if let Some((_, madt)) = tables().find(|(sig, _)| sig == b"APIC") {
        CPUS.store(count_cpus(madt), core::sync::atomic::Ordering::Relaxed);
    }
    let fadt = tables().find(|(sig, _)| sig == b"FACP");
    let Some((_, f)) = fadt else { return };
    let x_dsdt = if f.len() >= 148 { rd64(f.as_ptr() as u64 + 140) } else { 0 };
    let dsdt = if x_dsdt != 0 { x_dsdt } else { le32(f, 40) as u64 };
    let Some(s5) = table(dsdt).and_then(|(_, d)| s5(d)) else { return };
    let pm = Pm { pm1a_cnt: le32(f, 64) as u16, pm1b_cnt: le32(f, 68) as u16, pm1a_evt: le32(f, 56) as u16, s5 };
    if pm.pm1a_cnt == 0 {
        return;
    }
    // ACPI mode, so the power button reports to us rather than to firmware
    let (smi_cmd, enable) = (le32(f, 48) as u16, f.get(52).copied().unwrap_or(0));
    unsafe {
        if inw(pm.pm1a_cnt) & SCI_EN == 0 && smi_cmd != 0 && enable != 0 {
            outb(smi_cmd, enable);
            for _ in 0..1_000_000 {
                if inw(pm.pm1a_cnt) & SCI_EN != 0 {
                    break;
                }
                inb(0x80);
            }
        }
        if pm.pm1a_evt != 0 {
            outw(pm.pm1a_evt, PWRBTN); // clear a stale press
            // the press is only latched while enabled; the SCI it raises stays
            // masked at the PIC, we poll the status bit
            let en = pm.pm1a_evt + f.get(88).map_or(4, |&l| l as u16 / 2);
            outw(en, inw(en) | PWRBTN);
        }
    }
    unsafe { *PM.get() = Some(pm) };
}

pub fn available() -> bool {
    unsafe { PM.get().is_some() }
}

/// The power button was pressed (or the hypervisor asked for a shutdown).
pub fn power_button() -> bool {
    let Some(pm) = (unsafe { *PM.get() }) else { return false };
    if pm.pm1a_evt == 0 {
        return false;
    }
    unsafe {
        if inw(pm.pm1a_evt) & PWRBTN == 0 {
            return false;
        }
        outw(pm.pm1a_evt, PWRBTN);
    }
    true
}

/// Enter S5. Returns only if ACPI is not available or the write had no effect.
pub fn poweroff() {
    let Some(pm) = (unsafe { *PM.get() }) else { return };
    unsafe {
        outw(pm.pm1a_cnt, pm.s5.0 << 10 | SLP_EN);
        if pm.pm1b_cnt != 0 {
            outw(pm.pm1b_cnt, pm.s5.1 << 10 | SLP_EN);
        }
        for _ in 0..10_000_000 {
            inb(0x80);
        }
    }
}
