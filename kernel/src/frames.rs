//! Physical memory for user-mode processes: every 4 KiB frame of RAM that
//! the kernel image (with its heap), the boot modules and the boot
//! information leave free. Free frames form a list through their first
//! word (all RAM is identity-mapped). Frames shared copy-on-write between
//! address spaces are counted.

use alloc::vec::Vec;

use crate::Global;

pub const PAGE: u64 = 4096;

struct Frames {
    head: u64,
    free: u64,
    total: u64,
    /// frames with more than one owner: (frame, owners beyond the first),
    /// sorted by frame
    shared: Vec<(u64, u32)>,
}

static F: Global<Frames> = Global::new(Frames { head: 0, free: 0, total: 0, shared: Vec::new() });

fn f() -> &'static mut Frames {
    // Safety: single core, main loop only (never from interrupts)
    unsafe { F.get() }
}

/// Add `[base, base + len)` minus the `taken` ranges.
fn add(base: u64, len: u64, taken: &[(u64, u64)]) {
    let mut a = (base + PAGE - 1) & !(PAGE - 1);
    let end = (base + len) & !(PAGE - 1);
    while a < end {
        match taken.iter().find(|t| a >= t.0 && a < t.1) {
            Some(t) => a = (t.1 + PAGE - 1) & !(PAGE - 1),
            None => {
                free(a);
                f().total += 1;
                a += PAGE;
            }
        }
    }
}

/// Take the RAM (`ram`: base, length) but `taken` (start, end); RAM above
/// 4 GiB is identity-mapped first (its page tables from the frames below).
pub fn init(ram: impl Iterator<Item = (u64, u64)> + Clone, taken: &[(u64, u64)]) {
    const LOW: u64 = 4 << 30;
    for (b, l) in ram.clone() {
        if b < LOW {
            add(b.max(1 << 20), (b + l).min(LOW).saturating_sub(b.max(1 << 20)), taken);
        }
    }
    for (b, l) in ram {
        let (b, e) = (b.max(LOW), b + l);
        if e > b && crate::mem::map_identity(b, e - b) {
            add(b, e - b, taken);
        }
    }
}

/// A zeroed frame.
pub fn alloc() -> Option<u64> {
    let s = f();
    let a = s.head;
    if a == 0 {
        return None;
    }
    // Safety: a free frame, identity-mapped, ours
    unsafe {
        s.head = *(a as *const u64);
        core::ptr::write_bytes(a as *mut u8, 0, PAGE as usize);
    }
    s.free -= 1;
    Some(a)
}

pub fn free(a: u64) {
    let s = f();
    // Safety: the caller gives the frame up
    unsafe { *(a as *mut u64) = s.head };
    s.head = a;
    s.free += 1;
}

/// One more owner of frame `a` (copy-on-write).
pub fn share(a: u64) {
    let s = f();
    match s.shared.binary_search_by_key(&a, |e| e.0) {
        Ok(i) => s.shared[i].1 += 1,
        Err(i) => s.shared.insert(i, (a, 1)),
    }
}

/// Whether frame `a` has other owners.
pub fn shared(a: u64) -> bool {
    f().shared.binary_search_by_key(&a, |e| e.0).is_ok()
}

/// An owner lets go of frame `a`: freed with the last one.
pub fn release(a: u64) {
    let s = f();
    match s.shared.binary_search_by_key(&a, |e| e.0) {
        Ok(i) if s.shared[i].1 > 1 => s.shared[i].1 -= 1,
        Ok(i) => {
            s.shared.remove(i);
        }
        Err(_) => free(a),
    }
}

/// (free, total) frames.
pub fn stats() -> (u64, u64) {
    (f().free, f().total)
}
