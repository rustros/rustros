//! Address spaces of user-mode processes. The kernel's mappings (the
//! identity map and devices: PML4 entries 0..128) are the same in all of
//! them; the user range above (`USER_START..USER_END`) is each one's own, in
//! 4 KiB pages. Memory is anonymous, zero-filled when first touched (or
//! filled from the program when loaded); a fork shares it copy-on-write.
//! The kernel reaches a process's memory through the identity map, never
//! through the process's own mappings.

use alloc::vec::Vec;

use crate::frames::{self, PAGE};
use crate::mem;

/// PML4 entry 128 on: the kernel's identity map stays below (64 TiB).
pub const USER_START: u64 = 0x4000_0000_0000;
pub const USER_END: u64 = 0x7FFF_FFFF_F000;

const P: u64 = 1;
const W: u64 = 2;
const U: u64 = 4;
/// A writable page shared copy-on-write (one of the bits for the OS).
const COW: u64 = 1 << 9;
const NX: u64 = 1 << 63;
const ADDR: u64 = 0x000F_FFFF_FFFF_F000;

pub const PROT_R: u32 = 1;
pub const PROT_W: u32 = 2;
pub const PROT_X: u32 = 4;

/// A mapped range: [start, end), page aligned.
#[derive(Clone)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
}

pub struct Space {
    pml4: u64,
    pub vmas: Vec<Vma>,
    /// the heap: [brk_start, brk)
    pub brk_start: u64,
    pub brk: u64,
    /// where the next mmap without an address goes (downwards)
    pub mmap_top: u64,
    /// pages in memory
    pub pages: u64,
}

fn table(phys: u64) -> &'static mut [u64; 512] {
    // Safety: a page table frame of an address space, identity-mapped
    unsafe { &mut *((phys & ADDR) as *mut [u64; 512]) }
}

fn cr3() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack)) };
    v & ADDR
}

fn invlpg(va: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack)) };
}

/// The leaf flags for `prot`.
fn flags(prot: u32) -> u64 {
    P | U | if prot & PROT_W != 0 { W } else { 0 } | if prot & PROT_X != 0 { 0 } else { NX }
}

pub fn page_down(a: u64) -> u64 {
    a & !(PAGE - 1)
}

pub fn page_up(a: u64) -> u64 {
    a.saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// Every present leaf of the user range: f(va, entry).
fn each_page(pml4: u64, f: &mut dyn FnMut(u64, &mut u64)) {
    for i in mem::KERNEL_ENTRIES..256 {
        let e4 = table(pml4)[i];
        if e4 & P == 0 {
            continue;
        }
        for j in 0..512 {
            let e3 = table(e4)[j];
            if e3 & P == 0 {
                continue;
            }
            for k in 0..512 {
                let e2 = table(e3)[k];
                if e2 & P == 0 {
                    continue;
                }
                let pt = table(e2);
                for l in 0..512 {
                    if pt[l] & P != 0 {
                        let va = (i as u64) << 39 | (j as u64) << 30 | (k as u64) << 21 | (l as u64) << 12;
                        f(va, &mut pt[l]);
                    }
                }
            }
        }
    }
}

impl Space {
    pub fn new() -> Option<Space> {
        let pml4 = frames::alloc()?;
        table(pml4)[..mem::KERNEL_ENTRIES].copy_from_slice(mem::kernel_entries());
        Some(Space { pml4, vmas: Vec::new(), brk_start: 0, brk: 0, mmap_top: 0x7F00_0000_0000, pages: 0 })
    }

    /// Make it the address space the CPU uses.
    pub fn activate(&self) {
        if cr3() != self.pml4 {
            table(self.pml4)[..mem::KERNEL_ENTRIES].copy_from_slice(mem::kernel_entries());
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) self.pml4, options(nostack)) };
        }
    }

    fn active(&self) -> bool {
        cr3() == self.pml4
    }

    /// The leaf entry for `va`, the tables on the way made if `make`.
    fn entry(&mut self, va: u64, make: bool) -> Option<&'static mut u64> {
        let mut t = self.pml4;
        for shift in [39, 30, 21] {
            let e = &mut table(t)[(va >> shift) as usize & 511];
            if *e & P == 0 {
                if !make {
                    return None;
                }
                *e = frames::alloc()? | P | W | U;
            }
            t = *e;
        }
        Some(&mut table(t)[(va >> 12) as usize & 511])
    }

    pub fn vma(&self, va: u64) -> Option<&Vma> {
        self.vmas.iter().find(|v| va >= v.start && va < v.end)
    }

    /// Whether [start, end) is free.
    pub fn free_range(&self, start: u64, end: u64) -> bool {
        start >= USER_START && end <= USER_END && start < end && !self.vmas.iter().any(|v| v.start < end && start < v.end)
    }

    pub fn add(&mut self, start: u64, end: u64, prot: u32) {
        self.vmas.push(Vma { start, end, prot });
    }

    /// Map frame `frame` at `va` (loading a program).
    pub fn put(&mut self, va: u64, frame: u64, prot: u32) -> bool {
        let Some(e) = self.entry(va, true) else { return false };
        *e = frame | flags(prot);
        self.pages += 1;
        true
    }

    /// A page fault at `va` (a write if `write`): resolved (true), or the
    /// process touched what it may not.
    pub fn fault(&mut self, va: u64, write: bool) -> bool {
        let Some(prot) = self.vma(va).map(|v| v.prot) else { return false };
        if write && prot & PROT_W == 0 {
            return false;
        }
        let va = page_down(va);
        let Some(e) = self.entry(va, true) else { return false };
        if *e & P == 0 {
            let Some(f) = frames::alloc() else { return false };
            *e = f | flags(prot);
            self.pages += 1;
            return true;
        }
        if write && *e & COW != 0 {
            let old = *e & ADDR;
            if frames::shared(old) {
                let Some(new) = frames::alloc() else { return false };
                // Safety: both frames are identity-mapped, and ours
                unsafe { core::ptr::copy_nonoverlapping(old as *const u8, new as *mut u8, PAGE as usize) };
                frames::release(old);
                *e = new | flags(prot);
            } else {
                *e = (*e | W) & !COW;
            }
            if self.active() {
                invlpg(va);
            }
            return true;
        }
        false
    }

    /// The frame behind `va`, in memory (faulted in as a write would if
    /// `write`).
    fn frame(&mut self, va: u64, write: bool) -> Option<u64> {
        if va < USER_START || va >= USER_END {
            return None;
        }
        let e = self.entry(page_down(va), false).map(|e| *e).unwrap_or(0);
        if e & P == 0 || (write && e & W == 0) {
            if !self.fault(va, write) {
                return None;
            }
            return self.frame(va, false);
        }
        Some(e & ADDR)
    }

    /// Copy out of the process's memory; false on a bad address.
    pub fn read(&mut self, mut va: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let Some(f) = self.frame(va, false) else { return false };
            let off = va & (PAGE - 1);
            let n = ((PAGE - off) as usize).min(buf.len() - done);
            // Safety: inside one identity-mapped frame of this space
            unsafe { core::ptr::copy_nonoverlapping((f + off) as *const u8, buf[done..].as_mut_ptr(), n) };
            done += n;
            va += n as u64;
        }
        true
    }

    /// Copy into the process's memory; false on a bad address.
    pub fn write(&mut self, mut va: u64, data: &[u8]) -> bool {
        let mut done = 0;
        while done < data.len() {
            let Some(f) = self.frame(va, true) else { return false };
            let off = va & (PAGE - 1);
            let n = ((PAGE - off) as usize).min(data.len() - done);
            // Safety: as in `read`
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), (f + off) as *mut u8, n) };
            done += n;
            va += n as u64;
        }
        true
    }

    /// Unmap [start, end) (page aligned): its ranges and pages go.
    pub fn unmap(&mut self, start: u64, end: u64) {
        let mut kept = Vec::new();
        for v in self.vmas.drain(..) {
            if v.end <= start || v.start >= end {
                kept.push(v);
                continue;
            }
            if v.start < start {
                kept.push(Vma { start: v.start, end: start, prot: v.prot });
            }
            if v.end > end {
                kept.push(Vma { start: end, end: v.end, prot: v.prot });
            }
        }
        self.vmas = kept;
        let active = self.active();
        let mut va = start;
        while va < end {
            if let Some(e) = self.entry(va, false) {
                if *e & P != 0 {
                    frames::release(*e & ADDR);
                    *e = 0;
                    self.pages -= 1;
                    if active {
                        invlpg(va);
                    }
                }
            }
            va += PAGE;
        }
    }

    /// A copy for a forked child: the pages shared copy-on-write.
    pub fn fork(&mut self) -> Option<Space> {
        let mut child = Space::new()?;
        child.vmas = self.vmas.clone();
        (child.brk_start, child.brk, child.mmap_top, child.pages) = (self.brk_start, self.brk, self.mmap_top, self.pages);
        let mut ok = true;
        each_page(self.pml4, &mut |va, e| {
            if *e & W != 0 {
                *e = (*e & !W) | COW;
            }
            match child.entry(va, true) {
                Some(c) => {
                    *c = *e;
                    frames::share(*e & ADDR);
                }
                None => ok = false,
            }
        });
        if self.active() {
            unsafe { core::arch::asm!("mov rax, cr3; mov cr3, rax", out("rax") _, options(nostack)) };
        }
        ok.then_some(child)
    }
}

impl Drop for Space {
    fn drop(&mut self) {
        if self.active() {
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) mem::kernel_pml4(), options(nostack)) };
        }
        each_page(self.pml4, &mut |_, e| frames::release(*e & ADDR));
        let p4 = table(self.pml4);
        for i in mem::KERNEL_ENTRIES..256 {
            if p4[i] & P == 0 {
                continue;
            }
            for j in 0..512 {
                let e3 = table(p4[i])[j];
                if e3 & P == 0 {
                    continue;
                }
                for k in 0..512 {
                    let e2 = table(e3)[k];
                    if e2 & P != 0 {
                        frames::free(e2 & ADDR);
                    }
                }
                frames::free(e3 & ADDR);
            }
            frames::free(p4[i] & ADDR);
        }
        frames::free(self.pml4);
    }
}
