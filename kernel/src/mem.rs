//! Memory: identity mapping above 4 GiB and the kernel heap.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use crate::Global;

// ---------------------------------------------------------------- paging

unsafe extern "C" {
    static mut boot_pml4: [u64; 512];
}

#[repr(C, align(4096))]
struct Table([u64; 512]);

/// Spare page tables for MMIO above 4 GiB (OVMF likes to put 64-bit BARs
/// far up, beyond 512 GiB).
static EXTRA: Global<[Table; 16]> = Global::new([const { Table([0; 512]) }; 16]);
static EXTRA_USED: Global<usize> = Global::new(0);

/// Return the table referenced by `entry`, allocating one if it is empty.
fn next_table(entry: &mut u64) -> Option<&'static mut [u64; 512]> {
    if *entry & 1 == 0 {
        // Safety: single core, called during init only.
        let (pool, used) = unsafe { (EXTRA.get(), EXTRA_USED.get()) };
        let t = pool.get_mut(*used)?;
        *used += 1;
        *entry = t.0.as_ptr() as u64 | 3;
    }
    // Safety: identity-mapped page table we own.
    Some(unsafe { &mut *((*entry & 0x000F_FFFF_FFFF_F000) as *mut [u64; 512]) })
}

/// Make sure `[phys, phys+len)` is identity-mapped (uncached). The first 4 GiB
/// are mapped by boot.rs with 2 MiB pages; this adds more of them on demand.
pub fn map_identity(phys: u64, len: u64) -> bool {
    map(phys, len, false)
}

/// `map_identity` for a device's registers: uncached below 4 GiB too (boot.rs
/// maps that cacheable; firmware MTRRs usually cover device memory, not always).
pub fn map_device(phys: u64, len: u64) -> bool {
    map(phys, len, true)
}

fn map(phys: u64, len: u64, uncached_low: bool) -> bool {
    const MB2: u64 = 2 << 20;
    if phys + len <= 4 << 30 && !uncached_low {
        return true;
    }
    if phys + len > 1 << 47 {
        return false;
    }
    let pml4 = unsafe { &mut *(&raw mut boot_pml4) };
    let mut a = phys & !(MB2 - 1);
    while a < phys + len {
        let Some(pdpt) = next_table(&mut pml4[(a >> 39) as usize & 511]) else { return false };
        let Some(pd) = next_table(&mut pdpt[(a >> 30) as usize & 511]) else { return false };
        let e = &mut pd[(a >> 21) as usize & 511];
        if *e & 1 == 0 {
            *e = a | 0x9B; // present | writable | PWT | PCD | 2 MiB page
        } else if uncached_low {
            *e |= 0x18; // PWT | PCD
        }
        a += MB2;
    }
    unsafe { core::arch::asm!("mov rax, cr3; mov cr3, rax", out("rax") _, options(nostack)) }
    true
}

// ---------------------------------------------------------------- heap

/// WebAssembly apps need a few MiB each; the VM needs >= 256 MiB of RAM.
pub const HEAP_SIZE: usize = 96 << 20;

#[repr(C, align(4096))]
struct HeapArea([u8; HEAP_SIZE]);
static HEAP_AREA: Global<HeapArea> = Global::new(HeapArea([0; HEAP_SIZE]));

/// Free block header, stored inside the free block itself.
struct Node {
    size: usize,
    next: *mut Node,
}

const UNIT: usize = 16; // every block is a multiple of 16 bytes, 16-aligned

/// Address-ordered first-fit free list with coalescing.
pub struct Heap {
    head: Global<*mut Node>,
    free: Global<usize>,
}

#[global_allocator]
pub static HEAP: Heap = Heap { head: Global::new(null_mut()), free: Global::new(0) };

fn round_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

impl Heap {
    pub fn init(&self) {
        unsafe {
            let base = HEAP_AREA.get().0.as_mut_ptr() as *mut Node;
            base.write(Node { size: HEAP_SIZE, next: null_mut() });
            *self.head.get() = base;
            *self.free.get() = HEAP_SIZE;
        }
    }

    pub fn free_bytes(&self) -> usize {
        unsafe { *self.free.get() }
    }

    fn sizes(layout: Layout) -> (usize, usize) {
        (round_up(layout.size().max(UNIT), UNIT), layout.align().max(UNIT))
    }
}

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let (size, align) = Heap::sizes(layout);
        unsafe {
            let head = self.head.get();
            let mut link: *mut *mut Node = head;
            while !(*link).is_null() {
                let cur = *link;
                let start = cur as usize;
                let end = start + (*cur).size;
                let a = round_up(start, align);
                if a + size <= end {
                    // front gap and back gap are multiples of UNIT, so either
                    // empty or big enough to hold a Node
                    let mut next = (*cur).next;
                    if end > a + size {
                        let back = (a + size) as *mut Node;
                        back.write(Node { size: end - a - size, next });
                        next = back;
                    }
                    if a > start {
                        (*cur).size = a - start;
                        (*cur).next = next;
                    } else {
                        *link = next;
                    }
                    *self.free.get() -= size;
                    return a as *mut u8;
                }
                link = &raw mut (*cur).next;
            }
        }
        null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let (size, _) = Heap::sizes(layout);
        unsafe {
            *self.free.get() += size;
            let blk = ptr as *mut Node;
            let addr = ptr as usize;
            // find insertion point: prev < blk < cur
            let mut prev: *mut Node = null_mut();
            let mut cur = *self.head.get();
            while !cur.is_null() && (cur as usize) < addr {
                prev = cur;
                cur = (*cur).next;
            }
            blk.write(Node { size, next: cur });
            // merge with following block
            if !cur.is_null() && addr + size == cur as usize {
                (*blk).size += (*cur).size;
                (*blk).next = (*cur).next;
            }
            // merge with preceding block
            if !prev.is_null() && prev as usize + (*prev).size == addr {
                (*prev).size += (*blk).size;
                (*prev).next = (*blk).next;
            } else if prev.is_null() {
                *self.head.get() = blk;
            } else {
                (*prev).next = blk;
            }
        }
    }
}
