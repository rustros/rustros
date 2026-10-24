//! fork, wait4, copy-on-write, anonymous mmap and brk.
#![no_std]
#![no_main]

use rt::println;

static mut BUF: [u8; 8192] = [b'p'; 8192];

fn buf() -> &'static mut [u8; 8192] {
    // Safety: one thread
    unsafe { &mut *(&raw mut BUF) }
}

#[unsafe(no_mangle)]
fn main(_: &[&str]) -> i32 {
    // memory: 1 MiB anonymous, 64 KiB more heap
    let m = rt::mmap(1 << 20);
    if m < 0 {
        println!("mmap failed: {}", m);
        return 1;
    }
    let mem = unsafe { core::slice::from_raw_parts_mut(m as *mut u8, 1 << 20) };
    for (i, b) in mem.iter_mut().enumerate() {
        *b = i as u8;
    }
    let start = rt::brk(0);
    let end = rt::brk(start + 65536);
    if end != start + 65536 {
        println!("brk failed");
        return 1;
    }
    unsafe { core::ptr::write_bytes(start as *mut u8, 0xAB, 65536) };
    let child = rt::fork();
    if child == 0 {
        // the child sees the parent's memory, and writes its own copy
        let ok = buf().iter().all(|&b| b == b'p') && mem.iter().enumerate().all(|(i, &b)| b == i as u8) && unsafe { *(start as *const u8) } == 0xAB;
        buf().fill(b'c');
        mem.fill(0);
        rt::exit(if ok { 7 } else { 1 });
    }
    let (pid, st) = rt::wait(child);
    let cow = buf().iter().all(|&b| b == b'p') && mem.iter().enumerate().all(|(i, &b)| b == i as u8);
    println!("fork: child {} ended with status {:#x}; parent's memory {}", pid, st, if cow { "untouched (copy-on-write)" } else { "CHANGED" });
    // many children, one after the other: their memory comes back
    for _ in 0..50 {
        match rt::fork() {
            0 => rt::exit(3),
            c if c > 0 => {
                if rt::wait(c).1 != 3 << 8 {
                    println!("a child's status is wrong");
                    return 1;
                }
            }
            e => {
                println!("fork failed: {}", e);
                return 1;
            }
        }
    }
    let (r, _) = rt::wait(-1);
    println!("50 children done; wait with none left: {}", r);
    if pid == child && st == 7 << 8 && cow && r == -10 { 0 } else { 1 }
}
