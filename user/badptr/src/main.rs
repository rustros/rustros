//! A bad pointer: first as a system call argument (EFAULT), then touched
//! (the process is killed, nothing else).
#![no_std]
#![no_main]

use rt::println;

#[unsafe(no_mangle)]
fn main(_: &[&str]) -> i32 {
    let r = rt::syscall(1, [1, 0x1000, 5, 0, 0, 0]);
    println!("write from a bad pointer: {}", r);
    println!("now touching kernel memory");
    // Safety: it is not; the point is the fault
    unsafe { core::ptr::write_volatile(0x10_0000 as *mut u64, 1) };
    println!("still alive?!");
    1
}
