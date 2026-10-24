//! Says hello from ring 3, with its pid and arguments, and exits.
#![no_std]
#![no_main]

use rt::println;

#[unsafe(no_mangle)]
fn main(args: &[&str]) -> i32 {
    let mut uts = [0u8; 390];
    rt::syscall(63, [uts.as_mut_ptr() as u64, 0, 0, 0, 0, 0]);
    let sys = core::str::from_utf8(&uts[..5]).unwrap_or("?");
    println!("hello from ring 3: pid {}, {} on {}, args {:?}", rt::getpid(), args[0], sys, &args[1..]);
    0
}
