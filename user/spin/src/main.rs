//! Loops for ever, never making a system call.
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
fn main(_: &[&str]) -> i32 {
    rt::write(1, b"spinning\n");
    let mut x = 0u64;
    loop {
        x = core::hint::black_box(x.wrapping_add(1));
    }
}
