//! A minimal runtime for the test programs: the entry point (argc and argv
//! from the initial stack), Linux system calls, printing.
#![no_std]

use core::arch::asm;
use core::fmt::Write;

core::arch::global_asm!(
    ".global _start",
    "_start:",
    "xor ebp, ebp",
    "mov r12, rsp",
    "and rsp, -16",
    "lea rdi, [rip + __ehdr_start]",
    "lea rsi, [rip + _DYNAMIC]",
    "call rt_relocate",
    "mov rdi, r12",
    "call rt_start",
    "ud2",
);

unsafe extern "Rust" {
    fn main(args: &[&str]) -> i32;
}

/// Apply our own relative relocations (a static PIE; nothing else does).
/// Runs before anything that could need them.
#[unsafe(no_mangle)]
unsafe extern "C" fn rt_relocate(base: u64, dynamic: *const u64) {
    // Safety: the linker's _DYNAMIC: (tag, value) pairs up to DT_NULL
    unsafe {
        let (mut rela, mut size) = (0, 0);
        let mut d = dynamic;
        while *d != 0 {
            match *d {
                7 => rela = *d.add(1),
                8 => size = *d.add(1),
                _ => {}
            }
            d = d.add(2);
        }
        let mut r = (base + rela) as *const u64;
        let end = (base + rela + size) as *const u64;
        while r < end {
            // R_X86_64_RELATIVE
            if *r.add(1) as u32 == 8 {
                *((base + *r) as *mut u64) = base + *r.add(2);
            }
            r = r.add(3);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rt_start(sp: *const u64) -> ! {
    let mut args: [&str; 16] = [""; 16];
    // Safety: the kernel's initial stack: argc, then argv pointers to C strings
    let n = unsafe {
        let argc = (*sp as usize).min(16);
        for (i, a) in args.iter_mut().enumerate().take(argc) {
            let p = *sp.add(1 + i) as *const u8;
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            *a = core::str::from_utf8(core::slice::from_raw_parts(p, len)).unwrap_or("?");
        }
        argc
    };
    exit(unsafe { main(&args[..n]) })
}

pub fn syscall(nr: u64, a: [u64; 6]) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr as i64 => r, in("rdi") a[0], in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5], lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

pub fn write(fd: u64, b: &[u8]) -> i64 {
    syscall(1, [fd, b.as_ptr() as u64, b.len() as u64, 0, 0, 0])
}

pub fn exit(code: i32) -> ! {
    syscall(231, [code as u64, 0, 0, 0, 0, 0]);
    loop {}
}

pub fn getpid() -> i64 {
    syscall(39, [0; 6])
}

pub fn fork() -> i64 {
    syscall(57, [0; 6])
}

/// (pid, wait status)
pub fn wait(pid: i64) -> (i64, i32) {
    let mut st = 0i32;
    let r = syscall(61, [pid as u64, &mut st as *mut i32 as u64, 0, 0, 0, 0]);
    (r, st)
}

pub fn mmap(len: u64) -> i64 {
    // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS
    syscall(9, [0, len, 3, 0x22, u64::MAX, 0])
}

pub fn brk(at: u64) -> u64 {
    syscall(12, [at, 0, 0, 0, 0, 0]) as u64
}

pub struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(1, s.as_bytes());
        Ok(())
    }
}

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => {{ use core::fmt::Write; let _ = writeln!($crate::Out, $($t)*); }};
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = writeln!(Out, "panic: {info}");
    exit(101)
}
