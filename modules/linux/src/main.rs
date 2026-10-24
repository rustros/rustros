//! The Linux system calls of user-mode processes (x86-64 numbers and
//! semantics, from the man pages): the kernel hands every `syscall` here.
//! A beginning: the console as fd 1 and 2, memory (brk, anonymous mmap),
//! the process calls (fork, wait4, exit) and a few queries; the rest is
//! ENOSYS. Files, signals and the rest come with the compatibility layer.
#![no_std]
#![no_main]

use rustros_module::rustros_api::module::{ProcHost, Syscalls, Sysret};

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const ENODEV: i64 = 19;

const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const WNOHANG: u64 = 1;
const ARCH_SET_FS: u64 = 0x1002;

struct Linux;

fn err(e: i32) -> Sysret {
    Sysret::Value(-(e as i64))
}

/// Up to `len` bytes at `addr` to the console; how many.
fn console(h: &mut dyn ProcHost, addr: u64, len: u64) -> Result<u64, i64> {
    let mut buf = [0u8; 512];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(buf.len() as u64) as usize;
        if !h.read(addr + done, &mut buf[..n]) {
            return if done > 0 { Ok(done) } else { Err(EFAULT) };
        }
        h.console(&buf[..n]);
        done += n as u64;
    }
    Ok(done)
}

impl Syscalls for Linux {
    fn syscall(&mut self, h: &mut dyn ProcHost, nr: u64, a: [u64; 6]) -> Sysret {
        let v = |r: Result<u64, i64>| Sysret::Value(r.unwrap_or_else(|e| (-e) as u64) as i64);
        match nr {
            // write
            1 if a[0] == 1 || a[0] == 2 => v(console(h, a[1], a[2])),
            1 => Sysret::Value(-EBADF),
            // writev
            20 if a[0] == 1 || a[0] == 2 => {
                let mut total = 0;
                for i in 0..a[2].min(1024) {
                    let mut iov = [0u8; 16];
                    if !h.read(a[1] + i * 16, &mut iov) {
                        return Sysret::Value(-EFAULT);
                    }
                    let base = u64::from_le_bytes(iov[..8].try_into().unwrap());
                    let len = u64::from_le_bytes(iov[8..].try_into().unwrap());
                    match console(h, base, len) {
                        Ok(n) => total += n,
                        Err(e) => return Sysret::Value(-e),
                    }
                }
                Sysret::Value(total as i64)
            }
            // mmap: anonymous memory only, until there are files
            9 => {
                if a[3] & MAP_ANONYMOUS == 0 {
                    return Sysret::Value(-ENODEV);
                }
                match h.map(a[0], a[1], a[2] as u32, a[3] & MAP_FIXED != 0) {
                    Ok(at) => Sysret::Value(at as i64),
                    Err(e) => err(e),
                }
            }
            // munmap
            11 => match h.unmap(a[0], a[1]) {
                Ok(()) => Sysret::Value(0),
                Err(e) => err(e),
            },
            // brk
            12 => Sysret::Value(h.brk(a[0]) as i64),
            // sched_yield
            24 => Sysret::Value(0),
            // getpid, getppid, gettid
            39 | 186 => Sysret::Value(h.pid() as i64),
            110 => Sysret::Value(h.ppid() as i64),
            // getuid, getgid, geteuid, getegid: root
            102 | 104 | 107 | 108 => Sysret::Value(0),
            // fork
            57 => match h.fork() {
                Ok(pid) => Sysret::Value(pid as i64),
                Err(e) => err(e),
            },
            // exit, exit_group: status as wait reports it
            60 | 231 => {
                h.exit(((a[0] & 0xFF) << 8) as i32);
                Sysret::Exit
            }
            // wait4
            61 => match h.wait(a[0] as i32) {
                Ok(Some((pid, status))) => {
                    if a[1] != 0 && !h.write(a[1], &status.to_le_bytes()) {
                        return Sysret::Value(-EFAULT);
                    }
                    Sysret::Value(pid as i64)
                }
                Ok(None) if a[2] & WNOHANG != 0 => Sysret::Value(0),
                Ok(None) => Sysret::Wait,
                Err(e) => err(e),
            },
            // uname
            63 => {
                let mut u = [0u8; 65 * 6];
                for (i, f) in [&b"Linux"[..], b"rustros", b"6.1.0-rustros", b"#1", b"x86_64", b"(none)"].iter().enumerate() {
                    u[i * 65..i * 65 + f.len()].copy_from_slice(f);
                }
                Sysret::Value(if h.write(a[0], &u) { 0 } else { -EFAULT })
            }
            // arch_prctl
            158 if a[0] == ARCH_SET_FS => {
                h.set_fs(a[1]);
                Sysret::Value(0)
            }
            158 => Sysret::Value(-EINVAL),
            // set_tid_address: the thread id; set_robust_list
            218 => Sysret::Value(h.pid() as i64),
            273 => Sysret::Value(0),
            // clock_gettime: CLOCK_REALTIME, CLOCK_MONOTONIC (and the rest as monotonic)
            228 => {
                let ns = if a[0] == 0 { h.unix_ns() } else { h.now_ns() };
                let mut ts = [0u8; 16];
                ts[..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
                ts[8..].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
                Sysret::Value(if h.write(a[1], &ts) { 0 } else { -EFAULT })
            }
            _ => Sysret::Value(-ENOSYS),
        }
    }
}

rustros_module::export_syscalls!(Linux);
