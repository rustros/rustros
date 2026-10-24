//! User-mode processes: ring 3, each in its own address space (vm.rs), on
//! one CPU. The kernel owns them (registers, memory, the process tree), so
//! the module with the system calls (`rustros_api::module::Syscalls`) can be
//! replaced while they run.
//!
//! The data plane comes first: processes run only when the main loop would
//! otherwise sleep, and every interrupt (a NIC's, the 1 ms timer's) takes the
//! CPU back to it. A system call or a page fault is handled on the main
//! loop's stack, and the process goes on unless an interrupt came in.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::ProcInfo;
use rustros_api::module::{ProcHost, Syscalls, Sysret};

use crate::arch::{self, BY_FAULT, BY_SYSCALL, UserRegs};
use crate::frames::{self, PAGE};
use crate::kprintln;
use crate::vm::{PROT_R, PROT_W, PROT_X, Space, USER_END, USER_START, page_down, page_up};

/// The stack's top and how far it may grow.
const STACK_TOP: u64 = 0x7FFF_FFFF_E000;
const STACK_MAX: u64 = 8 << 20;
/// Where a position-independent program is put (as Linux does).
const PIE_BASE: u64 = 0x5555_5555_4000;
/// Wait statuses: killed by SIGKILL, by SIGSEGV.
const KILLED: i32 = 9;
const SEGV: i32 = 11;

/// The FPU / SSE registers (FXSAVE layout).
#[repr(C, align(16))]
struct Fx([u8; 512]);

enum State {
    Run,
    /// waiting in a system call (made again when something happens to it)
    Wait,
    /// ended: its wait status, for the parent
    Gone(i32),
}

struct Proc {
    pid: u32,
    ppid: u32,
    name: String,
    regs: UserRegs,
    fs: u64,
    fx: Box<Fx>,
    space: Option<Space>,
    state: State,
    cpu_tsc: u64,
}

#[derive(Default)]
pub struct Procs {
    list: Vec<Proc>,
    last_pid: u32,
    /// round robin: the next to look at
    next: usize,
    /// whose registers the FPU holds
    fx_owner: u32,
}

fn fxsave(fx: &mut Fx) {
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) fx.0.as_mut_ptr(), options(nostack)) };
}

fn fxrstor(fx: &Fx) {
    unsafe { core::arch::asm!("fxrstor64 [{}]", in(reg) fx.0.as_ptr(), options(nostack)) };
}

fn fresh_fx() -> Box<Fx> {
    let mut fx = Box::new(Fx([0; 512]));
    fx.0[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
    fx.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
    fx
}

fn le16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]) as u64)
}
fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
}
fn le64(b: &[u8], o: usize) -> u64 {
    le32(b, o) | le32(b, o + 4) << 32
}

/// Load a static ELF64 program (ET_EXEC in the user range, or ET_DYN at
/// PIE_BASE) into `sp`: (entry, program headers' address, their count).
fn load(sp: &mut Space, img: &[u8]) -> Result<(u64, u64, u64), String> {
    if img.len() < 64 || &img[..4] != b"\x7fELF" || img[4] != 2 || img[5] != 1 || le16(img, 18) != 62 {
        return Err(String::from("not an x86-64 ELF program"));
    }
    let bias = match le16(img, 16) {
        2 => 0,
        3 => PIE_BASE,
        _ => return Err(String::from("not an executable")),
    };
    let (phoff, phent, phnum) = (le64(img, 32) as usize, le16(img, 54) as usize, le16(img, 56) as usize);
    if phent < 56 || phnum > 64 || phoff + phent * phnum > img.len() {
        return Err(String::from("bad program headers"));
    }
    let mut phdr = 0;
    let mut end = 0;
    for i in 0..phnum {
        let h = &img[phoff + i * phent..];
        match le32(h, 0) {
            3 => return Err(String::from("dynamically linked programs are not supported yet")),
            6 => phdr = le64(h, 16) + bias,
            1 => {}
            _ => continue,
        }
        if le32(h, 0) != 1 {
            continue;
        }
        let (fl, off, va, filesz, memsz) = (le32(h, 4), le64(h, 8) as usize, le64(h, 16) + bias, le64(h, 32), le64(h, 40));
        let (start, stop) = (page_down(va), page_up(va.saturating_add(memsz)));
        if memsz < filesz || off.saturating_add(filesz as usize) > img.len() || !sp.free_range(start, stop) {
            return Err(String::from("a segment outside the user range, or overlapping"));
        }
        let prot = if fl & 4 != 0 { PROT_R } else { 0 } | if fl & 2 != 0 { PROT_W } else { 0 } | if fl & 1 != 0 { PROT_X } else { 0 };
        sp.add(start, stop, prot);
        // the pages with file data now; the rest (bss) on first touch
        let mut p = start;
        while p < page_up(va + filesz) {
            let f = frames::alloc().ok_or("out of memory")?;
            let (from, to) = (p.max(va), (p + PAGE).min(va + filesz));
            // Safety: a fresh identity-mapped frame
            unsafe { core::ptr::copy_nonoverlapping(img[off + (from - va) as usize..].as_ptr(), (f + from - p) as *mut u8, (to - from) as usize) };
            if !sp.put(p, f, prot) {
                return Err(String::from("out of memory"));
            }
            p += PAGE;
        }
        end = end.max(stop);
        if phdr == 0 && off == 0 {
            phdr = va + le64(img, 32);
        }
    }
    if end == 0 {
        return Err(String::from("nothing to load"));
    }
    (sp.brk_start, sp.brk) = (end, end);
    Ok((le64(img, 24) + bias, phdr, phnum as u64))
}

/// The initial stack as Linux makes it: argc, argv, envp, the auxiliary
/// vector, then the strings. Its pointer.
fn stack(sp: &mut Space, args: &[&str], env: &[&str], aux: &[(u64, u64)]) -> Option<u64> {
    sp.add(STACK_TOP - STACK_MAX, STACK_TOP, PROT_R | PROT_W);
    let mut top = STACK_TOP;
    let mut put = |sp: &mut Space, s: &[u8]| -> Option<u64> {
        top -= s.len() as u64;
        sp.write(top, s).then_some(top)
    };
    let random = put(sp, &crate::arch::rdtsc().to_le_bytes().repeat(2))?;
    let mut strs = Vec::new();
    for s in args.iter().chain(env) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        strs.push(put(sp, &b)?);
    }
    let mut words: Vec<u64> = alloc::vec![args.len() as u64];
    words.extend_from_slice(&strs[..args.len()]);
    words.push(0);
    words.extend_from_slice(&strs[args.len()..]);
    words.push(0);
    for &(k, v) in aux {
        words.extend_from_slice(&[k, v]);
    }
    words.extend_from_slice(&[25, random, 0, 0]); // AT_RANDOM, AT_NULL
    let at = (top - words.len() as u64 * 8) & !15;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    sp.write(at, &bytes).then_some(at)
}

impl Procs {
    fn pid(&mut self) -> u32 {
        loop {
            self.last_pid = self.last_pid % 4_000_000 + 1;
            let p = self.last_pid;
            if !self.list.iter().any(|x| x.pid == p) {
                return p;
            }
        }
    }

    pub fn spawn(&mut self, img: &[u8], args: &[&str]) -> Result<u32, String> {
        let mut sp = Space::new().ok_or("out of memory")?;
        let (entry, phdr, phnum) = load(&mut sp, img)?;
        let aux = [(3, phdr), (4, 56), (5, phnum), (6, PAGE), (9, entry), (11, 0), (12, 0), (13, 0), (14, 0)];
        let rsp = stack(&mut sp, args, &["PATH=/bin:/usr/bin"], &aux).ok_or("out of memory")?;
        let pid = self.pid();
        let name = String::from(args.first().map_or("?", |a| a.rsplit('/').next().unwrap_or(a)));
        kprintln!("proc: {} {} started", pid, name);
        let regs = UserRegs { rip: entry, rsp, rflags: 0x202, ..UserRegs::default() };
        self.list.push(Proc { pid, ppid: 0, name, regs, fs: 0, fx: fresh_fx(), space: Some(sp), state: State::Run, cpu_tsc: 0 });
        Ok(pid)
    }

    fn find(&self, pid: u32) -> Option<usize> {
        self.list.iter().position(|p| p.pid == pid)
    }

    /// Process `i` ends with wait status `status`: its memory goes; its
    /// parent hears of it (one that nobody waits for is gone at once).
    fn end(&mut self, i: usize, status: i32) {
        let pid = self.list[i].pid;
        self.list[i].space = None;
        if self.fx_owner == pid {
            self.fx_owner = 0;
        }
        let ppid = self.list[i].ppid;
        match self.find(ppid) {
            Some(pi) => {
                self.list[i].state = State::Gone(status);
                if matches!(self.list[pi].state, State::Wait) {
                    self.list[pi].state = State::Run;
                }
            }
            None => {
                self.list.remove(i);
            }
        }
        for c in self.list.iter_mut().filter(|c| c.ppid == pid) {
            c.ppid = 0;
        }
        // ended orphans nobody will wait for
        self.list.retain(|c| c.ppid != 0 || !matches!(c.state, State::Gone(_)));
    }

    pub fn kill(&mut self, pid: u32) -> bool {
        match self.find(pid).filter(|&i| !matches!(self.list[i].state, State::Gone(_))) {
            Some(i) => {
                kprintln!("proc: {} {} killed", pid, self.list[i].name);
                self.end(i, KILLED);
                true
            }
            None => false,
        }
    }

    pub fn list(&self) -> Vec<ProcInfo> {
        self.list
            .iter()
            .map(|p| ProcInfo {
                pid: p.pid,
                ppid: p.ppid,
                name: p.name.clone(),
                state: match p.state {
                    State::Run => String::from("running"),
                    State::Wait => String::from("waiting"),
                    State::Gone(s) => format!("ended {s:#x}"),
                },
                mem_kib: p.space.as_ref().map_or(0, |s| s.pages * 4),
                cpu_ms: p.cpu_tsc / arch::tsc_per_ms(),
            })
            .collect()
    }

    pub fn runnable(&self) -> bool {
        self.list.iter().any(|p| matches!(p.state, State::Run))
    }
}

/// What a system call sees of the kernel.
struct Host<'a> {
    procs: &'a mut Procs,
    i: usize,
    exited: bool,
}

impl Host<'_> {
    fn me(&mut self) -> &mut Proc {
        &mut self.procs.list[self.i]
    }
    fn space(&mut self) -> &mut Space {
        self.procs.list[self.i].space.as_mut().unwrap()
    }
}

impl ProcHost for Host<'_> {
    fn pid(&self) -> u32 {
        self.procs.list[self.i].pid
    }
    fn ppid(&self) -> u32 {
        self.procs.list[self.i].ppid
    }
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool {
        self.space().read(addr, buf)
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> bool {
        self.space().write(addr, data)
    }
    fn console(&mut self, data: &[u8]) {
        crate::kprint!("{}", String::from_utf8_lossy(data));
    }
    fn exit(&mut self, status: i32) {
        self.exited = true;
        let i = self.i;
        self.procs.end(i, status);
    }
    fn fork(&mut self) -> Result<u32, i32> {
        let pid = self.procs.pid();
        let i = self.i;
        let me = &mut self.procs.list[i];
        let space = me.space.as_mut().unwrap().fork().ok_or(12)?; // ENOMEM
        // the FPU holds this process's registers now
        let mut fx = fresh_fx();
        fxsave(&mut fx);
        let regs = UserRegs { rax: 0, ..me.regs.clone() };
        let child = Proc { pid, ppid: me.pid, name: me.name.clone(), regs, fs: me.fs, fx, space: Some(space), state: State::Run, cpu_tsc: 0 };
        self.procs.list.push(child);
        Ok(pid)
    }
    fn wait(&mut self, pid: i32) -> Result<Option<(u32, i32)>, i32> {
        let me = self.pid();
        let mine = |p: &Proc| p.ppid == me && (pid == -1 || p.pid as i32 == pid);
        if !self.procs.list.iter().any(mine) {
            return Err(10); // ECHILD
        }
        let Some(c) = self.procs.list.iter().position(|p| mine(p) && matches!(p.state, State::Gone(_))) else { return Ok(None) };
        let c = self.procs.list.remove(c);
        self.i = self.procs.find(me).unwrap_or(0);
        let State::Gone(status) = c.state else { return Ok(None) };
        Ok(Some((c.pid, status)))
    }
    fn map(&mut self, addr: u64, len: u64, prot: u32, fixed: bool) -> Result<u64, i32> {
        let len = page_up(len);
        let sp = self.space();
        if len == 0 {
            return Err(22); // EINVAL
        }
        let start = if fixed {
            if addr & (PAGE - 1) != 0 || addr < USER_START || addr.saturating_add(len) > USER_END {
                return Err(22);
            }
            sp.unmap(addr, addr + len);
            addr
        } else if addr != 0 && sp.free_range(page_down(addr), page_down(addr) + len) {
            page_down(addr)
        } else {
            let mut at = sp.mmap_top - len;
            while !sp.free_range(at, at + len) {
                at = sp.vmas.iter().filter(|v| v.start < at + len && at < v.end).map(|v| v.start).min().unwrap_or(at).checked_sub(len).filter(|&a| a >= USER_START).ok_or(12)?;
            }
            sp.mmap_top = at;
            at
        };
        sp.add(start, start + len, prot);
        Ok(start)
    }
    fn unmap(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        if addr & (PAGE - 1) != 0 || len == 0 {
            return Err(22);
        }
        self.space().unmap(addr, page_up(addr.saturating_add(len)));
        Ok(())
    }
    fn brk(&mut self, addr: u64) -> u64 {
        let sp = self.space();
        let (start, cur) = (sp.brk_start, sp.brk);
        if addr < start || addr > start + (1 << 30) {
            return cur;
        }
        let (old_end, new_end) = (page_up(cur), page_up(addr));
        if new_end > old_end {
            if !sp.free_range(old_end, new_end) {
                return cur;
            }
            sp.add(old_end, new_end, PROT_R | PROT_W);
        } else if new_end < old_end {
            sp.unmap(new_end, old_end);
        }
        sp.brk = addr;
        addr
    }
    fn set_fs(&mut self, base: u64) {
        self.me().fs = base;
        arch::write_fs_base(base);
    }
    fn now_ns(&self) -> u64 {
        arch::now_us() * 1000
    }
    fn unix_ns(&self) -> u64 {
        arch::unix_time() * 1_000_000_000 + (arch::now_us() % 1_000_000) * 1000
    }
}

/// Run a process for a while (the CPU would otherwise sleep): until an
/// interrupt comes in. Called with interrupts off. True: a process ran, and
/// interrupts are on again. False: none could run, and interrupts are still
/// off, so the caller's `sti; hlt` cannot miss an interrupt that comes in
/// meanwhile (it would otherwise sleep until the next timer tick).
pub fn run(procs: &mut Procs, syscalls: Option<&mut dyn Syscalls>) -> bool {
    let n = procs.list.len();
    let Some(i) = (0..n).map(|k| (procs.next + k) % n).find(|&i| matches!(procs.list[i].state, State::Run)) else {
        return false;
    };
    procs.next = i + 1;
    let mut syscalls = syscalls;
    let mut i = i;
    let pid = procs.list[i].pid;
    {
        let p = &mut procs.list[i];
        p.space.as_ref().unwrap().activate();
        arch::write_fs_base(p.fs);
    }
    if procs.fx_owner != pid {
        if let Some(o) = procs.list.iter_mut().find(|o| o.pid == procs.fx_owner) {
            fxsave(&mut o.fx);
        }
        fxrstor(&procs.list[i].fx);
        procs.fx_owner = pid;
    }
    // `syscall` allowed for the time a process runs (see arch::syscall_insn)
    arch::syscall_insn(true);
    loop {
        let t = arch::rdtsc();
        // Safety: the process's address space is active; its registers stay put
        let why = unsafe { arch::user_enter(&mut procs.list[i].regs) };
        procs.list[i].cpu_tsc += arch::rdtsc() - t;
        match why {
            BY_SYSCALL => {
                let r = &procs.list[i].regs;
                let (nr, args) = (r.rax, [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]);
                let Some(sc) = syscalls.as_deref_mut() else {
                    kprintln!("proc: {} {}: no system call layer installed (module linux); killed", pid, procs.list[i].name);
                    procs.end(i, KILLED);
                    break;
                };
                let mut h = Host { procs: &mut *procs, i, exited: false };
                let ret = sc.syscall(&mut h, nr, args);
                let exited = h.exited;
                match (ret, exited) {
                    (_, true) | (Sysret::Exit, _) => break,
                    (Sysret::Value(v), _) => {
                        // a wait may have moved the caller in the list
                        i = procs.find(pid).unwrap_or(i);
                        procs.list[i].regs.rax = v as u64;
                    }
                    (Sysret::Wait, _) => {
                        // made again once something happens to it: back
                        // before the `syscall` (2 bytes)
                        i = procs.find(pid).unwrap_or(i);
                        let p = &mut procs.list[i];
                        p.regs.rax = nr;
                        p.regs.rip -= 2;
                        p.state = State::Wait;
                        break;
                    }
                }
            }
            BY_FAULT => {
                // Safety: written by the fault, interrupts are off
                let (vector, err, cr2) = unsafe { *arch::FAULT.get() };
                let p = &mut procs.list[i];
                if vector == 14 && err & 4 != 0 && p.space.as_mut().unwrap().fault(cr2, err & 2 != 0) {
                    continue;
                }
                kprintln!(
                    "proc: {} {}: {} at {:#x} (rip {:#x}); killed",
                    pid,
                    p.name,
                    if vector == 14 { "bad memory access" } else { "CPU exception" },
                    if vector == 14 { cr2 } else { vector },
                    p.regs.rip
                );
                procs.end(i, SEGV);
                break;
            }
            _ => break, // BY_INTERRUPT: the main loop's turn
        }
    }
    arch::syscall_insn(false);
    arch::sti();
    true
}
