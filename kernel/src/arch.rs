//! CPU-level bits: port I/O, IDT, 8259 PIC, PIT, TSC clock, reboot.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::Global;

pub unsafe fn outb(port: u16, v: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}
pub unsafe fn outw(port: u16, v: u16) {
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe { asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}
pub unsafe fn outl(port: u16, v: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) }
}
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe { asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// A random number from the CPU (RDSEED, else RDRAND); None if it has
/// neither or they keep failing.
pub fn hw_random() -> Option<u64> {
    use core::arch::x86_64::__cpuid;
    use core::sync::atomic::AtomicU8;
    // 0 = not probed, 1 = none, 2 = RDRAND, 3 = RDSEED
    static KIND: AtomicU8 = AtomicU8::new(0);
    let mut kind = KIND.load(Ordering::Relaxed);
    if kind == 0 {
        let rdrand = __cpuid(1).ecx & (1 << 30) != 0;
        let rdseed = __cpuid(0).eax >= 7 && __cpuid(7).ebx & (1 << 18) != 0;
        kind = if rdseed { 3 } else if rdrand { 2 } else { 1 };
        KIND.store(kind, Ordering::Relaxed);
    }
    for _ in 0..16 {
        let (v, ok): (u64, u8);
        unsafe {
            if kind == 3 {
                asm!("rdseed {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack));
            } else if kind == 2 {
                asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack));
            } else {
                return None;
            }
        }
        if ok == 1 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    // RDSEED can run dry under load; RDRAND (a DRBG reseeded from it) does not
    if kind == 3 && __cpuid(1).ecx & (1 << 30) != 0 {
        KIND.store(2, Ordering::Relaxed);
        return hw_random();
    }
    None
}

pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) }
    ((hi as u64) << 32) | lo as u64
}

pub fn halt_forever() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) }
    }
}

/// Sleep until the next interrupt. `sti; hlt` is atomic, so no wakeup is lost.
pub fn wait_for_interrupt() {
    unsafe { asm!("sti; hlt", options(nomem, nostack)) }
}

// ---------------------------------------------------------------- IDT

#[derive(Clone, Copy)]
#[repr(C)]
struct IdtEntry {
    off_lo: u16,
    sel: u16,
    ist: u8,
    attr: u8,
    off_mid: u16,
    off_hi: u32,
    zero: u32,
}

impl IdtEntry {
    const EMPTY: IdtEntry = IdtEntry { off_lo: 0, sel: 0, ist: 0, attr: 0, off_mid: 0, off_hi: 0, zero: 0 };
    fn new(handler: u64) -> IdtEntry {
        IdtEntry {
            off_lo: handler as u16,
            sel: 0x08,
            ist: 0,
            attr: 0x8E, // present, ring 0, interrupt gate
            off_mid: (handler >> 16) as u16,
            off_hi: (handler >> 32) as u32,
            zero: 0,
        }
    }
}

#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

static IDT: Global<[IdtEntry; 256]> = Global::new([IdtEntry::EMPTY; 256]);

unsafe extern "C" {
    static isr_table: [u64; 48];
    fn isr_other();
}

/// Register layout pushed by `isr_common` in boot.rs.
#[repr(C)]
pub struct Frame {
    r15: u64, r14: u64, r13: u64, r12: u64, r11: u64, r10: u64, r9: u64, r8: u64,
    rbp: u64, rdi: u64, rsi: u64, rdx: u64, rcx: u64, rbx: u64, rax: u64,
    vector: u64,
    err: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

static IRQS: AtomicU64 = AtomicU64::new(0);

/// Software watchdog: the main loop must check in this often.
pub const WATCHDOG_MS: u64 = 30_000;
/// now_ms() of the main loop's last iteration; 0 = not armed yet.
static HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Called by the main loop on every iteration.
pub fn heartbeat() {
    HEARTBEAT.store(now_ms().max(1), Ordering::Relaxed);
}

#[unsafe(no_mangle)]
extern "C" fn isr_handler(f: &mut Frame) {
    match f.vector {
        0..=31 => {
            let cr2: u64;
            unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) }
            crate::crash(format_args!(
                "CPU exception {} err={:#x} rip={:#x} rsp={:#x} cr2={:#x} rax={:#x}",
                f.vector, f.err, f.rip, f.rsp, cr2, f.rax
            ));
        }
        v => {
            if v == 32 {
                IRQS.fetch_add(1, Ordering::Relaxed);
                let beat = HEARTBEAT.load(Ordering::Relaxed);
                if beat != 0 && now_ms().saturating_sub(beat) > WATCHDOG_MS {
                    // The main loop is stuck (an app looping forever?).
                    HEARTBEAT.store(0, Ordering::Relaxed);
                    crate::watchdog_expired();
                }
            }
            if (33..48).contains(&v) {
                crate::virtio::ack_irq((v - 32) as u8);
            }
            unsafe {
                if v >= 40 {
                    outb(0xA0, 0x20);
                }
                outb(0x20, 0x20);
            }
        }
    }
}

/// Let a PIC line through (and the cascade for lines 8-15).
pub fn unmask_irq(line: u8) {
    unsafe {
        if line < 8 {
            outb(0x21, inb(0x21) & !(1 << line));
        } else {
            outb(0x21, inb(0x21) & !(1 << 2));
            outb(0xA1, inb(0xA1) & !(1 << (line - 8)));
        }
    }
}

pub fn cli() {
    unsafe { asm!("cli", options(nomem, nostack)) }
}

pub fn sti() {
    unsafe { asm!("sti", options(nomem, nostack)) }
}

/// Number of timer interrupts seen so far (used to detect whether IRQs work).
pub fn irq_count() -> u64 {
    IRQS.load(Ordering::Relaxed)
}

pub fn init_interrupts() {
    // Safety: single core, interrupts are still disabled here.
    let idt = unsafe { IDT.get() };
    for (i, e) in idt.iter_mut().enumerate() {
        let h = if i < 48 { unsafe { isr_table[i] } } else { isr_other as *const () as u64 };
        *e = IdtEntry::new(h);
    }
    let ptr = IdtPtr { limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16, base: idt.as_ptr() as u64 };
    unsafe {
        asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack));

        // Remap the 8259 PICs to vectors 32..47, unmask only IRQ0 (timer).
        outb(0x20, 0x11);
        outb(0xA0, 0x11);
        outb(0x21, 0x20);
        outb(0xA1, 0x28);
        outb(0x21, 0x04);
        outb(0xA1, 0x02);
        outb(0x21, 0x01);
        outb(0xA1, 0x01);
        outb(0x21, 0xFE);
        outb(0xA1, 0xFF);

        // PIT channel 0, mode 2, 1000 Hz. Only used to wake the CPU from `hlt`;
        // time itself comes from the TSC.
        let div: u16 = (1_193_182 / 1000) as u16;
        outb(0x43, 0x34);
        outb(0x40, div as u8);
        outb(0x40, (div >> 8) as u8);
    }
}

// ---------------------------------------------------------------- clock

static TSC_PER_MS: AtomicU64 = AtomicU64::new(1);
static TSC_BASE: AtomicU64 = AtomicU64::new(0);

/// One 10 ms PIT channel 2 one-shot; TSC ticks per ms, None if the PIT
/// does not behave.
fn measure_tsc() -> Option<u64> {
    const LIMIT: u64 = 50_000_000;
    unsafe {
        let port61 = inb(0x61);
        outb(0x61, (port61 & !0x02) | 0x01); // gate on, speaker off
        outb(0x43, 0xB0); // channel 2, lo/hi, mode 0
        let count: u16 = 11932; // 10 ms
        outb(0x42, count as u8);
        outb(0x42, (count >> 8) as u8);
        // OUT2 must drop when the count is loaded; a stale high level
        // would end the measurement early
        let mut spins = 0;
        while inb(0x61) & 0x20 != 0 && spins < LIMIT {
            spins += 1;
        }
        let start = rdtsc();
        while inb(0x61) & 0x20 == 0 && spins < LIMIT {
            spins += 1;
        }
        let end = rdtsc();
        outb(0x61, port61);
        (spins < LIMIT).then_some((end - start) / 10)
    }
}

/// Calibrate the TSC: median of five PIT measurements, so one glitch cannot
/// make the clock run 20x fast (which would also trip the watchdog).
pub fn init_clock() {
    let mut samples = [0u64; 5];
    let mut n = 0;
    for _ in 0..8 {
        if let Some(v) = measure_tsc().filter(|&v| v >= 100_000) {
            samples[n] = v;
            n += 1;
            if n == samples.len() {
                break;
            }
        }
    }
    let per_ms = if n == 0 {
        2_000_000 // no usable PIT: assume 2 GHz
    } else {
        let s = &mut samples[..n];
        s.sort_unstable();
        s[n / 2]
    };
    TSC_PER_MS.store(per_ms, Ordering::Relaxed);
    TSC_BASE.store(rdtsc(), Ordering::Relaxed);
}

pub fn tsc_per_ms() -> u64 {
    TSC_PER_MS.load(Ordering::Relaxed)
}

pub fn now_us() -> u64 {
    (rdtsc() - TSC_BASE.load(Ordering::Relaxed)) * 1000 / TSC_PER_MS.load(Ordering::Relaxed)
}

pub fn now_ms() -> u64 {
    (rdtsc() - TSC_BASE.load(Ordering::Relaxed)) / TSC_PER_MS.load(Ordering::Relaxed)
}

pub fn cpu_mhz() -> u64 {
    TSC_PER_MS.load(Ordering::Relaxed) / 1000
}

pub fn reboot() -> ! {
    unsafe {
        // keyboard controller reset line
        for _ in 0..100_000 {
            if inb(0x64) & 0x02 == 0 {
                break;
            }
        }
        outb(0x64, 0xFE);
        // fall back to a triple fault: load an empty IDT and trap
        let ptr = IdtPtr { limit: 0, base: 0 };
        asm!("lidt [{}]; int3", in(reg) &ptr, options(nostack));
    }
    halt_forever()
}

/// Like `wait_for_interrupt`, but never hangs if no timer IRQ arrives.
pub fn wait_for_interrupt_or_spin() {
    unsafe { asm!("sti", options(nomem, nostack)) }
    core::hint::spin_loop();
}

/// Wall clock at boot (seconds since 1970, from the CMOS real-time clock;
/// 0 if it could not be read).
static BOOT_UNIX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn cmos(reg: u8) -> u8 {
    // Safety: the CMOS index/data ports; NMI stays enabled (bit 7 clear)
    unsafe {
        outb(0x70, reg);
        inb(0x71)
    }
}

/// Read the real-time clock (UTC on KVM) once, at boot.
pub fn init_wall_clock() {
    let read = || {
        while cmos(0x0A) & 0x80 != 0 {} // update in progress
        [cmos(0x00), cmos(0x02), cmos(0x04), cmos(0x07), cmos(0x08), cmos(0x09), cmos(0x32)]
    };
    // twice the same, so no update happened in between
    let mut r = read();
    for _ in 0..5 {
        let again = read();
        if again == r {
            break;
        }
        r = again;
    }
    let b = cmos(0x0B);
    let bcd = |v: u8| if b & 0x04 == 0 { (v & 0x0F) + (v >> 4) * 10 } else { v };
    let (sec, min, day, mon, yy) = (bcd(r[0]) as u64, bcd(r[1]) as u64, bcd(r[3]) as u64, bcd(r[4]) as u64, bcd(r[5]) as u64);
    let mut hour = bcd(r[2] & 0x7F) as u64;
    if b & 0x02 == 0 && r[2] & 0x80 != 0 {
        hour = (hour + 12) % 24; // 12-hour clock, PM
    }
    let century = match bcd(r[6]) as u64 {
        c @ 19..=21 => c,
        _ => 20,
    };
    let year = century * 100 + yy;
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) || year < 2020 {
        return;
    }
    // days since 1970-01-01 (civil from days, H. Hinnant)
    let (y, m) = if mon <= 2 { (year - 1, mon + 9) } else { (year, mon - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let unix = days * 86400 + hour * 3600 + min * 60 + sec;
    BOOT_UNIX.store(unix - now_ms() / 1000, core::sync::atomic::Ordering::Relaxed);
}

/// Seconds since 1970 (0: unknown).
pub fn unix_time() -> u64 {
    match BOOT_UNIX.load(core::sync::atomic::Ordering::Relaxed) {
        0 => 0,
        b => b + now_ms() / 1000,
    }
}
