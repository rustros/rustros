//! RustROS kernel: boots, brings up the console, virtio-net and virtio-blk, runs
//! the network stack and polls the built-in applications (see rustros_api::sys).
#![no_std]
#![no_main]

extern crate alloc;

mod modules;
mod offload;
mod klog;
mod perf;
mod acpi;
mod arch;
mod boot;
mod console;
mod font;
mod loader;
mod mem;
mod multiboot;
mod pci;
mod sys;
mod virtio;
mod virtio_blk;
mod virtio_net;
mod watchdog;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use rustros_api::{Module, Caps, Frame, HEADROOM, Offload, Verdict};
use devices::NetDevice;
use netstack::Stack;
use rustros_util::wire::{IpFmt, cmdline_get, parse_cidr, parse_ip};

use modules::Slot;
use sys::Kernel;

/// Interior-mutable global for the single-core kernel. Callers of `get`
/// promise there is no concurrent access (interrupt handlers never touch it).
pub struct Global<T>(UnsafeCell<T>);

unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    pub const fn new(v: T) -> Global<T> {
        Global(UnsafeCell::new(v))
    }
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

/// Where `crash` records its reason: the boot disk, once it is known.
static CRASH_SINK: Global<*mut sys::Boot> = Global::new(core::ptr::null_mut());
static CRASHING: AtomicBool = AtomicBool::new(false);
const CRASH_TEXT_MAX: usize = 300;

/// Fixed-size formatting buffer (crash reporting must not depend on the heap).
struct FixedBuf {
    buf: [u8; CRASH_TEXT_MAX],
    len: usize,
}

impl Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                break;
            }
            // grubenv values: one line, no backslashes
            self.buf[self.len] = match b {
                b'\n' | b'\t' => b' ',
                b'\\' => b'/',
                0x20..0x7F => b,
                _ => b'?',
            };
            self.len += 1;
        }
        Ok(())
    }
}

/// Fatal error: report, record the reason in grubenv (`last_panic`) and reboot.
/// A crash during a trial boot thereby also rolls back to the previous kernel.
pub fn crash(args: fmt::Arguments) -> ! {
    kprintln!("\n*** {}", args);
    // only the first crash gets to touch the disk; a crash while recording
    // goes straight to the reboot
    if !CRASHING.swap(true, Ordering::SeqCst) {
        let mut msg = FixedBuf { buf: [0; CRASH_TEXT_MAX], len: 0 };
        let _ = write!(msg, "up {}s: {}", arch::now_ms() / 1000, args);
        let text = core::str::from_utf8(&msg.buf[..msg.len]).unwrap_or("?");
        // Safety: we never return to whatever was using the boot disk.
        let sink = unsafe { *CRASH_SINK.get() };
        if let Some(b) = unsafe { sink.as_mut() } {
            // a native module that crashes is switched off at the next boot
            let culprit = modules::current_native().unwrap_or("");
            if b.upd.set_vars(&mut *b.disk, &[("last_panic", text), ("crash_app", culprit)]) {
                kprintln!("crash recorded in grubenv{}", if culprit.is_empty() { "" } else { " (native app)" });
            }
            kprintln!("rebooting in 2 s");
            // the last words, for `log prev` after the reboot
            if let Some(l) = b.log.as_mut() {
                l.flush(&mut *b.disk);
            }
        } else {
            kprintln!("rebooting in 2 s");
        }
    } else {
        kprintln!("rebooting in 2 s");
    }
    let t = arch::now_ms();
    while arch::now_ms() - t < 2000 {
        core::hint::spin_loop();
    }
    arch::reboot()
}

const CTRL_RIGHT_BRACKET: u8 = 0x1D;

/// Power off through ACPI; without it, reboot. (Callers say so first.)
pub fn poweroff() -> ! {
    acpi::poweroff();
    kprintln!("power off failed, rebooting");
    arch::reboot()
}

/// Who gets console input: the newest running module that asked for it
/// (Caps::CONSOLE), else the built-in rescue console; Ctrl-] forces rescue.
fn console_owner(k: &Kernel, slots: &[Slot], force_rescue: bool) -> Option<usize> {
    let rescue = k.names.iter().position(|n| *n == "rescue");
    if force_rescue && rescue.is_some() {
        return rescue;
    }
    let claimed = (0..slots.len())
        .rev()
        .find(|&id| !matches!(slots[id], Slot::Empty) && Some(id) != rescue && k.caps.get(id).is_some_and(|c| c.contains(Caps::CONSOLE)));
    claimed.or(rescue)
}

/// The software watchdog fired (from the timer interrupt): the main loop is
/// stuck. If it is stuck in a native module, pin it on the module so it is
/// switched off at the next boot; that needs a disk write, done only when the
/// disk is idle.
pub fn watchdog_expired() -> ! {
    match modules::current_native() {
        Some(name) if !virtio_blk::busy() => crash(format_args!("watchdog: main loop stuck in native app {}", name)),
        _ => {
            kprintln!("\n*** watchdog: main loop stuck for {} s, rebooting", arch::WATCHDOG_MS / 1000);
            arch::reboot()
        }
    }
}

/// Running this long counts as a stable boot (clears grubenv's boot_count).
const STABLE_MS: u64 = 120_000;
/// Unstable boots in a row before safe mode (GRUB falls back to the other
/// kernel slot at the next one).
const SAFE_MODE_AT: u32 = 3;

/// A trial boot that is not confirmed in time falls back to the old slot.
const TRIAL_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// The applications built into this image (see the features in Cargo.toml).
fn make_apps() -> Vec<Box<dyn Module>> {
    let mut apps: Vec<Box<dyn Module>> = Vec::new();
    #[cfg(feature = "rescue")]
    apps.push(Box::new(rescue::Rescue::new()));
    #[cfg(feature = "dhcp")]
    apps.push(Box::new(dhcp::Dhcp::new()));
    #[cfg(feature = "shell")]
    apps.push(Box::new(shell::Shell::new()));
    #[cfg(feature = "echo")]
    apps.push(Box::new(echo::Echo::new()));
    #[cfg(feature = "httpd")]
    apps.push(Box::new(httpd::Httpd::new()));
    #[cfg(feature = "updater")]
    apps.push(Box::new(updater::Updater::new()));
    apps
}

#[unsafe(no_mangle)]
extern "C" fn kmain(magic: u32, info: u32) -> ! {
    mem::HEAP.init();
    let bi = multiboot::parse(magic, info);
    console::init(bi.fb, bi.efi);
    kprintln!("RustROS {} ({} boot, {})", env!("CARGO_PKG_VERSION"), if bi.efi { "UEFI" } else { "BIOS" }, console::describe());
    if magic != multiboot::MAGIC {
        kprintln!("warning: not booted by a multiboot2 loader");
    }

    arch::init_clock();
    arch::init_wall_clock();
    arch::init_interrupts();
    let t0 = arch::now_ms();
    while arch::now_ms() - t0 < 20 {
        arch::wait_for_interrupt_or_spin();
    }
    let irq_ok = arch::irq_count() > 0;
    kprintln!(
        "cpu {} MHz, heap {} MiB, timer irq {}, random {}",
        arch::cpu_mhz(),
        mem::HEAP.free_bytes() >> 20,
        if irq_ok { "ok" } else { "missing (busy polling)" },
        if arch::hw_random().is_some() { "from the CPU" } else { "WEAK (no RDRAND/RDSEED: give the VM the host CPU's flags)" }
    );

    let cmdline = String::from_utf8_lossy(bi.cmdline).into_owned();
    acpi::init(bi.rsdp);
    kprintln!("acpi: {} CPUs listed, RustROS runs on one", acpi::cpu_count());
    if !acpi::available() {
        kprintln!("acpi: not found, power off will reboot");
    }
    // never echo the update secret to the console / serial log
    let shown: Vec<&str> = cmdline.split_ascii_whitespace().map(|w| if w.starts_with("key=") { "key=***" } else { w }).collect();
    kprintln!("cmdline: {}", shown.join(" "));

    let mut nets = Vec::new();
    let mut blks = Vec::new();
    pci::scan(|d| {
        if virtio_net::is_net(&d) {
            nets.push(d);
        } else if virtio_blk::is_blk(&d) {
            blks.push(d);
        }
    });
    let mut disks: Vec<_> = blks.iter().filter_map(virtio_blk::VirtioBlk::new).collect();
    // "rustros.disktest=<lba>,<sectors>": exercise the first disk on a spare
    // area (its content is put back), for new hardware
    if let (Some(spec), Some(d)) = (cmdline_get(&cmdline, "rustros.disktest"), disks.first_mut()) {
        let mut it = spec.split(',').map(|v| v.parse::<u64>().ok());
        if let (Some(Some(lba)), Some(Some(n))) = (it.next(), it.next()) {
            disk_test(d, lba, n);
        }
    }
    let boot = match slots::Updater::new(&cmdline, disks) {
        Ok((mut disk, upd)) => {
            kprintln!("disk: running slot {}{}", upd.slot, if upd.trial { " (trial boot)" } else { "" });
            if let Some(p) = upd.get("last_panic") {
                kprintln!("disk: last crash: {}", p);
            }
            let store = match storage::open(&mut disk, arch::rdtsc()) {
                Ok((store, part)) => {
                    if part.moved_backup {
                        kprintln!("storage: disk is {} MiB; moved the backup GPT to its end", disk.sectors / 2048);
                    }
                    if part.created {
                        kprintln!("storage: created data partition, {} MiB at {} MiB", part.sectors / 2048, part.start / 2048);
                    }
                    if let Some((start, n)) = part.cache {
                        kprintln!("storage: cache partition {} MiB at {} MiB", n / 2048, start / 2048);
                    }
                    let (live, _, half) = store.usage();
                    kprintln!(
                        "storage: data partition {} MiB, store {} MiB, {} keys / {} bytes",
                        part.sectors / 2048,
                        half / 1024,
                        store.keys("").count(),
                        live
                    );
                    Some((store, part))
                }
                Err(e) => {
                    kprintln!("storage: unavailable: {}", e);
                    None
                }
            };
            // the console log goes to the start of the cache partition
            let mut log = store.as_ref().and_then(|(_, part)| part.cache).and_then(|(start, n)| klog::DiskLog::open(&mut disk, start, n));
            match log.as_mut() {
                Some(l) => {
                    kprintln!("log: this is boot {}; the last {} boots' console logs are kept", l.seq, klog::SLOTS);
                    l.flush(&mut disk);
                }
                None => kprintln!("log: no cache partition, the console log is not kept"),
            }
            Some(sys::Boot { disk: Box::new(disk), upd, store, log })
        }
        Err(e) => {
            kprintln!("disk: online update and storage disabled: {}", e);
            None
        }
    };

    let (ip, mask) = cmdline_get(&cmdline, "ip").and_then(parse_cidr).unwrap_or((0, 0));
    let gw = cmdline_get(&cmdline, "gw").and_then(parse_ip).unwrap_or(0);
    if ip == 0 {
        kprintln!("net: no ip= on the command line, address unconfigured");
    } else {
        kprintln!("net: ip {} gw {}", IpFmt(ip), IpFmt(gw));
    }
    // NIC offloads (TSO / checksums) unless turned off: "offload=off" on the
    // command line or net_offload=off in grubenv
    let offloads = cmdline_get(&cmdline, "offload").or_else(|| boot.as_ref().and_then(|b| b.upd.get("net_offload"))) != Some("off");
    let nics: Vec<Box<dyn NetDevice>> = nets.iter().filter_map(|d| virtio_net::VirtioNet::new(d, offloads)).map(|n| Box::new(n) as Box<dyn NetDevice>).collect();
    if nics.is_empty() {
        kprintln!("no usable virtio-net device found ({} seen, messages above), halting", nets.len());
        arch::halt_forever();
    }
    for (i, n) in nics.iter().enumerate() {
        kprintln!("net: nic{} {} mac {}", i, n.kind(), rustros_util::wire::MacFmt(n.mac()));
    }

    let mut stack = Stack::new(nics[0].mac(), ip, mask, gw);
    if let Some(mtu) = cmdline_get(&cmdline, "mtu").and_then(|m| m.parse::<usize>().ok()) {
        stack.primary().mtu = mtu.clamp(576, 1500);
        kprintln!("net: mtu {}", stack.primary().mtu);
    }
    for n in &nics[1..] {
        stack.add_iface(n.mac());
    }
    let mut ifmap: Vec<sys::IfMap> = (0..nics.len()).map(|phys| sys::IfMap { phys, vlan: None }).collect();
    // VLAN interfaces: "vlans=0.109,1.20" on the command line, else net_vlans in grubenv
    let vlans = cmdline_get(&cmdline, "vlans").map(String::from).or_else(|| boot.as_ref().and_then(|b| b.upd.get("net_vlans")).map(String::from));
    for v in vlans.as_deref().unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        let parsed = v.split_once('.').and_then(|(p, id)| Some((p.parse::<usize>().ok()?, id.parse::<u16>().ok()?)));
        match parsed {
            Some((phys, vid)) if phys < nics.len() && (1..=4094).contains(&vid) && !ifmap.contains(&sys::IfMap { phys, vlan: Some(vid) }) => {
                stack.add_iface(nics[phys].mac());
                ifmap.push(sys::IfMap { phys, vlan: Some(vid) });
                kprintln!("net: nic{} is VLAN {} on nic{}", ifmap.len() - 1, vid, phys);
            }
            _ => kprintln!("net: bad VLAN '{}' (want <nic>.<id>)", v),
        }
    }
    net_config_extra(&mut stack, &cmdline, boot.as_ref().map(|b| &b.upd));
    // static routes: "routes=10.9.0.0/16>10.20.0.1,0.0.0.0/0>gw<10.20.0.1/32,..."
    // or net_routes in grubenv
    let routes = cmdline_get(&cmdline, "routes").map(String::from).or_else(|| boot.as_ref().and_then(|b| b.upd.get("net_routes")).map(String::from));
    for r in routes.as_deref().unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        match parse_route(r) {
            Some(rt) => {
                stack.ifs.1.push(rt);
                kprintln!("net: route {}", fmt_route(&rt).replace('>', " via ").replace('<', " from "));
            }
            None => kprintln!("net: bad route '{}' (want a.b.c.d/n>gateway[<source/n])", r),
        }
    }
    let mut k = Kernel::new(nics, ifmap, boot, cmdline, stack);
    // boot-loop protection: GRUB appends an "x" to boot_count on every boot
    k.unstable_boots = cmdline_get(&k.cmdline, "rustros.boots").map_or(1, |b| b.len() as u32).max(1);
    k.safe_mode = k.unstable_boots >= SAFE_MODE_AT;
    if let Some(b) = k.boot.as_mut() {
        if let Some(from) = b.upd.get("rolled_back").map(String::from) {
            let to = b.upd.slot;
            let why = format!("kernel slot {from} did not come up 4 times in a row; GRUB rolled back to slot {to}");
            kprintln!("boot: {}", why);
            b.upd.set_vars(&mut *b.disk, &[("last_panic", &why), ("rolled_back", "")]);
        }
    }
    if k.unstable_boots > 1 {
        kprintln!("boot: {} unstable boots in a row", k.unstable_boots);
    }
    if let Some(b) = k.boot.as_mut() {
        // Safety: `k` lives on this stack frame until reboot and never moves.
        unsafe { *CRASH_SINK.get() = b as *mut sys::Boot };
    }
    let mut hw_watchdog = watchdog::Esb::probe();
    match &hw_watchdog {
        Some(_) => kprintln!("watchdog: i6300esb armed ({} s), software watchdog {} s", watchdog::TIMEOUT_S, arch::WATCHDOG_MS / 1000),
        None if irq_ok => kprintln!("watchdog: software only ({} s)", arch::WATCHDOG_MS / 1000),
        None => kprintln!("watchdog: none (no timer interrupt)"),
    }

    let mut slots: Vec<Slot> = make_apps().into_iter().map(Slot::Builtin).collect();
    k.names = slots.iter_mut().map(|s| s.app().map_or("", |a| a.name())).collect();
    // built-in apps get what they ask for
    k.caps = slots.iter_mut().map(|s| s.app().map_or(Caps::NONE, |a| a.caps())).collect();
    k.builtin_names = k.names.clone();
    k.stack.owner_names = k.names.clone();
    kprintln!("modules: {} (built in)", k.names.join(", "));
    for id in 0..slots.len() {
        modules::call(&mut k, &mut slots, id, |app, ctx| app.start(ctx));
    }
    // installed modules (native modules, WebAssembly)
    if k.safe_mode {
        kprintln!("boot: SAFE MODE: installed modules are not started; fix them (mod rm / mod switch) and reboot");
    } else {
        modules::boot(&mut k);
        modules::apply(&mut k, &mut slots);
    }
    kprintln!();

    // receive buffers for the packet path: HEADROOM free bytes before each frame
    let mut pool: Vec<devices::Buf> = (0..BATCH).map(|_| devices::new_buf()).collect();
    const _: () = assert!(devices::HEADROOM == HEADROOM);
    let mut warned = false;
    let mut status_at = 0;
    let mut force_rescue = false;
    let mut stable = false;
    let mut shown_owner = None;
    loop {
        arch::heartbeat();
        if let Some(w) = hw_watchdog.as_mut() {
            w.pet();
        }
        let mut busy = false;
        while receive_batch(&mut k, &mut slots, &mut pool) {
            busy = true;
            while stack_tx_batch(&mut k, &mut slots, &mut pool) {}
        }
        {
            let (st, mut link) = k.net();
            st.poll(&mut link);
        }
        for id in 0..slots.len() {
            modules::call(&mut k, &mut slots, id, |app, ctx| app.poll(ctx));
        }
        while stack_tx_batch(&mut k, &mut slots, &mut pool) {
            busy = true;
        }
        while let Some(c) = console::getc() {
            busy = true;
            if c == CTRL_RIGHT_BRACKET {
                force_rescue = !force_rescue;
                continue;
            }
            if let Some(id) = console_owner(&k, &slots, force_rescue) {
                modules::call(&mut k, &mut slots, id, |app, ctx| app.key(ctx, c));
            }
        }
        // tell the user when the console changes hands
        let owner = console_owner(&k, &slots, force_rescue);
        if owner != shown_owner {
            shown_owner = owner;
            if let Some(id) = owner {
                let name = k.names[id];
                kprintln!("\n[console: {}{}]", name, if name == "rescue" { "; Ctrl-] switches" } else { "" });
                if name == "rescue" {
                    // empty line: the rescue console shows its prompt
                    modules::call(&mut k, &mut slots, id, |app, ctx| app.key(ctx, b'\n'));
                }
            }
        }
        if !k.app_ops.is_empty() {
            modules::apply(&mut k, &mut slots);
        }
        if k.net_deadline.is_some_and(|t| arch::now_ms() >= t) && k.net_revert() {
            kprintln!("net: apply not confirmed in time, previous configuration restored (the candidate is kept)");
        }
        if acpi::power_button() {
            kprintln!("power button pressed, powering off...");
            k.planned_shutdown();
            poweroff();
        }
        let now = arch::now_ms();
        if !stable && now >= STABLE_MS {
            stable = true;
            if let Some(b) = k.boot.as_mut() {
                b.upd.set_vars(&mut *b.disk, &[("boot_count", "")]);
            }
        }
        if now - status_at >= 1000 {
            status_at = now;
            modules::refresh_status(&mut k, &mut slots);
            k.perf.tick(&k.nics, &k.names);
            if let Some(b) = k.boot.as_mut() {
                if let Some(l) = b.log.as_mut() {
                    l.flush(&mut *b.disk);
                }
            }
        }
        if k.trial() {
            let now = arch::now_ms();
            if now > TRIAL_TIMEOUT_MS {
                kprintln!("trial boot not confirmed within {} s, rolling back", TRIAL_TIMEOUT_MS / 1000);
                arch::reboot();
            } else if !warned && now > TRIAL_TIMEOUT_MS - 60_000 {
                kprintln!("trial boot: confirm within 60 s or RustROS reboots into the previous kernel");
                warned = true;
            }
        }
        for nic in k.nics.iter_mut() {
            nic.flush();
        }
        if !busy && irq_ok {
            // sleep until a frame arrives (or the next timer tick); check
            // again with interrupts off so a frame that just came in cannot
            // be missed
            for nic in k.nics.iter_mut() {
                nic.rx_interrupts(true);
            }
            arch::cli();
            if k.nics.iter().any(|n| n.rx_pending()) {
                arch::sti();
            } else {
                let t = arch::rdtsc();
                arch::wait_for_interrupt();
                k.perf.idle_tsc += arch::rdtsc() - t;
            }
            for nic in k.nics.iter_mut() {
                nic.rx_interrupts(false);
            }
        }
    }
}

/// Configuration beyond NIC 0's address: NIC 0's extra addresses and the
/// other NICs, from the command line (`extra=`, `ip1=`, `gw1=`, `mtu1=`,
/// `extra1=`, ...) or else from grubenv (`net_extra`, `net1_ip`, ...,
/// written by `save`).
fn net_config_extra(stack: &mut Stack, cmdline: &str, env: Option<&slots::Updater>) {
    for nic in 0..stack.ifs.0.len() {
        let (c, e) = if nic == 0 { (String::new(), String::from("net_")) } else { (format!("{nic}"), format!("net{nic}_")) };
        let get = |k: &str| -> Option<String> {
            cmdline_get(cmdline, &format!("{k}{c}")).map(String::from).or_else(|| env.and_then(|u| u.get(&format!("{e}{k}"))).map(String::from))
        };
        let f = &mut stack.ifs.0[nic];
        if nic > 0 {
            if let Some((ip, mask)) = get("ip").as_deref().and_then(parse_cidr) {
                f.ip = ip;
                f.mask = mask;
                f.gw = get("gw").as_deref().and_then(parse_ip).unwrap_or(0);
            }
            if let Some(mtu) = get("mtu").and_then(|m| m.parse::<usize>().ok()) {
                f.mtu = mtu.clamp(576, 1500);
            }
        }
        if let Some(list) = get("extra") {
            f.extra = rustros_util::wire::parse_ip_list(&list).unwrap_or_default();
            f.extra.retain(|&a| a != 0 && a != f.ip);
        }
        if nic > 0 && f.ip != 0 {
            kprintln!("net: nic{} ip {}/{}{}", nic, IpFmt(f.ip), f.mask.count_ones(), if f.gw != 0 { format!(" gw {}", IpFmt(f.gw)) } else { String::new() });
        }
        if !f.extra.is_empty() {
            kprintln!("net: nic{} {} extra addresses {}", nic, f.extra.len(), rustros_util::wire::fmt_ip_list(&f.extra));
        }
    }
}

/// A route as stored: "net/n>gw" or "net/n>gw<src/n".
fn parse_route(r: &str) -> Option<netstack::iface::Route> {
    let (r, src) = match r.split_once('<') {
        Some((r, s)) => (r, Some(parse_cidr(s)?)),
        None => (r, None),
    };
    let (n, g) = r.split_once('>')?;
    let ((net, mask), gw) = (parse_cidr(n)?, parse_ip(g)?);
    let (src, src_mask) = src.unwrap_or((0, 0));
    (net & !mask == 0 && src & !src_mask == 0).then_some(netstack::iface::Route { net, mask, gw, src, src_mask })
}

pub fn fmt_route(r: &netstack::iface::Route) -> String {
    let mut s = format!("{}/{}>{}", IpFmt(r.net), r.mask.count_ones(), IpFmt(r.gw));
    if r.src_mask != 0 {
        s += &format!("<{}/{}", IpFmt(r.src), r.src_mask.count_ones());
    }
    s
}

const BATCH: usize = 32;

/// Receive up to BATCH frames and run them through the packet apps and then
/// the system stack. False when nothing was received.
fn receive_batch(k: &mut Kernel, slots: &mut [Slot], pool: &mut [devices::Buf]) -> bool {
    // frames a shaper released go first, in batches of their own
    if let Some(&(_, after, _, _)) = k.injected.front() {
        let (mut lens, mut from, starts, mut offs) = ([0usize; BATCH], [0u8; BATCH], [HEADROOM; BATCH], [Offload::default(); BATCH]);
        let mut n = 0;
        while n < BATCH && k.injected.front().is_some_and(|f| f.1 == after) {
            let (nic, _, data, off) = k.injected.pop_front().unwrap();
            if pool[n].len() < HEADROOM + data.len() {
                pool[n] = devices::buf_for(data.len());
            }
            pool[n][HEADROOM..HEADROOM + data.len()].copy_from_slice(&data);
            lens[n] = data.len();
            from[n] = nic;
            offs[n] = off;
            n += 1;
        }
        process_batch(k, slots, pool, n, &starts, &lens, &from, &offs, after);
        return true;
    }
    let mut lens = [0usize; BATCH];
    let mut from = [0u8; BATCH];
    let mut starts = [HEADROOM; BATCH];
    let mut offs = [Offload::default(); BATCH];
    let mut n = 0;
    // take from every NIC in turn so none can starve the others
    let mut idle = 0;
    let mut nic = 0;
    while n < BATCH && idle < k.nics.len() {
        // zero copy: the frame's buffer comes in exchange for pool[n]
        match k.nics[nic].recv_swap(&mut pool[n]) {
            Some((len, off)) => {
                idle = 0;
                offs[n] = off;
                let b = &mut pool[n];
                if len >= 18 && b[HEADROOM + 12..HEADROOM + 14] == [0x81, 0x00] {
                    // 802.1Q: to its VLAN interface, untagged
                    let vid = u16::from_be_bytes([b[HEADROOM + 14], b[HEADROOM + 15]]) & 0xFFF;
                    let Some(i) = k.ifmap.iter().position(|m| m.phys == nic && m.vlan == Some(vid)) else {
                        nic = (nic + 1) % k.nics.len();
                        continue; // a VLAN we do not have
                    };
                    b.copy_within(HEADROOM..HEADROOM + 12, HEADROOM + 4);
                    starts[n] = HEADROOM + 4;
                    lens[n] = len - 4;
                    from[n] = i as u8;
                } else {
                    starts[n] = HEADROOM;
                    lens[n] = len;
                    from[n] = nic as u8;
                }
                n += 1;
            }
            None => idle += 1,
        }
        nic = (nic + 1) % k.nics.len();
    }
    if n == 0 {
        return false;
    }
    process_batch(k, slots, pool, n, &starts, &lens, &from, &offs, i32::MIN);
    true
}

/// Send what the system's stack queued, through the egress hook. False when
/// there was nothing.
fn stack_tx_batch(k: &mut Kernel, slots: &mut [Slot], pool: &mut [devices::Buf]) -> bool {
    if k.stack_tx.is_empty() {
        return false;
    }
    let (mut lens, mut from, starts) = ([0usize; BATCH], [0u8; BATCH], [HEADROOM; BATCH]);
    let mut n = 0;
    while n < BATCH {
        let Some((nic, data)) = k.stack_tx.pop_front() else { break };
        if pool[n].len() < HEADROOM + data.len() {
            pool[n] = devices::buf_for(data.len());
        }
        pool[n][HEADROOM..HEADROOM + data.len()].copy_from_slice(&data);
        lens[n] = data.len();
        from[n] = nic;
        n += 1;
    }
    // already decided: to be sent, past every module but the egress hook
    process_batch(k, slots, pool, n, &starts, &lens, &from, &[Offload::default(); BATCH], i32::MAX);
    true
}

/// Run `n` frames in `pool` through the packet modules after module order
/// `after` (and the egress hook), send what they say, give the rest to the
/// system stack.
#[allow(clippy::too_many_arguments)]
/// Finish the offloads of the undecided frames (`frames[..live]`) for an app
/// that wants plain packets: checksums in place; a big segment is cut into
/// packets that come back after `after`, and so does every frame behind it
/// (in order: a connection's packets must not overtake each other). Those
/// frames are consumed here. Returns how many are still undecided.
fn plain_for(k: &mut Kernel, frames: &mut [Frame], live: usize, after: i32) -> usize {
    let Some(first) = frames[..live].iter().position(|f| f.offload.gso_size > 0) else {
        for f in frames[..live].iter_mut().filter(|f| f.offload.csum_partial) {
            rustros_util::offload::complete_csum(f.data_mut());
            f.offload = Offload::default();
        }
        return live;
    };
    for f in frames[..live].iter_mut() {
        if f.offload.csum_partial && f.offload.gso_size == 0 {
            rustros_util::offload::complete_csum(f.data_mut());
            f.offload = Offload::default();
        }
    }
    for f in frames[first..live].iter_mut() {
        if f.offload.gso_size > 0 {
            for p in offload::plain(f.data(), f.offload) {
                k.injected.push_back((f.nic, after, p, Offload::default()));
            }
        } else {
            k.injected.push_back((f.nic, after, f.data().to_vec(), Offload::default()));
        }
        f.verdict = Verdict::Consumed;
    }
    first
}

#[allow(clippy::too_many_arguments)]
fn process_batch(k: &mut Kernel, slots: &mut [Slot], pool: &mut [devices::Buf], n: usize, starts: &[usize; BATCH], lens: &[usize; BATCH], from: &[u8; BATCH], offs: &[Offload; BATCH], after: i32) {
    let mut bufs = pool.iter_mut();
    let mut frames: [Frame; BATCH] = core::array::from_fn(|i| {
        let mut f = Frame::new(&mut bufs.next().unwrap()[..], starts[i], lens[i]);
        f.nic = from[i];
        f.slot = i as u8;
        f.offload = offs[i];
        if after == i32::MAX {
            f.verdict = Verdict::Transmit; // the stack's own: only the egress hook
        }
        f
    });
    // frames[..live] are still undecided
    let mut live = if after == i32::MAX { 0 } else { n };
    // packet modules by their order, then by id
    let mut ids = [0usize; 64];
    let mut count = 0;
    for id in 0..slots.len().min(64) {
        if !k.caps.get(id).is_some_and(|c| c.contains(Caps::PACKET)) {
            continue;
        }
        let ord = slots[id].app().map_or(0, |a| a.order());
        if after != i32::MIN && ord <= after {
            continue; // already seen by these
        }
        let mut j = count;
        while j > 0 && slots[ids[j - 1]].app().map_or(0, |a| a.order()) > ord {
            ids[j] = ids[j - 1];
            j -= 1;
        }
        ids[j] = id;
        count += 1;
    }
    for &id in &ids[..count] {
        if live == 0 {
            break;
        }
        let (ord, offloads) = slots[id].app().map_or((0, false), |a| (a.order(), a.offloads()));
        if !offloads {
            live = plain_for(k, &mut frames, live, ord.saturating_sub(1));
            if live == 0 {
                break;
            }
        }
        modules::call(k, slots, id, |app, ctx| app.on_frames(ctx, &mut frames[..live]));
        // stable partition: undecided frames to the front
        let mut j = 0;
        for i in 0..live {
            if frames[i].verdict == Verdict::Pass {
                frames.swap(i, j);
                j += 1;
            }
        }
        live = j;
    }
    // egress hook (shapers): the frames to send, first in frames[live..]
    let mut t = live;
    for i in live..n {
        if frames[i].verdict == Verdict::Transmit {
            frames.swap(i, t);
            t += 1;
        }
    }
    if t > live {
        for id in 0..slots.len() {
            if k.caps.get(id).is_some_and(|c| c.contains(Caps::PACKET)) {
                if !slots[id].app().is_some_and(|a| a.offloads()) {
                    // plain packets for it: they come back to the egress hook,
                    // with every frame behind the first big one (in order)
                    if let Some(first) = frames[live..t].iter().position(|f| f.verdict == Verdict::Transmit && f.offload.gso_size > 0) {
                        for f in frames[live + first..t].iter_mut().filter(|f| f.verdict == Verdict::Transmit) {
                            for p in offload::plain(f.data(), f.offload) {
                                k.injected.push_back((f.nic, i32::MAX, p, Offload::default()));
                            }
                            f.verdict = Verdict::Consumed;
                        }
                    }
                    for f in frames[live..t].iter_mut().filter(|f| f.verdict == Verdict::Transmit && f.offload.csum_partial) {
                        rustros_util::offload::complete_csum(f.data_mut());
                        f.offload = Offload::default();
                    }
                }
                modules::call(k, slots, id, |app, ctx| app.on_egress(ctx, &mut frames[live..t]));
            }
        }
    }
    // frames to send: (pool slot, start, length, NIC, offloads)
    let mut out = [(0u8, 0usize, 0usize, 0usize, Offload::default()); BATCH];
    let mut sends = 0;
    for f in frames[live..n].iter_mut() {
        if f.verdict == Verdict::Transmit {
            let Some(&m) = k.ifmap.get(f.nic as usize) else { continue };
            if let Some(v) = m.vlan {
                // tag it in the headroom: move the MAC addresses 4 bytes forward
                if f.push_front(4).is_none() || f.len() < 18 {
                    continue;
                }
                let d = f.data_mut();
                d.copy_within(4..16, 0);
                d[12..16].copy_from_slice(&[0x81, 0x00, (v >> 8) as u8, v as u8]);
            }
            out[sends] = (f.slot, f.headroom(), f.len(), m.phys, f.offload);
            sends += 1;
        }
    }
    let (st, mut link) = k.net();
    for f in frames[..live].iter_mut() {
        // the stack takes plain packets
        if f.offload.gso_size > 0 {
            for p in offload::plain(f.data(), f.offload) {
                st.input(&mut link, f.nic as usize, &p);
            }
            continue;
        }
        if f.offload.csum_partial {
            rustros_util::offload::complete_csum(f.data_mut());
        }
        st.input(&mut link, f.nic as usize, f.data());
    }
    drop(frames);
    // zero copy: the buffers themselves go onto the TX rings (a spare one
    // comes back into the pool slot)
    for &(slot, start, len, phys, off) in &out[..sends] {
        k.nics[phys].send_swap(&mut pool[slot as usize], start, len, off);
    }
    for nic in k.nics.iter_mut() {
        nic.flush();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crash(format_args!("panic: {}", info))
}

/// Write and read back patterns of many sizes (and buffer alignments) on
/// `[lba, lba+n)`, then restore what was there.
fn disk_test(d: &mut dyn devices::BlockDevice, lba: u64, n: u64) {
    let len = (n * 512) as usize;
    let mut orig = alloc::vec![0u8; len];
    if !d.read(lba, &mut orig) {
        kprintln!("disktest: reading the area failed");
        return;
    }
    let (mut ok, mut bad) = (0, 0);
    for size in [512usize, 4096, 65536, 65536 + 512, 131072, 184320, len] {
        for skew in [0usize, 3, 512] {
            if size > len {
                continue;
            }
            let mut w = alloc::vec![0u8; size + skew];
            for (i, b) in w[skew..].iter_mut().enumerate() {
                *b = (i as u32).wrapping_mul(2_654_435_761).wrapping_add((size + skew) as u32).to_le_bytes()[1];
            }
            let mut r = alloc::vec![0u8; size + skew + 7];
            let good = d.write(lba, &w[skew..]) && d.read(lba, &mut r[skew + 7..]) && r[skew + 7..] == w[skew..];
            if good {
                ok += 1;
            } else {
                bad += 1;
                kprintln!("disktest: {} bytes (buffer offset {}) FAILED", size, skew);
            }
        }
    }
    let mut back = alloc::vec![0u8; len];
    let restored = d.write(lba, &orig) && d.read(lba, &mut back) && back == orig;
    kprintln!("disktest: {} of {} cases ok{}, area {}", ok, ok + bad, if bad == 0 { "" } else { " (FAILURES above)" }, if restored { "restored" } else { "NOT restored" });
}
