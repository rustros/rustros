//! Where RustROS's packet path spends its CPU time, per forwarded packet:
//! cycle counters around each stage of a batch (receive, packet modules,
//! egress hook, delivery to the system stack, transmit, device
//! notification) and around the app polls of each main-loop pass. Only in
//! measurement builds (cargo feature `stages`); otherwise every function
//! here is empty and the calls vanish.

#[cfg(feature = "stages")]
mod imp {
    use alloc::format;
    use alloc::string::String;

    use crate::Global;

    pub const RX: usize = 0;
    pub const MODULES: usize = 1;
    pub const EGRESS: usize = 2;
    pub const STACK: usize = 3;
    pub const TX: usize = 4;
    pub const FLUSH: usize = 5;
    pub const POLL: usize = 6;
    const N: usize = 7;
    const NAMES: [&str; N] = ["receive", "modules", "egress", "stack", "transmit", "notify", "app polls"];

    #[derive(Clone, Copy, Default)]
    struct Counts {
        tsc: [u64; N],
        /// frames received in batches, batches, main-loop passes
        frames: u64,
        batches: u64,
        passes: u64,
    }

    static NOW: Global<Counts> = Global::new(Counts { tsc: [0; N], frames: 0, batches: 0, passes: 0 });
    static LAST: Global<Counts> = Global::new(Counts { tsc: [0; N], frames: 0, batches: 0, passes: 0 });
    static LINE: Global<String> = Global::new(String::new());

    fn now() -> &'static mut Counts {
        // Safety: single core, main loop only
        unsafe { NOW.get() }
    }

    pub fn t() -> u64 {
        crate::arch::rdtsc()
    }

    /// The time since `t0` goes to stage `i`; the time now.
    pub fn add(i: usize, t0: u64) -> u64 {
        let t = crate::arch::rdtsc();
        now().tsc[i] += t - t0;
        t
    }

    pub fn batch(frames: usize) {
        let c = now();
        c.frames += frames as u64;
        c.batches += 1;
    }

    pub fn pass() {
        now().passes += 1;
    }

    /// Once a second (perf::tick): the line for the summary, from the
    /// last second, and the NICs' notifications and TX waits.
    pub fn tick(dt_ms: u64, kicks: u64, tx_wait_tsc: u64) {
        let (c, l) = (*now(), unsafe { *LAST.get() });
        unsafe { *LAST.get() = c };
        let frames = c.frames - l.frames;
        let per = |x: u64| if frames == 0 { 0 } else { x / frames };
        let mut s = format!("stages, cycles per packet received ({} kpps, {} batches/s of {} on average, {} loop passes/s):",
            frames / dt_ms.max(1), (c.batches - l.batches) * 1000 / dt_ms.max(1),
            if c.batches > l.batches { frames / (c.batches - l.batches) } else { 0 }, (c.passes - l.passes) * 1000 / dt_ms.max(1));
        for (i, name) in NAMES.iter().enumerate() {
            s += &format!(" {} {}", name, per(c.tsc[i] - l.tsc[i]));
        }
        s += &format!("; TX slot waits {} per packet; notifications {}/s", per(tx_wait_tsc), kicks * 1000 / dt_ms.max(1));
        unsafe { *LINE.get() = s };
    }

    pub fn line() -> String {
        unsafe { LINE.get().clone() }
    }
}

#[cfg(not(feature = "stages"))]
mod imp {
    use alloc::string::String;

    pub const RX: usize = 0;
    pub const MODULES: usize = 1;
    pub const EGRESS: usize = 2;
    pub const STACK: usize = 3;
    pub const TX: usize = 4;
    pub const FLUSH: usize = 5;
    pub const POLL: usize = 6;

    #[inline(always)]
    pub fn t() -> u64 {
        0
    }
    #[inline(always)]
    pub fn add(_: usize, _: u64) -> u64 {
        0
    }
    #[inline(always)]
    pub fn batch(_: usize) {}
    #[inline(always)]
    pub fn pass() {}
    #[inline(always)]
    pub fn tick(_: u64, _: u64, _: u64) {}
    #[inline(always)]
    pub fn line() -> String {
        String::new()
    }
}

pub use imp::*;
