//! Throughput and load: per-NIC rates and CPU use, sampled every second,
//! with peaks (logged when they rise, so they survive in the console log).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use devices::{DevStats, NetDevice};

use crate::{arch, kprintln};

#[derive(Clone, Copy, Default)]
struct Rates {
    rx_bps: u64,
    tx_bps: u64,
    rx_pps: u64,
    tx_pps: u64,
}

#[derive(Default)]
pub struct Perf {
    last: Vec<DevStats>,
    last_ms: u64,
    last_idle: u64,
    cur: Vec<Rates>,
    peak: Vec<Rates>,
    cpu: u64,
    cpu_peak: u64,
    logged_ms: u64,
    /// TSC ticks spent halted (waiting for work)
    pub idle_tsc: u64,
    /// TSC ticks spent in each module (by id), and at the last tick
    mod_tsc: Vec<u64>,
    mod_last: Vec<u64>,
    /// CPU % per module in the last second, and its peak
    mod_cpu: Vec<(&'static str, u64, u64)>,
}

fn mbps(bps: u64) -> String {
    format!("{}.{} Mbps", bps / 1_000_000, bps / 100_000 % 10)
}

fn kpps(pps: u64) -> String {
    format!("{}.{} kpps", pps / 1000, pps / 100 % 10)
}

impl Perf {
    /// Time spent in module `id`.
    pub fn charge(&mut self, id: usize, tsc: u64) {
        if id >= self.mod_tsc.len() {
            self.mod_tsc.resize(id + 1, 0);
        }
        self.mod_tsc[id] += tsc;
    }

    /// Call about once a second.
    pub fn tick(&mut self, nics: &[alloc::boxed::Box<dyn NetDevice>], names: &[&'static str]) {
        let now = arch::now_ms();
        let now_stats: Vec<DevStats> = nics.iter().map(|n| n.stats()).collect();
        let dt = now.saturating_sub(self.last_ms);
        if self.last.len() == now_stats.len() && dt > 0 {
            let per_s = |d: u64| d * 1000 / dt;
            self.cur = self
                .last
                .iter()
                .zip(&now_stats)
                .map(|(a, b)| Rates {
                    rx_bps: per_s((b.rx_bytes - a.rx_bytes) * 8),
                    tx_bps: per_s((b.tx_bytes - a.tx_bytes) * 8),
                    rx_pps: per_s(b.rx_pkts - a.rx_pkts),
                    tx_pps: per_s(b.tx_pkts - a.tx_pkts),
                })
                .collect();
            let per_ms = arch::tsc_per_ms().max(1);
            let idle_ms = (self.idle_tsc - self.last_idle) / per_ms;
            self.cpu = 100u64.saturating_sub(idle_ms * 100 / dt);
            self.mod_last.resize(self.mod_tsc.len(), 0);
            self.mod_cpu.resize(self.mod_tsc.len(), ("", 0, 0));
            for (id, ((t, last), m)) in self.mod_tsc.iter().zip(&self.mod_last).zip(&mut self.mod_cpu).enumerate() {
                let name = names.get(id).copied().unwrap_or("");
                if m.0 != name {
                    *m = (name, 0, 0); // another module in this slot
                }
                m.1 = ((t - last) * 100 / (per_ms * dt)).min(100);
                m.2 = m.2.max(m.1);
            }
            self.mod_last.clone_from(&self.mod_tsc);
            self.peak.resize(self.cur.len(), Rates::default());
            let mut rose = self.cpu > self.cpu_peak;
            self.cpu_peak = self.cpu_peak.max(self.cpu);
            for (p, c) in self.peak.iter_mut().zip(&self.cur) {
                // a new peak worth noting: 10% above the old one
                rose |= c.rx_bps > p.rx_bps * 11 / 10 + 1_000_000 || c.tx_bps > p.tx_bps * 11 / 10 + 1_000_000;
                p.rx_bps = p.rx_bps.max(c.rx_bps);
                p.tx_bps = p.tx_bps.max(c.tx_bps);
                p.rx_pps = p.rx_pps.max(c.rx_pps);
                p.tx_pps = p.tx_pps.max(c.tx_pps);
            }
            if rose && now - self.logged_ms >= 10_000 && self.cpu_peak > 10 {
                self.logged_ms = now;
                kprintln!("perf: {}", self.summary(&now_stats).replace('\n', "; "));
            }
        }
        self.last = now_stats;
        self.last_ms = now;
        self.last_idle = self.idle_tsc;
    }

    fn summary(&self, stats: &[DevStats]) -> String {
        let cpus = crate::acpi::cpu_count();
        let mut s = format!("cpu0 {}% (peak {}%), 1 of {} CPUs in use", self.cpu, self.cpu_peak, if cpus == 0 { String::from("?") } else { format!("{cpus}") });
        // where the time goes: modules that used any, the rest is the kernel
        // (drivers, the network stack, the loop)
        let mut used: Vec<_> = self.mod_cpu.iter().filter(|m| m.2 > 0 && !m.0.is_empty()).collect();
        used.sort_unstable_by_key(|m| core::cmp::Reverse(m.2));
        if !used.is_empty() {
            let mods: u64 = self.mod_cpu.iter().map(|m| m.1).sum();
            s += &format!("\nby module (now, peak): kernel {}%", self.cpu.saturating_sub(mods));
            for m in used {
                s += &format!(", {} {}% {}%", m.0, m.1, m.2);
            }
        }
        for (i, (c, p)) in self.cur.iter().zip(&self.peak).enumerate() {
            if p.rx_pps == 0 && p.tx_pps == 0 {
                continue;
            }
            s += &format!(
                "\nnic{} now rx {} {} tx {} {}, peak rx {} {} tx {} {}",
                i,
                mbps(c.rx_bps),
                kpps(c.rx_pps),
                mbps(c.tx_bps),
                kpps(c.tx_pps),
                mbps(p.rx_bps),
                kpps(p.rx_pps),
                mbps(p.tx_bps),
                kpps(p.tx_pps)
            );
            if let Some(d) = stats.get(i).filter(|d| d.tx_full + d.tx_wait + d.rx_full > 0) {
                s += &format!(", tx dropped {} (waited {} times), rx ring full {} times", d.tx_full, d.tx_wait, d.rx_full);
            }
            if let Some(d) = stats.get(i).filter(|d| d.rx_foreign > 0) {
                s += &format!(", {} not for us", d.rx_foreign);
            }
        }
        s
    }

    /// CPU use over the last second, percent.
    pub fn cpu(&self) -> u32 {
        self.cpu.min(100) as u32
    }

    pub fn report(&self) -> String {
        self.summary(&self.last)
    }

    /// Start the peaks over.
    pub fn reset(&mut self) {
        self.peak.clear();
        self.cpu_peak = 0;
        for m in &mut self.mod_cpu {
            m.2 = 0;
        }
    }
}
