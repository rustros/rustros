//! A/B kernel slots on the boot disk, switched through GRUB's grubenv.
//!
//! mkimg.py preallocates /boot/rustros-a.elf and /boot/rustros-b.elf as contiguous
//! files on the ESP and passes their LBAs on the command line, so updating
//! is a raw sector write; the FAT itself never changes.
//!
//! grub.cfg boots `try_slot` once if set (clearing it), else `boot_slot`.
//! grubenv also carries the saved network settings (`net_ip`, `net_gw`,
//! `net_mtu`); every rewrite keeps all variables.
//!
//! The disk is passed to every call (the kernel shares it with the data
//! partition), so this works with any `BlockDevice` and is tested on the host.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use devices::BlockDevice;

const ENV_MAGIC: &[u8] = b"# GRUB Environment Block\n";
const CHUNK: usize = 64 * 1024;

/// Slot bookkeeping. The boot disk itself is owned by the kernel and passed
/// in, since the data partition lives on it too.
pub struct Updater {
    pub slot: char,
    pub trial: bool,
    default_slot: char,
    lba: [u64; 2],
    pub sectors: u64,
    env_lba: u64,
    /// grubenv variables, in file order
    env: Vec<(String, String)>,
    buf: Vec<u8>,
    written: u64,
    active: bool,
}

fn arg<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    rustros_util::wire::cmdline_get(cmdline, key)
}

fn other(slot: char) -> char {
    if slot == 'a' { 'b' } else { 'a' }
}

impl Updater {
    /// Find the boot disk (the one holding our grubenv and running slot).
    pub fn new<D: BlockDevice>(cmdline: &str, disks: Vec<D>) -> Result<(D, Updater), &'static str> {
        let slot = match arg(cmdline, "rustros.slot") {
            Some("a") => 'a',
            Some("b") => 'b',
            _ => return Err("no rustros.slot on the command line"),
        };
        let trial = arg(cmdline, "rustros.trial") == Some("1");
        let mut nums = arg(cmdline, "rustros.slots").ok_or("no rustros.slots")?.split(',').map(|v| v.parse::<u64>());
        let (Some(Ok(a)), Some(Ok(b)), Some(Ok(sectors))) = (nums.next(), nums.next(), nums.next()) else {
            return Err("bad rustros.slots");
        };
        let env_lba: u64 = arg(cmdline, "rustros.env").and_then(|v| v.parse().ok()).ok_or("bad rustros.env")?;
        let cur = if slot == 'a' { a } else { b };
        for mut disk in disks {
            let mut env = alloc::vec![0u8; 1024];
            let mut elf = alloc::vec![0u8; 512];
            if disk.read(env_lba, &mut env) && env.starts_with(ENV_MAGIC) && disk.read(cur, &mut elf) && elf.starts_with(b"\x7fELF") {
                if disk.read_only() {
                    return Err("boot disk is read-only");
                }
                let text = String::from_utf8_lossy(&env);
                let env: Vec<(String, String)> = text
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .filter_map(|l| l.split_once('='))
                    .map(|(k, v)| (String::from(k), String::from(v)))
                    .collect();
                let default_slot = match env.iter().find(|(k, _)| k == "boot_slot").map(|(_, v)| v.as_str()) {
                    Some("b") => 'b',
                    _ => 'a',
                };
                let upd = Updater {
                    slot,
                    trial,
                    default_slot,
                    lba: [a, b],
                    sectors,
                    env_lba,
                    env,
                    buf: Vec::new(),
                    written: 0,
                    active: false,
                };
                return Ok((disk, upd));
            }
        }
        Err("boot disk not found among virtio-blk devices")
    }

    fn target_lba(&self) -> u64 {
        self.lba[if other(self.slot) == 'a' { 0 } else { 1 }]
    }

    pub fn vars(&self) -> impl Iterator<Item = (&str, &str)> {
        self.env.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn set(&mut self, key: &str, value: &str) {
        self.env.retain(|(k, _)| k != key);
        if !value.is_empty() {
            self.env.push((String::from(key), String::from(value)));
        }
    }

    fn write_env(&mut self, disk: &mut dyn BlockDevice, boot: char, try_slot: Option<char>) -> bool {
        self.set("boot_slot", &format!("{boot}"));
        self.set("try_slot", &try_slot.map(|t| format!("{t}")).unwrap_or_default());
        self.save_env(disk)
    }

    fn save_env(&mut self, disk: &mut dyn BlockDevice) -> bool {
        let mut s = String::from_utf8_lossy(ENV_MAGIC).into_owned();
        for (k, v) in &self.env {
            s += &format!("{k}={v}\n");
        }
        if s.len() > 1024 {
            return false;
        }
        let mut b = s.into_bytes();
        b.resize(1024, b'#');
        disk.write(self.env_lba, &b)
    }

    /// Persist variables (an empty value removes one). Values must be plain
    /// text without newlines or backslashes.
    pub fn set_vars(&mut self, disk: &mut dyn BlockDevice, vars: &[(&str, &str)]) -> bool {
        if vars.iter().any(|(_, v)| v.contains(['\n', '\\'])) {
            return false;
        }
        for (k, v) in vars {
            self.set(k, v);
        }
        self.save_env(disk)
    }

    pub fn begin(&mut self) -> bool {
        if self.trial {
            return false; // confirm the running kernel first
        }
        self.buf.clear();
        self.written = 0;
        self.active = true;
        true
    }

    fn flush(&mut self, disk: &mut dyn BlockDevice, n: usize) -> bool {
        let lba = self.target_lba() + self.written / 512;
        let ok = disk.write(lba, &self.buf[..n]);
        self.buf.drain(..n);
        self.written += n as u64;
        ok
    }

    pub fn write(&mut self, disk: &mut dyn BlockDevice, data: &[u8]) -> bool {
        if !self.active || self.written + (self.buf.len() + data.len()) as u64 > self.sectors * 512 {
            self.active = false;
            return false;
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= CHUNK {
            if !self.flush(disk, CHUNK) {
                self.active = false;
                return false;
            }
        }
        true
    }

    pub fn commit(&mut self, disk: &mut dyn BlockDevice) -> bool {
        if !self.active {
            return false;
        }
        self.active = false;
        let n = self.buf.len().div_ceil(512) * 512;
        self.buf.resize(n, 0);
        if n > 0 && !self.flush(disk, n) {
            return false;
        }
        let try_slot = other(self.slot);
        self.write_env(disk, self.default_slot, Some(try_slot))
    }

    pub fn confirm(&mut self, disk: &mut dyn BlockDevice) -> bool {
        if !self.write_env(disk, self.slot, None) {
            return false;
        }
        self.default_slot = self.slot;
        self.trial = false;
        true
    }
}

#[cfg(test)]
mod tests;
