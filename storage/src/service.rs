//! The boot disk's services as a boot module provides them to the kernel
//! (`rustros_api::module::Storage`): grubenv and the kernel slots (`slots`),
//! the data partition's key-value store, the console log in the cache
//! partition, the files partition and the ESP.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;
use kvstore::Store;
use rustros_api::module::{Disk, Hw, Storage};
use rustros_api::sys::{KvError, StorageInfo};
use rustros_util::snap::{R, W};

use crate::gpt::Gpt;
use crate::log::{DiskLog, SLOTS};
use crate::{BOOT_AREA_END, Info};

/// GPT type of the EFI system partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B, as stored).
const ESP_TYPE: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];

struct Open {
    disk: Box<dyn Disk>,
    upd: slots::Updater,
    store: Option<(Store, Info)>,
    log: Option<DiskLog>,
    /// the files partition: (first sector, sectors)
    files: Option<(u64, u64)>,
}

#[derive(Default)]
pub struct Service {
    b: Option<Open>,
}

/// The files partition, lent out (LBAs from its start).
struct PartDisk<'a> {
    disk: &'a mut dyn Disk,
    start: u64,
    sectors: u64,
}

impl PartDisk<'_> {
    fn inside(&self, lba: u64, len: usize) -> bool {
        len % 512 == 0 && lba.checked_add(len as u64 / 512).is_some_and(|end| end <= self.sectors)
    }
}

impl Disk for PartDisk<'_> {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.inside(lba, buf.len()) && self.disk.read(self.start + lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        self.inside(lba, buf.len()) && self.disk.write(self.start + lba, buf)
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
}

fn kv_err(e: kvstore::Error) -> KvError {
    match e {
        kvstore::Error::Io => KvError::Io,
        kvstore::Error::TooLarge => KvError::TooLarge,
        kvstore::Error::Full | kvstore::Error::TooSmall => KvError::Full,
    }
}

/// Some(()) if `n` sectors from `lba` lie inside the boot disk's ESP.
fn esp_range(disk: &mut dyn BlockDevice, lba: u64, n: u64) -> Option<()> {
    let p = Gpt::read(disk).ok()?.find(&ESP_TYPE)?;
    (n > 0 && n <= 128 && lba >= p.first && lba.checked_add(n)? <= p.last + 1).then_some(())
}

impl Service {
    pub fn new() -> Service {
        Service::default()
    }
}

/// The state handed to the next version (hot replacement).
const TAG: &[u8; 4] = b"STOR";

/// Where this boot's log is (None: it is not kept).
fn resume_state(s: &[u8]) -> Result<Option<(u64, u64, Vec<u8>)>, String> {
    let (mut r, v) = R::new(s, TAG)?;
    if v != 1 {
        return Err(format!("state format {v}: this version reads 1"));
    }
    let log = if r.bool()? { Some((r.u64()?, r.u64()?, r.bytes()?)) } else { None };
    r.end()?;
    Ok(log)
}

impl Storage for Service {
    fn open(&mut self, hw: &'static dyn Hw, cmdline: &str, disks: &mut Vec<Box<dyn Disk>>, seed: u64, state: Option<&[u8]>) -> Result<(), String> {
        // carrying on after a replacement: this boot's log goes on, the
        // boot messages are not repeated
        let resume = match state {
            Some(s) => Some(resume_state(s)?),
            None => None,
        };
        let quiet = resume.is_some();
        let log = |s: String| {
            if !quiet {
                hw.log(&s)
            }
        };
        let (mut disk, upd) = slots::Updater::new(cmdline, disks)?;
        log(format!("disk: running slot {}{}", upd.slot, if upd.trial { " (trial boot)" } else { "" }));
        if let Some(p) = upd.get("last_panic") {
            log(format!("disk: last crash: {}", p));
        }
        let store = match crate::open(&mut *disk, seed) {
            Ok((store, part)) => {
                if part.moved_backup {
                    log(format!("storage: disk is {} MiB; moved the backup GPT to its end", disk.sectors() / 2048));
                }
                if part.created {
                    log(format!("storage: created data partition, {} MiB at {} MiB", part.sectors / 2048, part.start / 2048));
                }
                if let Some((start, n)) = part.cache {
                    log(format!("storage: cache partition {} MiB at {} MiB", n / 2048, start / 2048));
                }
                let (live, _, half) = store.usage();
                log(format!("storage: data partition {} MiB, store {} MiB, {} keys / {} bytes", part.sectors / 2048, half / 1024, store.keys("").count(), live));
                Some((store, part))
            }
            Err(e) => {
                hw.log(&format!("storage: unavailable: {}", e));
                None
            }
        };
        // the console log goes to the start of the cache partition
        let cache = store.as_ref().and_then(|(_, part)| part.cache);
        let dl = match resume {
            Some(Some((seq, total, tail))) => cache.and_then(|(start, n)| DiskLog::resume(start, n, seq, total, tail)),
            Some(None) => None,
            None => cache.and_then(|(start, n)| DiskLog::open(&mut *disk, start, n)),
        };
        match &dl {
            Some(l) => log(format!("log: this is boot {}; the last {} boots' console logs are kept", l.seq, SLOTS)),
            None => log("log: no cache partition, the console log is not kept".to_string()),
        }
        // the files partition: its file system is a driver module's
        let files = store.as_ref().and_then(|(_, part)| part.files);
        if let Some((_, n)) = files {
            log(format!("storage: files partition {} MiB", n >> 11));
        }
        self.b = Some(Open { disk, upd, store, log: dl, files });
        Ok(())
    }

    fn state_version(&self) -> u32 {
        1
    }
    fn busy(&self) -> bool {
        self.b.as_ref().is_some_and(|b| b.upd.busy())
    }
    /// Format 1: whether this boot's log is kept, and where it is (boot
    /// number, bytes written, the partial sector). Everything else is on
    /// the disk.
    fn hand_over(&mut self, version: u32, disks: &mut Vec<Box<dyn Disk>>) -> Option<Vec<u8>> {
        if version != 1 || self.busy() {
            return None;
        }
        let b = self.b.take()?;
        let mut w = W::new(TAG, 1);
        w.u8(b.log.is_some() as u8);
        if let Some(l) = &b.log {
            let (seq, total, tail) = l.position();
            w.u64(seq);
            w.u64(total);
            w.bytes(tail);
        }
        disks.push(b.disk);
        Some(w.0)
    }

    fn slot(&self) -> (char, bool) {
        self.b.as_ref().map_or(('a', false), |b| (b.upd.slot, b.upd.trial))
    }
    fn slot_bytes(&self) -> u64 {
        self.b.as_ref().map_or(0, |b| b.upd.sectors * 512)
    }
    fn env(&self, key: &str) -> Option<&str> {
        self.b.as_ref()?.upd.get(key)
    }
    fn env_vars(&self) -> Vec<(String, String)> {
        let Some(b) = self.b.as_ref() else { return Vec::new() };
        b.upd.vars().map(|(k, v)| (String::from(k), String::from(v))).collect()
    }
    fn env_set(&mut self, vars: &[(&str, &str)]) -> bool {
        self.b.as_mut().is_some_and(|b| b.upd.set_vars(&mut *b.disk, vars))
    }
    fn update_begin(&mut self) -> bool {
        self.b.as_mut().is_some_and(|b| b.upd.begin())
    }
    fn update_write(&mut self, data: &[u8]) -> bool {
        self.b.as_mut().is_some_and(|b| b.upd.write(&mut *b.disk, data))
    }
    fn update_commit(&mut self) -> bool {
        self.b.as_mut().is_some_and(|b| b.upd.commit(&mut *b.disk))
    }
    fn confirm(&mut self) -> bool {
        self.b.as_mut().is_some_and(|b| b.upd.confirm(&mut *b.disk))
    }

    fn kv_get(&self, key: &str) -> Option<&[u8]> {
        self.b.as_ref()?.store.as_ref()?.0.get(key)
    }
    fn kv_keys(&self, prefix: &str) -> Vec<String> {
        match self.b.as_ref().and_then(|b| b.store.as_ref()) {
            Some((s, _)) => s.keys(prefix).map(String::from).collect(),
            None => Vec::new(),
        }
    }
    fn kv_put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        let b = self.b.as_mut().ok_or(KvError::NoStorage)?;
        let (s, _) = b.store.as_mut().ok_or(KvError::NoStorage)?;
        s.put(&mut *b.disk, key, value).map_err(kv_err)
    }
    fn kv_delete(&mut self, key: &str) -> Result<bool, KvError> {
        let b = self.b.as_mut().ok_or(KvError::NoStorage)?;
        let (s, _) = b.store.as_mut().ok_or(KvError::NoStorage)?;
        s.delete(&mut *b.disk, key).map_err(kv_err)
    }
    fn kv_info(&self) -> Option<StorageInfo> {
        let (s, part) = self.b.as_ref()?.store.as_ref()?;
        let (live, tail, half) = s.usage();
        Some(StorageInfo { partition_bytes: part.sectors * 512, store_bytes: half * 2 * 512, live_bytes: live as u64, log_bytes: tail * 512 })
    }

    fn log_write(&mut self, text: &[u8]) {
        if let Some(b) = self.b.as_mut() {
            if let Some(l) = b.log.as_mut() {
                l.write(&mut *b.disk, text);
            }
        }
    }
    fn log_seq(&self) -> Option<u64> {
        self.b.as_ref()?.log.as_ref().map(|l| l.seq)
    }
    fn log_list(&mut self) -> Vec<(u64, u64)> {
        let Some(b) = self.b.as_mut() else { return Vec::new() };
        b.log.as_ref().map(|l| l.list(&mut *b.disk)).unwrap_or_default()
    }
    fn log_read(&mut self, seq: u64) -> Option<Vec<u8>> {
        let b = self.b.as_mut()?;
        b.log.as_ref()?.read(&mut *b.disk, seq)
    }

    fn files(&mut self, f: &mut dyn FnMut(&mut dyn Disk)) -> bool {
        let Some(b) = self.b.as_mut() else { return false };
        let Some((start, sectors)) = b.files else { return false };
        f(&mut PartDisk { disk: &mut *b.disk, start, sectors });
        true
    }
    fn esp_read(&mut self, lba: u64, sectors: usize) -> Option<Vec<u8>> {
        let disk = &mut *self.b.as_mut()?.disk;
        esp_range(disk, lba, sectors as u64)?;
        let mut buf = vec![0u8; sectors * 512];
        disk.read(lba, &mut buf).then_some(buf)
    }
    fn esp_write(&mut self, lba: u64, data: &[u8]) -> bool {
        let Some(b) = self.b.as_mut() else { return false };
        let disk = &mut *b.disk;
        data.len() % 512 == 0 && esp_range(disk, lba, (data.len() / 512) as u64).is_some() && disk.write(lba, data)
    }
    fn boot_area_write(&mut self, lba: u64, data: &[u8]) -> bool {
        let Some(b) = self.b.as_mut() else { return false };
        let n = data.len() as u64 / 512;
        if data.len() % 512 != 0 || n == 0 || n > 128 || lba < 34 || lba + n > BOOT_AREA_END {
            return false;
        }
        Gpt::read(&mut *b.disk).is_ok_and(|g| !g.overlaps(lba, lba + n - 1)) && b.disk.write(lba, data)
    }
    fn esp_move(&mut self, first: u64, last: u64) -> Result<(), String> {
        let b = self.b.as_mut().ok_or("no boot disk")?;
        if first < 34 || last < first || last >= BOOT_AREA_END {
            return Err("not inside the boot area".into());
        }
        let mut gpt = Gpt::read(&mut *b.disk)?;
        let esp = gpt.find(&ESP_TYPE).ok_or("no EFI partition")?;
        if gpt.overlaps(first, last) {
            return Err("the new place overlaps a partition".into());
        }
        // a FAT that fits the place
        let mut boot = [0u8; 512];
        if !b.disk.read(first, &mut boot) {
            return Err("cannot read the new place".into());
        }
        let total = u16::from_le_bytes([boot[19], boot[20]]) as u64;
        let total = if total == 0 { u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]) as u64 } else { total };
        if boot[510..512] != [0x55, 0xAA] || &boot[54..57] != b"FAT" || total == 0 || total > last - first + 1 {
            return Err("no FAT boot sector there, or it does not fit".into());
        }
        gpt.set_range(esp.index, first, last);
        let end = b.disk.sectors() - 1;
        gpt.write(&mut *b.disk, end)?;
        Ok(())
    }
    fn boot_area_read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let Some(b) = self.b.as_mut() else { return false };
        buf.len() % 512 == 0 && lba.checked_add(buf.len() as u64 / 512).is_some_and(|end| end <= BOOT_AREA_END) && b.disk.read(lba, buf)
    }
}
