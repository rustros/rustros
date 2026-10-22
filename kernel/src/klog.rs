//! Persistent console log: everything printed on the console also goes to
//! the start of the cache partition, one 1 MiB ring per boot, the last
//! `SLOTS` boots kept, so the previous boot's last words can be read after
//! a reboot (remotely too).
//!
//! Slot layout: a header sector ("HULLOG01", boot number, bytes written),
//! then the text as a ring; once more than fits was written, the ring holds
//! the most recent part.

use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;

use crate::Global;

/// On-disk format identifier (existing logs carry it).
const MAGIC: &[u8; 8] = b"HULLOG01";
pub const SLOTS: u64 = 8;
const SLOT_SECTORS: u64 = 2048; // 1 MiB
const DATA_BYTES: u64 = (SLOT_SECTORS - 1) * 512;
/// Console output kept in RAM until it reaches the disk.
const PENDING_MAX: usize = 64 * 1024;

struct Pending {
    buf: Vec<u8>,
    lost: u64,
}

static PENDING: Global<Pending> = Global::new(Pending { buf: Vec::new(), lost: 0 });

/// Called for all console output.
pub fn append(s: &[u8]) {
    // Safety: single core; the console is the only writer.
    let p = unsafe { PENDING.get() };
    if p.buf.len() + s.len() > PENDING_MAX {
        p.lost += s.len() as u64;
        return;
    }
    p.buf.extend_from_slice(s);
}

/// One boot's log on disk.
pub struct DiskLog {
    /// first sector of the log area
    base: u64,
    /// this boot's number
    pub seq: u64,
    /// bytes written this boot
    total: u64,
    /// the partial sector at the end of the text
    tail: Vec<u8>,
}

fn header(disk: &mut dyn BlockDevice, lba: u64) -> Option<(u64, u64)> {
    let mut h = [0u8; 512];
    if !disk.read(lba, &mut h) || &h[..8] != MAGIC {
        return None;
    }
    Some((u64::from_le_bytes(h[8..16].try_into().unwrap()), u64::from_le_bytes(h[16..24].try_into().unwrap())))
}

impl DiskLog {
    /// Take the next slot in the area at `start` (the cache partition; it
    /// needs SLOTS MiB).
    pub fn open(disk: &mut dyn BlockDevice, start: u64, sectors: u64) -> Option<DiskLog> {
        if sectors < SLOTS * SLOT_SECTORS {
            return None;
        }
        let last = (0..SLOTS).filter_map(|i| header(disk, start + i * SLOT_SECTORS)).map(|(seq, _)| seq).max().unwrap_or(0);
        let mut log = DiskLog { base: start, seq: last + 1, total: 0, tail: Vec::new() };
        log.scrub(disk);
        log.write_header(disk);
        Some(log)
    }

    /// Mask passwords that reached the logs on disk (written before they
    /// were masked at the console).
    fn scrub(&self, disk: &mut dyn BlockDevice) {
        let mut buf = vec![0u8; 64 * 512];
        for i in 0..SLOTS {
            let lba = self.base + i * SLOT_SECTORS;
            let Some((_, total)) = header(disk, lba) else { continue };
            let sectors = total.min(DATA_BYTES).div_ceil(512);
            for at in (0..sectors).step_by(64) {
                let n = (sectors - at).min(64) as usize;
                let chunk = &mut buf[..n * 512];
                if disk.read(lba + 1 + at, chunk) && rustros_util::secret::redact(chunk) {
                    disk.write(lba + 1 + at, chunk);
                }
            }
        }
    }

    fn slot_lba(&self, seq: u64) -> u64 {
        self.base + (seq % SLOTS) * SLOT_SECTORS
    }

    fn write_header(&mut self, disk: &mut dyn BlockDevice) -> bool {
        let mut h = [0u8; 512];
        h[..8].copy_from_slice(MAGIC);
        h[8..16].copy_from_slice(&self.seq.to_le_bytes());
        h[16..24].copy_from_slice(&self.total.to_le_bytes());
        disk.write(self.slot_lba(self.seq), &h)
    }

    /// Write out what was printed since the last flush.
    pub fn flush(&mut self, disk: &mut dyn BlockDevice) {
        // Safety: single core; nothing prints while we take the buffer.
        let p = unsafe { PENDING.get() };
        if p.buf.is_empty() && p.lost == 0 {
            return;
        }
        let mut data = core::mem::take(&mut p.buf);
        if p.lost > 0 {
            let note = alloc::format!("\n[log: {} bytes lost]\n", p.lost);
            data.extend_from_slice(note.as_bytes());
            p.lost = 0;
        }
        let data_lba = self.slot_lba(self.seq) + 1;
        let mut pos = self.total % DATA_BYTES;
        // continue the partial sector, then whole sectors up to the ring's end
        let mut buf = core::mem::take(&mut self.tail);
        buf.extend_from_slice(&data);
        rustros_util::secret::redact(&mut buf);
        let mut sector = pos / 512;
        let mut rest: &[u8] = &buf;
        while !rest.is_empty() {
            let room = (DATA_BYTES - sector * 512) as usize;
            let (now, later) = rest.split_at(rest.len().min(room));
            let mut chunk = now.to_vec();
            chunk.resize(chunk.len().div_ceil(512) * 512, 0);
            if !disk.write(data_lba + sector, &chunk) {
                return;
            }
            sector = 0; // wrapped
            rest = later;
        }
        self.total += data.len() as u64;
        pos = self.total % DATA_BYTES;
        let partial = (pos % 512) as usize;
        self.tail = buf[buf.len() - partial.min(buf.len())..].to_vec();
        self.write_header(disk);
    }

    /// Boots with a log: (boot number, bytes written).
    pub fn list(&self, disk: &mut dyn BlockDevice) -> Vec<(u64, u64)> {
        let mut l: Vec<(u64, u64)> = (0..SLOTS).filter_map(|i| header(disk, self.base + i * SLOT_SECTORS)).filter(|&(seq, _)| seq + SLOTS > self.seq).collect();
        l.sort();
        l
    }

    /// The text of boot `seq` (the most recent part if it outgrew its slot).
    pub fn read(&self, disk: &mut dyn BlockDevice, seq: u64) -> Option<Vec<u8>> {
        let lba = self.slot_lba(seq);
        let (s, total) = header(disk, lba)?;
        if s != seq {
            return None;
        }
        let used = total.min(DATA_BYTES);
        let mut data = vec![0u8; (used.div_ceil(512) * 512) as usize];
        if !data.is_empty() && !disk.read(lba + 1, &mut data) {
            return None;
        }
        data.truncate(used as usize);
        if total > DATA_BYTES {
            data.rotate_left((total % DATA_BYTES) as usize);
        }
        Some(data)
    }
}
