//! Just enough GPT for the system disk: validate the primary header, move the
//! backup header to the real end of the disk (images are dd'ed onto bigger
//! disks, and virtual disks grow), and find or create the system data
//! partition.

use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;
use kvstore::crc32;

pub const SECTOR: usize = 512;
const SIGNATURE: &[u8; 8] = b"EFI PART";
/// Partition types of the system data and cache partitions.
pub const DATA_TYPE: [u8; 16] = *b"HullOS-data-v1\0\0";
pub const CACHE_TYPE: [u8; 16] = *b"HullOS-cache-v1\0";
/// The files partition: the standard "Linux filesystem data" type
/// (0FC63DAF-8483-4772-8E79-3D69D8477DE4), as it holds an ext4.
pub const FILES_TYPE: [u8; 16] = [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4];

pub struct Gpt {
    header: Vec<u8>,
    entries: Vec<u8>,
    entry_size: usize,
    count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Part {
    pub index: usize,
    pub first: u64,
    pub last: u64,
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn set32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn set64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

impl Gpt {
    /// Read and check the primary GPT.
    pub fn read(disk: &mut dyn BlockDevice) -> Result<Gpt, &'static str> {
        let mut header = vec![0u8; SECTOR];
        if !disk.read(1, &mut header) {
            return Err("cannot read the partition table");
        }
        if &header[..8] != SIGNATURE {
            return Err("no GPT on the boot disk");
        }
        let hsize = le32(&header, 12) as usize;
        if !(92..=SECTOR).contains(&hsize) {
            return Err("bad GPT header");
        }
        let mut h = header[..hsize].to_vec();
        h[16..20].fill(0);
        if crc32(&h) != le32(&header, 16) {
            return Err("GPT header checksum mismatch");
        }
        let (entries_lba, count, entry_size) = (le64(&header, 72), le32(&header, 80) as usize, le32(&header, 84) as usize);
        if entry_size < 128 || count == 0 || count * entry_size > 64 * 1024 {
            return Err("bad GPT entry array");
        }
        let mut entries = vec![0u8; (count * entry_size).div_ceil(SECTOR) * SECTOR];
        if !disk.read(entries_lba, &mut entries) {
            return Err("cannot read the GPT entries");
        }
        entries.truncate(count * entry_size);
        if crc32(&entries) != le32(&header, 88) {
            return Err("GPT entry checksum mismatch");
        }
        Ok(Gpt { header, entries, entry_size, count })
    }

    fn entry(&self, i: usize) -> &[u8] {
        &self.entries[i * self.entry_size..(i + 1) * self.entry_size]
    }

    fn used(&self, i: usize) -> bool {
        self.entry(i)[..16].iter().any(|&b| b != 0)
    }

    /// Where the header says the backup is.
    pub fn alternate(&self) -> u64 {
        le64(&self.header, 32)
    }

    pub fn last_usable(&self) -> u64 {
        le64(&self.header, 48)
    }

    pub fn find(&self, ty: &[u8; 16]) -> Option<Part> {
        (0..self.count).find(|&i| &self.entry(i)[..16] == ty).map(|i| {
            let e = self.entry(i);
            Part { index: i, first: le64(e, 32), last: le64(e, 40) }
        })
    }

    /// End (exclusive) of the highest used partition.
    pub fn used_end(&self) -> u64 {
        (0..self.count).filter(|&i| self.used(i)).map(|i| le64(self.entry(i), 40) + 1).max().unwrap_or(34)
    }

    /// Whether `[first, last]` overlaps a partition.
    pub fn overlaps(&self, first: u64, last: u64) -> bool {
        (0..self.count).filter(|&i| self.used(i)).any(|i| {
            let e = self.entry(i);
            first <= le64(e, 40) && le64(e, 32) <= last
        })
    }

    /// Move partition `i` (type, GUID and name stay).
    pub fn set_range(&mut self, i: usize, first: u64, last: u64) {
        let es = self.entry_size;
        let e = &mut self.entries[i * es..(i + 1) * es];
        set64(e, 32, first);
        set64(e, 40, last);
    }

    /// Add a partition in the first free entry.
    pub fn add(&mut self, ty: &[u8; 16], name: &str, guid: [u8; 16], first: u64, last: u64) -> Option<Part> {
        let i = (0..self.count).find(|&i| !self.used(i))?;
        let es = self.entry_size;
        let e = &mut self.entries[i * es..(i + 1) * es];
        e.fill(0);
        e[..16].copy_from_slice(ty);
        e[16..32].copy_from_slice(&guid);
        set64(e, 32, first);
        set64(e, 40, last);
        for (k, c) in name.encode_utf16().enumerate().take(36) {
            e[56 + 2 * k..58 + 2 * k].copy_from_slice(&c.to_le_bytes());
        }
        Some(Part { index: i, first, last })
    }

    /// Write primary and backup GPT for a disk whose last sector is `last`
    /// (moves the backup to the end of the disk and widens the usable range).
    pub fn write(&mut self, disk: &mut dyn BlockDevice, last: u64) -> Result<(), &'static str> {
        let array_sectors = (self.count * self.entry_size).div_ceil(SECTOR) as u64;
        let backup_entries = last - array_sectors;
        set64(&mut self.header, 32, last); // alternate LBA
        set64(&mut self.header, 48, backup_entries - 1); // last usable
        set32(&mut self.header, 88, crc32(&self.entries));
        let mut array = self.entries.clone();
        array.resize(array_sectors as usize * SECTOR, 0);
        // backup first, so a crash in between leaves a valid primary
        let mut backup = self.header.clone();
        set64(&mut backup, 24, last); // my LBA
        set64(&mut backup, 32, 1); // alternate LBA
        set64(&mut backup, 72, backup_entries); // entries LBA
        seal(&mut backup);
        if !disk.write(backup_entries, &array) || !disk.write(last, &backup) {
            return Err("cannot write the backup GPT");
        }
        let mut primary = self.header.clone();
        seal(&mut primary);
        if !disk.write(le64(&self.header, 72), &array) || !disk.write(1, &primary) {
            return Err("cannot write the GPT");
        }
        self.header = primary;
        // the protective MBR covers the whole disk
        let mut mbr = vec![0u8; SECTOR];
        if disk.read(0, &mut mbr) && mbr[446 + 4] == 0xEE {
            set32(&mut mbr, 446 + 12, last.min(0xFFFF_FFFF) as u32);
            disk.write(0, &mbr);
        }
        Ok(())
    }

    /// Whether the backup header sits at `last` (false after a dd onto a
    /// bigger disk or a disk resize).
    pub fn backup_at(&self, last: u64) -> bool {
        le64(&self.header, 32) == last
    }
}

fn seal(h: &mut [u8]) {
    let size = le32(h, 12) as usize;
    h[16..20].fill(0);
    let crc = crc32(&h[..size]);
    set32(h, 16, crc);
}
