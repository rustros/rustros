//! The system data partition, on the GPT boot disk:
//!
//! ```text
//! 0 - 64 MiB        boot area: GPT, BIOS boot partition, ESP (the image is
//!                   2 MiB today; it may grow up to here without touching data)
//! 64 MiB - 512 MiB  cache partition: things that can be lost or rebuilt
//!                   (log ring, temporary files)
//! 512 MiB - 1 GiB   system data partition: key-value store (configuration,
//!                   modules, each module's data)
//! 1 GiB - end       free, for a future file system (NAS)
//! ```
//!
//! Both partitions are created on first boot. On a disk too small for this
//! (< ~520 MiB) the data partition starts at 64 MiB and there is no cache.
//! Partitions that exist are always used where they are.
//!
//! Every boot also moves the backup GPT to the real end of the disk: the
//! image is dd'ed onto bigger disks, and virtual disks get resized.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod gpt;

use devices::BlockDevice;
use kvstore::Store;

use gpt::{CACHE_TYPE, DATA_TYPE, Gpt};

/// End of the boot area: where the cache partition starts (64 MiB).
pub const BOOT_AREA_END: u64 = 64 * 2048;
/// First sector of the system data partition (512 MiB).
pub const DATA_START: u64 = 512 * 2048;
/// End (exclusive) of the system's area (1 GiB); the rest is for a NAS.
pub const DATA_END: u64 = 1024 * 2048;
/// Smallest data partition worth creating.
const MIN_SECTORS: u64 = 8 * 2048;
/// The store uses at most this much of the partition (256 MiB) so the log a
/// boot has to replay stays bounded; the rest is left for later use.
const STORE_SECTORS: u64 = 256 * 2048;

pub struct Info {
    pub start: u64,
    pub sectors: u64,
    /// (start, sectors) of the cache partition, if there is one.
    pub cache: Option<(u64, u64)>,
    /// The partition was created during this open.
    pub created: bool,
    /// The backup GPT was moved to the end of the disk (first boot after a
    /// dd, or the disk was enlarged).
    pub moved_backup: bool,
}

/// Find the data partition, creating it if needed.
fn partition(disk: &mut dyn BlockDevice, seed: u64) -> Result<Info, &'static str> {
    let last = disk.sectors().checked_sub(1).ok_or("empty disk")?;
    let mut gpt = Gpt::read(disk)?;
    let mut moved_backup = false;
    if !gpt.backup_at(last) {
        if gpt.alternate() > last {
            return Err("the disk is smaller than its partition table says; leaving it alone");
        }
        gpt.write(disk, last)?;
        moved_backup = true;
    }
    let cache = gpt.find(&CACHE_TYPE).map(|p| (p.first, p.last - p.first + 1));
    if let Some(p) = gpt.find(&DATA_TYPE) {
        return Ok(Info { start: p.first, sectors: p.last - p.first + 1, cache, created: false, moved_backup });
    }
    // nothing may sit where the new partitions go
    let limit = if cache.is_some() { DATA_START } else { BOOT_AREA_END };
    if gpt.used_end() > limit {
        return Err("existing partitions overlap the system partitions' place");
    }
    let end = (DATA_END - 1).min(gpt.last_usable());
    let guid = |n: u64| {
        let mut g = [0u8; 16];
        g[..8].copy_from_slice(&(seed ^ n).to_le_bytes());
        g[8..].copy_from_slice(&(seed ^ n).rotate_left(29).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        g
    };
    let (start, cache) = if end >= DATA_START + MIN_SECTORS {
        // the full layout: cache below 512 MiB, data above
        let cache = match cache {
            Some(c) => c,
            None => {
                gpt.add(&CACHE_TYPE, "system-cache", guid(1), BOOT_AREA_END, DATA_START - 1).ok_or("the partition table is full")?;
                (BOOT_AREA_END, DATA_START - BOOT_AREA_END)
            }
        };
        (DATA_START, Some(cache))
    } else if end >= BOOT_AREA_END + MIN_SECTORS && cache.is_none() {
        // small disk: data right after the boot area, no cache
        (BOOT_AREA_END, None)
    } else {
        return Err("no room for the data partition (the disk needs at least 72 MiB)");
    };
    gpt.add(&DATA_TYPE, "system-data", guid(2), start, end).ok_or("the partition table is full")?;
    gpt.write(disk, last)?;
    Ok(Info { start, sectors: end - start + 1, cache, created: true, moved_backup })
}

pub fn open(disk: &mut dyn BlockDevice, seed: u64) -> Result<(Store, Info), &'static str> {
    let part = partition(disk, seed)?;
    let n = part.sectors.min(STORE_SECTORS);
    let store = Store::open(disk, part.start, n, seed).map_err(|e| match e {
        kvstore::Error::Io => "I/O error",
        kvstore::Error::TooSmall => "partition too small",
        _ => "cannot open",
    })?;
    Ok((store, part))
}

#[cfg(test)]
mod tests;
