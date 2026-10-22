//! The metadata block cache: bitmaps, inode tables, directory and extent
//! tree blocks are read once and changed here; `sync` writes the changed
//! ones out (neighbours in one request).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::{BLOCK, Fs, R, Vol};

/// Clean blocks are dropped when the cache holds more than this many.
const MAX_BLOCKS: usize = 4096;
/// The most blocks one write request carries.
const MAX_RUN: usize = 64;

#[derive(Default)]
pub(crate) struct Cache {
    map: BTreeMap<u64, Entry>,
    dirty: usize,
}

struct Entry {
    data: Vec<u8>,
    dirty: bool,
    /// replayed from a journal that cannot be written back: kept, never dropped
    pinned: bool,
}

impl Cache {
    pub(crate) fn dirty_count(&self) -> usize {
        self.dirty
    }

    fn make_room(&mut self) {
        if self.map.len() >= MAX_BLOCKS {
            self.map.retain(|_, e| e.dirty || e.pinned);
        }
    }
}

impl Fs {
    /// A metadata block, as it is now.
    pub(crate) fn mread(&mut self, v: &mut Vol, b: u64) -> R<&[u8]> {
        self.load(v, b)?;
        Ok(&self.cache.map[&b].data)
    }

    /// A metadata block to change (written out at the next sync).
    pub(crate) fn mmod(&mut self, v: &mut Vol, b: u64) -> R<&mut [u8]> {
        self.load(v, b)?;
        let c = &mut self.cache;
        let e = c.map.get_mut(&b).expect("loaded");
        if !e.dirty {
            e.dirty = true;
            c.dirty += 1;
        }
        Ok(&mut e.data)
    }

    /// A newly allocated metadata block: zeros, not read from the disk.
    pub(crate) fn mzero(&mut self, b: u64) -> &mut [u8] {
        self.cache.make_room();
        let c = &mut self.cache;
        let e = c.map.entry(b).or_insert_with(|| Entry { data: vec![0u8; BLOCK], dirty: false, pinned: false });
        if !e.dirty {
            e.dirty = true;
            c.dirty += 1;
        }
        e.data.fill(0);
        &mut e.data
    }

    /// Change a metadata block to `data` only if it differs.
    pub(crate) fn mset(&mut self, v: &mut Vol, b: u64, data: &[u8]) -> R<()> {
        if self.mread(v, b)? != data {
            self.mmod(v, b)?.copy_from_slice(data);
        }
        Ok(())
    }

    /// Blocks given back: whatever the cache held for them is dropped (they
    /// may become file data, written past the cache).
    pub(crate) fn forget(&mut self, first: u64, len: u64) {
        let c = &mut self.cache;
        let gone: Vec<u64> = c.map.range(first..first + len).map(|(b, _)| *b).collect();
        for b in gone {
            if c.map.remove(&b).is_some_and(|e| e.dirty) {
                c.dirty -= 1;
            }
        }
    }

    fn load(&mut self, v: &mut Vol, b: u64) -> R<()> {
        if !self.cache.map.contains_key(&b) {
            if b >= self.blocks {
                return Err(crate::Error::Corrupt("block number out of range"));
            }
            self.cache.make_room();
            let data = v.block(b)?;
            self.cache.map.insert(b, Entry { data, dirty: false, pinned: false });
        }
        Ok(())
    }

    /// How many changed blocks wait for the next sync.
    pub fn dirty_blocks(&self) -> usize {
        self.cache.dirty
    }

    /// A cached block's contents.
    pub(crate) fn cached(&self, b: u64) -> &[u8] {
        &self.cache.map[&b].data
    }

    /// A block as a replayed journal has it (the disk is not written).
    pub(crate) fn pin(&mut self, b: u64, data: Vec<u8>) {
        self.cache.map.insert(b, Entry { data, dirty: false, pinned: true });
    }

    /// Everything changed to the disk: through the journal if there is one.
    pub fn sync(&mut self, v: &mut Vol) -> R<()> {
        if self.meta_dirty {
            self.render_meta(v)?;
        }
        if self.cache.dirty == 0 {
            return Ok(());
        }
        let dirty: Vec<u64> = self.cache.map.iter().filter(|(_, e)| e.dirty).map(|(b, _)| *b).collect();
        if !self.commit(v, &dirty)? {
            self.write_home(v, &dirty)?;
        }
        Ok(())
    }

    /// Cached blocks (sorted) to their places; clean after.
    pub(crate) fn write_home(&mut self, v: &mut Vol, blocks: &[u64]) -> R<()> {
        let mut k = 0;
        while k < blocks.len() {
            let mut n = 1;
            while k + n < blocks.len() && n < MAX_RUN && blocks[k + n] == blocks[k] + n as u64 {
                n += 1;
            }
            let mut buf = Vec::with_capacity(n * BLOCK);
            for b in &blocks[k..k + n] {
                buf.extend_from_slice(&self.cache.map[b].data);
            }
            v.write(blocks[k], &buf)?;
            for b in &blocks[k..k + n] {
                let e = self.cache.map.get_mut(b).expect("cached");
                if e.dirty {
                    e.dirty = false;
                    self.cache.dirty -= 1;
                }
            }
            k += n;
        }
        Ok(())
    }
}
