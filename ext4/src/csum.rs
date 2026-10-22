//! metadata_csum: the CRC-32C checksums Linux keeps on the superblock,
//! group descriptors, bitmaps, inodes, extent tree blocks, directory blocks
//! and attribute blocks; and the groups mke2fs leaves uninitialised
//! (their bitmaps are worked out here, as the kernel does, before use).

use alloc::vec;

use crate::journal::crc32c;
use crate::{BLOCK, Error, Fs, Inode, R, Vol, has_super, le16, le32, put16, put32};

/// Group flags.
pub(crate) const BG_INODE_UNINIT: u16 = 0x1;
pub(crate) const BG_BLOCK_UNINIT: u16 = 0x2;

/// A directory block's checksum tail: the last 12 bytes.
pub(crate) const DIR_TAIL: usize = 12;

/// The block has a checksum tail (a fake entry of 12 bytes, type 0xDE).
pub(crate) fn has_dir_tail(blk: &[u8]) -> bool {
    let t = BLOCK - DIR_TAIL;
    le32(blk, t) == 0 && le16(blk, t + 4) == DIR_TAIL as u16 && blk[t + 6] == 0 && blk[t + 7] == 0xDE
}

pub(crate) fn put_dir_tail(blk: &mut [u8]) {
    let t = BLOCK - DIR_TAIL;
    blk[t..].fill(0);
    put16(blk, t + 4, DIR_TAIL as u16);
    blk[t + 7] = 0xDE;
}

impl Fs {
    /// The checksum seed of an inode (number and generation).
    pub(crate) fn inode_seed(&self, ino: u32, generation: u32) -> u32 {
        let s = self.csum.unwrap_or(0);
        crc32c(crc32c(s, &ino.to_le_bytes()), &generation.to_le_bytes())
    }

    pub(crate) fn seed_of(&self, i: &Inode) -> u32 {
        self.inode_seed(i.ino, le32(&i.raw, 0x64))
    }

    /// An inode's checksum into it.
    pub(crate) fn seal_inode(&self, raw: &mut [u8], ino: u32) {
        if self.csum.is_none() {
            return;
        }
        let hi = raw.len() > 128 && le16(raw, 0x80) >= 4;
        put16(raw, 0x7C, 0);
        if hi {
            put16(raw, 0x82, 0);
        }
        let c = crc32c(self.inode_seed(ino, le32(raw, 0x64)), raw);
        put16(raw, 0x7C, c as u16);
        if hi {
            put16(raw, 0x82, (c >> 16) as u16);
        }
    }

    /// The superblock's checksum (its last 4 bytes).
    pub(crate) fn seal_sb(&self, sb: &mut [u8]) {
        if self.csum.is_some() {
            let c = crc32c(!0, &sb[..0x3FC]);
            put32(sb, 0x3FC, c);
        }
    }

    /// A group descriptor's checksum (16 bits of the CRC).
    pub(crate) fn seal_desc(&self, d: &mut [u8], g: usize) {
        if let Some(s) = self.csum {
            put16(d, 0x1E, 0);
            let c = crc32c(crc32c(s, &(g as u32).to_le_bytes()), d);
            put16(d, 0x1E, c as u16);
        }
    }

    /// The checksums of group `g`'s bitmaps (they go into its descriptor).
    pub(crate) fn bitmap_csums(&mut self, v: &mut Vol, g: usize) -> R<()> {
        let Some(s) = self.csum else { return Ok(()) };
        let (bpg, ipg) = (self.blocks_per_group as usize / 8, self.inodes_per_group as usize / 8);
        let (bb, ib) = (self.groups[g].block_bitmap, self.groups[g].inode_bitmap);
        let flags = self.groups[g].flags;
        if flags & BG_BLOCK_UNINIT == 0 {
            let c = crc32c(s, &self.mread(v, bb)?[..bpg]);
            self.groups[g].bb_csum = c;
        }
        if flags & BG_INODE_UNINIT == 0 {
            let c = crc32c(s, &self.mread(v, ib)?[..ipg]);
            self.groups[g].ib_csum = c;
        }
        Ok(())
    }

    /// A directory block's checksum into its tail (if it has one).
    pub(crate) fn seal_dir(&mut self, v: &mut Vol, b: u64, seed: u32) -> R<()> {
        if self.csum.is_none() {
            return Ok(());
        }
        let blk = self.mmod(v, b)?;
        if has_dir_tail(blk) {
            let c = crc32c(seed, &blk[..BLOCK - DIR_TAIL]);
            put32(blk, BLOCK - 4, c);
        }
        Ok(())
    }

    /// An extended attribute block's checksum (after its reference count changed).
    pub(crate) fn seal_xattr(&mut self, v: &mut Vol, b: u64) -> R<()> {
        let Some(s) = self.csum else { return Ok(()) };
        let blk = self.mmod(v, b)?;
        put32(blk, 0x10, 0);
        let c = crc32c(crc32c(s, &b.to_le_bytes()), blk);
        put32(blk, 0x10, c);
        Ok(())
    }

    /// Group `g`'s bitmaps on the disk before they are used: those mke2fs
    /// left uninitialised are worked out (what the group holds of the file
    /// system's own blocks) and written.
    pub(crate) fn init_group(&mut self, g: usize) -> R<()> {
        let flags = self.groups[g].flags;
        if flags & BG_BLOCK_UNINIT != 0 {
            let first = self.group_first_block(g);
            let len = (self.blocks - first).min(self.blocks_per_group as u64);
            let mut bm = vec![0u8; BLOCK];
            let mut set = |b: u64| {
                if b >= first && b < first + len {
                    let k = (b - first) as usize;
                    bm[k / 8] |= 1 << (k % 8);
                }
            };
            if has_super(g as u32) || le32(&self.sb, 0x64) & crate::RO_SPARSE_SUPER == 0 {
                let gdt = (self.groups.len() * self.desc_size).div_ceil(BLOCK) as u64;
                let reserved = le16(&self.sb, 0xCE) as u64;
                for b in first..first + 1 + gdt + reserved {
                    set(b);
                }
            }
            let itable = (self.inodes_per_group as u64 * self.inode_size as u64).div_ceil(BLOCK as u64);
            for gr in &self.groups {
                set(gr.block_bitmap);
                set(gr.inode_bitmap);
                for b in gr.inode_table..gr.inode_table + itable {
                    set(b);
                }
            }
            for k in len as usize..BLOCK * 8 {
                bm[k / 8] |= 1 << (k % 8);
            }
            let free = (0..len as usize).filter(|&k| bm[k / 8] & (1 << (k % 8)) == 0).count() as u32;
            if free != self.groups[g].free_blocks {
                return Err(Error::Corrupt("an uninitialised block group does not add up"));
            }
            self.mzero(self.groups[g].block_bitmap).copy_from_slice(&bm);
            self.groups[g].flags &= !BG_BLOCK_UNINIT;
            self.bitmaps_changed(g);
        }
        if flags & BG_INODE_UNINIT != 0 {
            let ipg = self.inodes_per_group as usize;
            let bm = self.mzero(self.groups[g].inode_bitmap);
            for k in ipg..BLOCK * 8 {
                bm[k / 8] |= 1 << (k % 8);
            }
            self.groups[g].flags &= !BG_INODE_UNINIT;
            self.bitmaps_changed(g);
        }
        Ok(())
    }

    /// Group `g`'s bitmaps changed: its checksums and descriptor go out at sync.
    pub(crate) fn bitmaps_changed(&mut self, g: usize) {
        self.csum_groups.insert(g);
        self.meta_dirty = true;
    }

    /// An inode taken from group `g` at `index`: beyond what the group counted
    /// as used of its inode table, the count follows.
    pub(crate) fn note_itable_use(&mut self, g: usize, index: u32) {
        let gr = &mut self.groups[g];
        let ipg = self.inodes_per_group;
        if gr.itable_unused > 0 && index >= ipg - gr.itable_unused {
            gr.itable_unused = ipg - index - 1;
        }
    }

    /// Linux's list of inodes being deleted or truncated when it stopped:
    /// finished here (the last link gone: released; else cut to its size).
    pub(crate) fn process_orphans(&mut self, v: &mut Vol, now: u32) -> R<()> {
        let mut ino = le32(&self.sb, 0xE8);
        let mut n = 0;
        while ino != 0 && n < 100_000 {
            let mut i = self.read_inode(v, ino)?;
            let next = le32(&i.raw, 0x14);
            if i.links() == 0 {
                self.release(v, ino, now)?;
            } else {
                if i.kind() == Some(crate::Kind::File) {
                    let size = i.size();
                    self.set_len(v, &mut i, size)?;
                }
                put32(&mut i.raw, 0x14, 0);
                self.write_inode(v, &i)?;
            }
            ino = next;
            n += 1;
        }
        if le32(&self.sb, 0xE8) != 0 {
            put32(&mut self.sb, 0xE8, 0);
            self.meta_dirty = true;
        }
        Ok(())
    }
}
