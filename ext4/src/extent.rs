//! Extent trees: where a file's blocks are, as runs (logical block,
//! physical block, count), in the inode (up to four) or in a tree of index
//! and leaf blocks of any depth below it.

use alloc::vec;
use alloc::vec::Vec;

use crate::{BLOCK, Error, Fs, Inode, Kind, R, Vol, le16, le32, put16, put32};

/// The longest run an extent holds (one that is allocated but unwritten: one less).
pub(crate) const INIT_MAX: u32 = 32768;
pub(crate) const UNINIT_MAX: u32 = 32767;
const MAGIC: u16 = 0xF30A;
/// Entries in a tree block, and in the inode.
const PER_BLOCK: usize = (BLOCK - 12) / 12;
const IN_INODE: usize = 4;

/// A run of a file's blocks.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Ext {
    /// first logical block
    pub l: u32,
    /// first physical block
    pub p: u64,
    pub n: u32,
    /// allocated but not written: reads as zeros
    pub uninit: bool,
}

impl Ext {
    pub fn end(&self) -> u64 {
        self.l as u64 + self.n as u64
    }
    /// The physical block of logical block `lb` (inside the run).
    pub fn at(&self, lb: u64) -> u64 {
        self.p + (lb - self.l as u64)
    }
}

fn header(b: &mut [u8], entries: usize, max: usize, depth: u16) {
    put16(b, 0, MAGIC);
    put16(b, 2, entries as u16);
    put16(b, 4, max as u16);
    put16(b, 6, depth);
    put32(b, 8, 0);
}

/// An inode's tree with nothing in it.
pub(crate) fn empty_root(i: &mut Inode) {
    let root = &mut i.raw[0x28..0x28 + 60];
    root.fill(0);
    header(root, 0, IN_INODE, 0);
}

fn leaf_entry(e: &Ext) -> [u8; 12] {
    let mut b = [0u8; 12];
    put32(&mut b, 0, e.l);
    put16(&mut b, 4, (e.n + if e.uninit { INIT_MAX } else { 0 }) as u16);
    put16(&mut b, 6, (e.p >> 32) as u16);
    put32(&mut b, 8, e.p as u32);
    b
}

fn index_entry(first: u32, block: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    put32(&mut b, 0, first);
    put32(&mut b, 4, block as u32);
    put16(&mut b, 8, (block >> 32) as u16);
    b
}

/// Sorted, without empty runs, neighbours joined.
fn normalize(exts: &[Ext]) -> Vec<Ext> {
    let mut v: Vec<Ext> = exts.iter().copied().filter(|e| e.n > 0).collect();
    v.sort_by_key(|e| e.l);
    let mut out: Vec<Ext> = Vec::with_capacity(v.len());
    for e in v {
        if let Some(last) = out.last_mut() {
            let max = if e.uninit { UNINIT_MAX } else { INIT_MAX };
            if last.end() == e.l as u64 && last.p + last.n as u64 == e.p && last.uninit == e.uninit && last.n + e.n <= max {
                last.n += e.n;
                continue;
            }
        }
        out.push(e);
    }
    out
}

impl Fs {
    /// The file's runs, in logical order.
    pub(crate) fn runs(&mut self, v: &mut Vol, i: &Inode) -> R<Vec<Ext>> {
        if !i.has_extents() {
            let special = matches!(i.kind(), Some(Kind::CharDev | Kind::BlockDev | Kind::Fifo | Kind::Socket));
            if i.fast_symlink() || special || i.size() == 0 {
                return Ok(Vec::new());
            }
            return Err(Error::Corrupt("a file without extents (old block maps are not supported)"));
        }
        let root = i.raw[0x28..0x28 + 60].to_vec();
        let mut out = Vec::new();
        self.walk(v, &root, &mut out, None, 0)?;
        Ok(out)
    }

    /// The runs below a node (`tree`: collect the tree's own blocks instead).
    fn walk(&mut self, v: &mut Vol, node: &[u8], out: &mut Vec<Ext>, mut tree: Option<&mut Vec<u64>>, level: u32) -> R<()> {
        let entries = le16(node, 2) as usize;
        if le16(node, 0) != MAGIC || level > 5 || 12 + entries * 12 > node.len() {
            return Err(Error::Corrupt("bad extent header"));
        }
        let depth = le16(node, 6);
        for k in 0..entries {
            let e = &node[12 + k * 12..24 + k * 12];
            if depth == 0 {
                if tree.is_some() {
                    return Ok(());
                }
                let raw = le16(e, 4) as u32;
                let (n, uninit) = if raw > INIT_MAX { (raw - INIT_MAX, true) } else { (raw, false) };
                out.push(Ext { l: le32(e, 0), p: (le16(e, 6) as u64) << 32 | le32(e, 8) as u64, n, uninit });
            } else {
                let child = (le16(e, 8) as u64) << 32 | le32(e, 4) as u64;
                if let Some(t) = tree.as_deref_mut() {
                    t.push(child);
                }
                let blk = self.mread(v, child)?.to_vec();
                self.walk(v, &blk, out, tree.as_deref_mut(), level + 1)?;
            }
        }
        Ok(())
    }

    /// Blocks of the extent tree itself (index and leaf blocks).
    pub(crate) fn tree_blocks(&mut self, v: &mut Vol, i: &Inode) -> R<Vec<u64>> {
        let mut out = Vec::new();
        if i.has_extents() {
            let root = i.raw[0x28..0x28 + 60].to_vec();
            self.walk(v, &root, &mut Vec::new(), Some(&mut out), 0)?;
        }
        Ok(out)
    }

    /// Map the inode to `exts` (not overlapping): the tree is written anew,
    /// in the blocks it had where it can; i_blocks follows. Nothing changes
    /// if the blocks for it cannot be had.
    pub(crate) fn set_runs(&mut self, v: &mut Vol, i: &mut Inode, exts: &[Ext]) -> R<()> {
        let exts = normalize(exts);
        let old = self.tree_blocks(v, i)?;
        // nodes per level, from the leaves up, until the inode holds the top
        let mut levels = Vec::new();
        let mut count = exts.len();
        while count > IN_INODE {
            count = count.div_ceil(PER_BLOCK);
            levels.push(count);
        }
        let need: usize = levels.iter().sum();
        let mut blocks: Vec<u64> = old.iter().copied().take(need).collect();
        let mut fresh = Vec::new();
        let goal = exts.first().map_or_else(|| self.group_first_block(self.group_of_ino(i.ino)), |e| e.p);
        while blocks.len() < need {
            match self.alloc_blocks(v, 1, goal) {
                Ok((_, b)) => {
                    blocks.push(b);
                    fresh.push(b);
                }
                Err(e) => {
                    for b in fresh {
                        self.free_blocks(v, b, 1)?;
                    }
                    return Err(e);
                }
            }
        }
        for &b in old.iter().skip(need) {
            self.free_blocks(v, b, 1)?;
        }
        let mut entries: Vec<[u8; 12]> = exts.iter().map(leaf_entry).collect();
        let mut firsts: Vec<u32> = exts.iter().map(|e| e.l).collect();
        let mut depth = 0u16;
        let mut next_block = blocks.iter();
        let mut node = vec![0u8; BLOCK];
        for _ in &levels {
            let (mut up_entries, mut up_firsts) = (Vec::new(), Vec::new());
            for (es, fs) in entries.chunks(PER_BLOCK).zip(firsts.chunks(PER_BLOCK)) {
                let b = *next_block.next().expect("counted");
                node.fill(0);
                header(&mut node, es.len(), PER_BLOCK, depth);
                for (k, e) in es.iter().enumerate() {
                    node[12 + k * 12..24 + k * 12].copy_from_slice(e);
                }
                if let Some(seed) = self.csum.map(|_| self.seed_of(i)) {
                    // the checksum tail after the entries
                    let t = 12 + 12 * PER_BLOCK;
                    let c = crate::journal::crc32c(seed, &node[..t]);
                    put32(&mut node, t, c);
                }
                if fresh.contains(&b) {
                    self.mzero(b).copy_from_slice(&node);
                } else {
                    self.mset(v, b, &node)?;
                }
                up_entries.push(index_entry(fs[0], b));
                up_firsts.push(fs[0]);
            }
            entries = up_entries;
            firsts = up_firsts;
            depth += 1;
        }
        let root = &mut i.raw[0x28..0x28 + 60];
        root.fill(0);
        header(root, entries.len(), IN_INODE, depth);
        for (k, e) in entries.iter().enumerate() {
            root[12 + k * 12..24 + k * 12].copy_from_slice(e);
        }
        let data: u64 = exts.iter().map(|e| e.n as u64).sum();
        let xattr = (i.xattr_block() != 0) as u64;
        i.set_blocks(data + need as u64 + xattr);
        Ok(())
    }
}
