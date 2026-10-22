//! Directories: entries listed one after another in the directory's blocks
//! (a hash index Linux made is read past, and dropped when it changes).

use alloc::string::String;
use alloc::vec::Vec;

use crate::csum::{DIR_TAIL, has_dir_tail, put_dir_tail};
use crate::extent::Ext;
use crate::{BLOCK, EXT4_INDEX_FL, Error, Fs, Inode, Kind, R, Vol, le16, le32, put16, put32};

/// Write a directory entry at the start of `b`; returns `rec_len`.
fn dirent(b: &mut [u8], ino: u32, name: &str, ft: u8, rec_len: usize) -> usize {
    put32(b, 0, ino);
    put16(b, 4, rec_len as u16);
    b[6] = name.len() as u8;
    b[7] = ft;
    b[8..8 + name.len()].copy_from_slice(name.as_bytes());
    for x in &mut b[8 + name.len()..(8 + name.len()).next_multiple_of(4).min(rec_len)] {
        *x = 0;
    }
    rec_len
}

/// Where a directory block's entries end (its checksum tail after).
fn entries_end(blk: &[u8]) -> usize {
    if has_dir_tail(blk) { BLOCK - DIR_TAIL } else { BLOCK }
}

/// The entries of a directory block: (offset, inode, rec_len, type, name).
fn parse(blk: &[u8]) -> R<Vec<(usize, u32, usize, u8, &[u8])>> {
    let mut out = Vec::new();
    let end = entries_end(blk);
    let mut at = 0;
    while at + 8 <= end {
        let ino = le32(blk, at);
        let rec = le16(blk, at + 4) as usize;
        let nl = blk[at + 6] as usize;
        if rec < 8 || at + rec > end || 8 + nl > rec {
            return Err(Error::Corrupt("bad directory entry"));
        }
        out.push((at, ino, rec, blk[at + 7], &blk[at + 8..at + 8 + nl]));
        at += rec;
    }
    Ok(out)
}

impl Fs {
    /// The directory's blocks (physical), in order.
    fn dir_blocks(&mut self, v: &mut Vol, dir: &Inode) -> R<Vec<u64>> {
        let size_blocks = dir.size() / BLOCK as u64;
        let mut out = Vec::new();
        for e in self.runs(v, dir)? {
            for lb in e.l as u64..e.end().min(size_blocks) {
                if !e.uninit {
                    out.push(e.at(lb));
                }
            }
        }
        Ok(out)
    }

    /// (inode, file type, name) of a directory's entries, "." and ".." too.
    pub(crate) fn entries(&mut self, v: &mut Vol, dir: &Inode) -> R<Vec<(u32, u8, String)>> {
        let mut out = Vec::new();
        for b in self.dir_blocks(v, dir)? {
            let blk = self.mread(v, b)?;
            for (_, ino, _, ft, name) in parse(blk)? {
                if ino != 0 && !name.is_empty() {
                    out.push((ino, ft, String::from_utf8_lossy(name).into_owned()));
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn find(&mut self, v: &mut Vol, dir: &Inode, name: &str) -> R<Option<(u32, u8)>> {
        for b in self.dir_blocks(v, dir)? {
            let blk = self.mread(v, b)?;
            if let Some(e) = parse(blk)?.into_iter().find(|e| e.1 != 0 && e.4 == name.as_bytes()) {
                return Ok(Some((e.1, e.3)));
            }
        }
        Ok(None)
    }

    /// Nothing in it but "." and "..".
    pub(crate) fn dir_empty(&mut self, v: &mut Vol, dir: &Inode) -> R<bool> {
        Ok(self.entries(v, dir)?.iter().all(|e| e.2 == "." || e.2 == ".."))
    }

    /// The inode of directory `ino`.
    pub(crate) fn dir_inode(&mut self, v: &mut Vol, ino: u32) -> R<Inode> {
        let d = self.read_inode(v, ino)?;
        if !d.is_dir() {
            return Err(Error::NotADirectory);
        }
        Ok(d)
    }

    /// A new directory's first block, with "." and ".."; two links.
    pub(crate) fn init_dir(&mut self, v: &mut Vol, i: &mut Inode, parent: u32) -> R<()> {
        let goal = self.group_first_block(self.group_of_ino(i.ino));
        let (_, b) = self.alloc_blocks(v, 1, goal)?;
        let end = self.new_dir_end();
        let d = self.mzero(b);
        let at = dirent(d, i.ino, ".", Kind::Dir.ft(), 12);
        dirent(&mut d[at..], parent, "..", Kind::Dir.ft(), end - at);
        if end < BLOCK {
            put_dir_tail(d);
        }
        let seed = self.seed_of(i);
        self.seal_dir(v, b, seed)?;
        if let Err(e) = self.set_runs(v, i, &[Ext { l: 0, p: b, n: 1, uninit: false }]) {
            self.free_blocks(v, b, 1)?;
            return Err(e);
        }
        i.set_size(BLOCK as u64);
        i.set_links(2);
        Ok(())
    }

    /// Where entries end in the directory blocks made here.
    fn new_dir_end(&self) -> usize {
        if self.csum.is_some() { BLOCK - DIR_TAIL } else { BLOCK }
    }

    /// A directory about to change: an index it has would go stale, so it
    /// becomes a plain one. Its blocks read right as such, except with
    /// checksums: then the index blocks become empty blocks with a tail.
    fn unindex(&mut self, v: &mut Vol, dir: &mut Inode) -> R<()> {
        let fl = dir.flags();
        if fl & EXT4_INDEX_FL == 0 {
            return Ok(());
        }
        dir.set_flags(fl & !EXT4_INDEX_FL);
        if self.csum.is_none() {
            return Ok(());
        }
        let seed = self.seed_of(dir);
        for (k, b) in self.dir_blocks(v, dir)?.into_iter().enumerate() {
            let blk = self.mread(v, b)?;
            if has_dir_tail(blk) {
                continue;
            }
            let blk = self.mmod(v, b)?;
            if k == 0 {
                // the root: "." and "..", the index after them in ".."'s room
                if le16(blk, 4) != 12 || le32(blk, 12) == 0 {
                    return Err(Error::Corrupt("bad hash index root"));
                }
                put16(blk, 16, (BLOCK - DIR_TAIL - 12) as u16);
                blk[24..BLOCK - DIR_TAIL].fill(0);
            } else if le32(blk, 0) == 0 && le16(blk, 4) as usize == BLOCK {
                // an index node: one empty entry over the block
                blk.fill(0);
                put16(blk, 4, (BLOCK - DIR_TAIL) as u16);
            } else {
                return Err(Error::Corrupt("a directory block without a checksum tail"));
            }
            put_dir_tail(blk);
            self.seal_dir(v, b, seed)?;
        }
        Ok(())
    }

    /// Put an entry into directory `dir` (a new block if no room).
    pub(crate) fn dir_add(&mut self, v: &mut Vol, dir: u32, ino: u32, name: &str, kind: Kind, now: u32) -> R<()> {
        let mut d = self.dir_inode(v, dir)?;
        self.unindex(v, &mut d)?;
        let seed = self.seed_of(&d);
        let need = (8 + name.len()).next_multiple_of(4);
        for b in self.dir_blocks(v, &d)? {
            let blk = self.mread(v, b)?;
            let slot = parse(blk)?.into_iter().find_map(|(at, e_ino, rec, _, nm)| {
                let used = if e_ino == 0 { 0 } else { (8 + nm.len()).next_multiple_of(4) };
                (rec - used >= need).then_some((at, e_ino, rec, used))
            });
            if let Some((at, e_ino, rec, used)) = slot {
                let blk = self.mmod(v, b)?;
                if e_ino == 0 {
                    dirent(&mut blk[at..], ino, name, kind.ft(), rec);
                } else {
                    put16(blk, at + 4, used as u16);
                    dirent(&mut blk[at + used..], ino, name, kind.ft(), rec - used);
                }
                self.seal_dir(v, b, seed)?;
                d.touch(now);
                return self.write_inode(v, &d);
            }
        }
        // a new block at the end
        let mut runs = self.runs(v, &d)?;
        let goal = runs.last().map_or_else(|| self.group_first_block(self.group_of_ino(dir)), |e| e.p + e.n as u64);
        let (_, b) = self.alloc_blocks(v, 1, goal)?;
        let next = (d.size() / BLOCK as u64) as u32;
        runs.push(Ext { l: next, p: b, n: 1, uninit: false });
        if let Err(e) = self.set_runs(v, &mut d, &runs) {
            self.free_blocks(v, b, 1)?;
            return Err(e);
        }
        let end = self.new_dir_end();
        let blk = self.mzero(b);
        dirent(blk, ino, name, kind.ft(), end);
        if end < BLOCK {
            put_dir_tail(blk);
        }
        self.seal_dir(v, b, seed)?;
        d.set_size(d.size() + BLOCK as u64);
        d.touch(now);
        self.write_inode(v, &d)
    }

    /// Take an entry out of directory `dir`.
    pub(crate) fn dir_remove(&mut self, v: &mut Vol, dir: u32, name: &str, now: u32) -> R<()> {
        let mut d = self.dir_inode(v, dir)?;
        self.unindex(v, &mut d)?;
        let seed = self.seed_of(&d);
        for b in self.dir_blocks(v, &d)? {
            let blk = self.mread(v, b)?;
            let es = parse(blk)?;
            let Some(k) = es.iter().position(|e| e.1 != 0 && e.4 == name.as_bytes()) else { continue };
            let (at, rec) = (es[k].0, es[k].2);
            let prev = k.checked_sub(1).map(|p| (es[p].0, es[p].2));
            let blk = self.mmod(v, b)?;
            match prev {
                Some((p, prec)) => put16(blk, p + 4, (prec + rec) as u16),
                None => put32(blk, at, 0), // first in its block: emptied, kept
            }
            self.seal_dir(v, b, seed)?;
            d.touch(now);
            return self.write_inode(v, &d);
        }
        Err(Error::NotFound)
    }

    /// Point an existing entry of `dir` at another inode.
    pub(crate) fn dir_retarget(&mut self, v: &mut Vol, dir: u32, name: &str, ino: u32, kind: Kind, now: u32) -> R<()> {
        let mut d = self.dir_inode(v, dir)?;
        self.unindex(v, &mut d)?;
        let seed = self.seed_of(&d);
        for b in self.dir_blocks(v, &d)? {
            let blk = self.mread(v, b)?;
            let Some(at) = parse(blk)?.into_iter().find(|e| e.1 != 0 && e.4 == name.as_bytes()).map(|e| e.0) else { continue };
            let blk = self.mmod(v, b)?;
            put32(blk, at, ino);
            blk[at + 7] = kind.ft();
            self.seal_dir(v, b, seed)?;
            d.touch(now);
            return self.write_inode(v, &d);
        }
        Err(Error::NotFound)
    }
}
