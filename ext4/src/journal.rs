//! The journal (jbd2, as Linux keeps it): every sync is one transaction.
//! The changed metadata blocks go to the log first, then a commit block;
//! only then to their places, after which the log is marked empty again.
//! Power lost half way: the next mount (ours or Linux's) replays what was
//! committed, and drops what was not. File data is written before the
//! commit ("ordered").
//!
//! What it writes: tags without checksums, 32-bit block numbers. What it
//! replays: also Linux's logs (64-bit tags, checksummed tags, revoke records).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::extent::Ext;
use crate::{BLOCK, Error, Fs, Kind, R, Vol, le32, put32};

const MAGIC: u32 = 0xC03B_3998;
const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V1: u32 = 3;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

const INCOMPAT_REVOKE: u32 = 0x1;
const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_ASYNC_COMMIT: u32 = 0x4;
const INCOMPAT_CSUM_V2: u32 = 0x8;
const INCOMPAT_CSUM_V3: u32 = 0x10;
/// What a log may use and still be replayed here.
const INCOMPAT_KNOWN: u32 = INCOMPAT_REVOKE | INCOMPAT_64BIT | INCOMPAT_ASYNC_COMMIT | INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3;

const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

/// The journal's inode.
pub(crate) const JOURNAL_INO: u32 = 8;
/// Tags in one of our descriptor blocks (8 bytes each; the first one has the UUID after it).
const TAGS_PER_DESCRIPTOR: usize = (BLOCK - 12 - 16) / 8;

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn put_be32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}

/// CRC-32C (Castagnoli), without the final inversion (as jbd2 and ext4 use it).
pub(crate) fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &x in data {
        crc ^= x as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0x82F6_3B78 } else { crc >> 1 };
        }
    }
    crc
}

/// How big a journal mke2fs gives a file system of `blocks` (None: too small for one).
pub(crate) fn default_size(blocks: u64) -> Option<u32> {
    Some(match blocks {
        0..2048 => return None,
        2048..32768 => 1024,
        32768..262_144 => 4096,
        262_144..524_288 => 8192,
        524_288..4_194_304 => 16384,
        4_194_304..8_388_608 => 32768,
        8_388_608..16_777_216 => 65536,
        16_777_216..33_554_432 => 131_072,
        _ => 262_144,
    })
}

pub(crate) struct Journal {
    /// where the journal's blocks are
    map: Vec<Ext>,
    /// its superblock (block 0 of the journal)
    sb: Vec<u8>,
    len: u32,
    first: u32,
    /// the next transaction's number
    tid: u32,
    /// it can take our transactions (else it is only replayed)
    usable: bool,
}

impl Journal {
    pub(crate) fn len(&self) -> u32 {
        self.len
    }

    /// The disk block of journal block `n`.
    fn block(&self, n: u32) -> R<u64> {
        self.map
            .iter()
            .find(|e| n >= e.l && (n as u64) < e.end())
            .map(|e| e.at(n as u64))
            .ok_or(Error::Corrupt("journal block not mapped"))
    }

    /// Journal blocks `from..from + data.len() / BLOCK` written (in as few requests as they allow).
    fn write(&self, v: &mut Vol, from: u32, data: &[u8]) -> R<()> {
        let n = (data.len() / BLOCK) as u32;
        let mut k = 0;
        while k < n {
            let p = self.block(from + k)?;
            let mut run = 1;
            while k + run < n && run < 64 && self.block(from + k + run)? == p + run as u64 {
                run += 1;
            }
            v.write(p, &data[k as usize * BLOCK..(k + run) as usize * BLOCK])?;
            k += run;
        }
        Ok(())
    }

    fn incompat(&self) -> u32 {
        be32(&self.sb, 0x28)
    }

    /// The log starting at `start` (0: empty) with transaction `tid` first.
    fn write_sb(&mut self, v: &mut Vol, start: u32, tid: u32) -> R<()> {
        put_be32(&mut self.sb, 0x18, tid);
        put_be32(&mut self.sb, 0x1C, start);
        if self.incompat() & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) != 0 {
            put_be32(&mut self.sb, 0xFC, 0);
            let c = crc32c(!0, &self.sb[..1024]);
            put_be32(&mut self.sb, 0xFC, c);
        }
        let p = self.block(0)?;
        v.write(p, &self.sb)
    }
}

impl Fs {
    /// A journal for a new file system (inode 8, zeroed, its superblock written).
    pub(crate) fn make_journal(&mut self, v: &mut Vol, uuid: &[u8], now: u32) -> R<()> {
        if let Some((j, i)) = self.build_journal(v, uuid, now)? {
            self.note_journal(&i);
            self.journal = Some(j);
        }
        Ok(())
    }

    /// A journal for a file system that has none (as `tune2fs -j` adds
    /// one): true if it got one. Its blocks and inode reach the disk before
    /// the superblock names it.
    pub fn add_journal(&mut self, v: &mut Vol, now: u32) -> R<bool> {
        if !self.writable || self.journal.is_some() || le32(&self.sb, 0x5C) & crate::COMPAT_HAS_JOURNAL != 0 {
            return Ok(false);
        }
        if self.read_inode(v, JOURNAL_INO)?.mode() != 0 {
            return Ok(false); // inode 8 is not free
        }
        match default_size(self.blocks) {
            // and room to spare after it
            Some(len) if self.usage().1 / BLOCK as u64 > 2 * len as u64 => {}
            _ => return Ok(false),
        }
        let uuid = self.sb[0x68..0x78].to_vec();
        let Some((j, i)) = self.build_journal(v, &uuid, now)? else { return Ok(false) };
        self.sync(v)?;
        self.note_journal(&i);
        self.sync(v)?; // the superblock alone: one block
        self.journal = Some(j);
        self.set_recover(v, true)?;
        Ok(true)
    }

    pub fn has_journal(&self) -> bool {
        self.journal.is_some()
    }

    /// Inode 8 with the journal's blocks, zeroed, its superblock written.
    fn build_journal(&mut self, v: &mut Vol, uuid: &[u8], now: u32) -> R<Option<(Journal, crate::Inode)>> {
        let Some(len) = default_size(self.blocks) else { return Ok(None) };
        // in the middle of the file system, as mke2fs puts it
        let goal = self.group_first_block(self.groups.len() / 2);
        let mut map = Vec::new();
        let mut got = 0u32;
        while got < len {
            let (n, p) = match self.alloc_blocks(v, len - got, goal) {
                Ok(x) => x,
                Err(e) => {
                    for x in &map {
                        let x: &Ext = x;
                        self.free_blocks(v, x.p, x.n as u64)?;
                    }
                    return Err(e);
                }
            };
            map.push(Ext { l: got, p, n, uninit: false });
            got += n;
        }
        let mut i = self.blank_inode(JOURNAL_INO, Kind::File, 0o600, 0, 0, now);
        i.set_links(1);
        self.set_runs(v, &mut i, &map)?;
        i.set_size(len as u64 * BLOCK as u64);
        self.write_inode(v, &i)?;
        let zero = vec![0u8; 64 * BLOCK];
        for e in &map {
            let mut k = 0;
            while k < e.n {
                let n = (e.n - k).min(64);
                v.write(e.p + k as u64, &zero[..n as usize * BLOCK])?;
                k += n;
            }
        }
        let mut sb = vec![0u8; BLOCK];
        put_be32(&mut sb, 0, MAGIC);
        put_be32(&mut sb, 4, SUPERBLOCK_V2);
        put_be32(&mut sb, 0x0C, BLOCK as u32);
        put_be32(&mut sb, 0x10, len);
        put_be32(&mut sb, 0x14, 1); // the log starts after this block
        put_be32(&mut sb, 0x18, 1);
        sb[0x30..0x40].copy_from_slice(uuid);
        put_be32(&mut sb, 0x40, 1); // users
        sb[0x100..0x110].copy_from_slice(uuid);
        let mut j = Journal { map, sb, len, first: 1, tid: 1, usable: true };
        j.write_sb(v, 0, 1)?;
        Ok(Some((j, i)))
    }

    /// The ext4 superblock: has_journal, inode 8, and a copy of its block map.
    fn note_journal(&mut self, i: &crate::Inode) {
        let fs_sb = &mut self.sb;
        let c = le32(fs_sb, 0x5C) | crate::COMPAT_HAS_JOURNAL;
        put32(fs_sb, 0x5C, c);
        put32(fs_sb, 0xE0, JOURNAL_INO);
        fs_sb[0xFD] = 1; // the copy below is of i_block
        fs_sb[0x10C..0x10C + 60].copy_from_slice(&i.raw[0x28..0x28 + 60]);
        put32(fs_sb, 0x10C + 60, (i.size() >> 32) as u32);
        put32(fs_sb, 0x10C + 64, i.size() as u32);
        self.meta_dirty = true;
    }

    /// The journal at mount: read, and replayed if it holds anything.
    /// `on_disk`: replayed blocks are written in place (else only cached).
    pub(crate) fn open_journal(&mut self, v: &mut Vol, on_disk: bool) -> R<()> {
        let ino = le32(&self.sb, 0xE0);
        let i = self.read_inode(v, ino)?;
        let map = self.runs(v, &i)?;
        let p0 = map.first().filter(|e| e.l == 0).ok_or(Error::Corrupt("journal block 0 not mapped"))?.p;
        let sb = v.block(p0)?;
        let kind = be32(&sb, 4);
        if be32(&sb, 0) != MAGIC || !(kind == SUPERBLOCK_V1 || kind == SUPERBLOCK_V2) || be32(&sb, 0x0C) != BLOCK as u32 {
            return Err(Error::Corrupt("bad journal superblock"));
        }
        let incompat = if kind == SUPERBLOCK_V2 { be32(&sb, 0x28) } else { 0 };
        let mut j = Journal { map, len: be32(&sb, 0x10), first: be32(&sb, 0x14), tid: be32(&sb, 0x18), usable: incompat & !INCOMPAT_KNOWN == 0, sb };
        if j.first == 0 || j.first >= j.len {
            return Err(Error::Corrupt("bad journal superblock"));
        }
        if !j.usable {
            // a log we cannot read (fast commits ...): leave it, and the file system, alone
            self.writable = false;
            self.journal = Some(j);
            return Ok(());
        }
        let start = be32(&j.sb, 0x1C);
        let mine = on_disk && self.writable;
        if start != 0 {
            let (blocks, next) = self.scan(v, &j, start)?;
            if mine {
                for (b, data) in &blocks {
                    v.write(*b, data)?;
                }
                // what was read before (the journal's inode) may be older than the log
                self.cache = crate::cache::Cache::default();
            } else {
                self.writable = false;
                for (b, data) in blocks {
                    self.pin(b, data);
                }
            }
            j.tid = next;
        }
        if mine {
            // from now on, logs as we write them (no checksums, 32-bit tags);
            // Linux sets its own features again when it mounts
            if start != 0 || j.incompat() & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3 | INCOMPAT_64BIT) != 0 {
                if kind == SUPERBLOCK_V2 {
                    for o in [0x24, 0x28, 0x2C, 0xFC] {
                        put_be32(&mut j.sb, o, 0);
                    }
                }
                let tid = j.tid;
                j.write_sb(v, 0, tid)?;
            }
            j.usable = true;
        } else {
            j.usable = false;
        }
        self.journal = Some(j);
        Ok(())
    }

    /// The committed transactions of the log from `start`: the blocks to
    /// write (the latest copy of each, revoked ones left out), and the
    /// number of the transaction after them.
    fn scan(&mut self, v: &mut Vol, j: &Journal, start: u32) -> R<(BTreeMap<u64, Vec<u8>>, u32)> {
        let incompat = j.incompat();
        let csum3 = incompat & INCOMPAT_CSUM_V3 != 0;
        let csum2 = incompat & INCOMPAT_CSUM_V2 != 0;
        let bit64 = incompat & INCOMPAT_64BIT != 0;
        let tag_size = if csum3 { 16 } else { 8 + if csum2 { 2 } else { 0 } + if bit64 { 4 } else { 0 } };
        let tail = if csum2 || csum3 { 4 } else { 0 };
        let next = |n: u32| if n + 1 >= j.len { j.first } else { n + 1 };

        // (transaction, block, journal block, escaped) of committed transactions
        let mut done: Vec<(u32, u64, u32, bool)> = Vec::new();
        let mut revoked: BTreeMap<u64, u32> = BTreeMap::new();
        let mut cur: Vec<(u64, u32, bool)> = Vec::new();
        let mut cur_revoked: Vec<u64> = Vec::new();
        let (mut pos, mut tid) = (start, j.tid);
        for _ in 0..j.len {
            let blk = v.block(j.block(pos)?)?;
            if be32(&blk, 0) != MAGIC || be32(&blk, 8) != tid {
                break;
            }
            match be32(&blk, 4) {
                DESCRIPTOR => {
                    let mut at = 12;
                    pos = next(pos);
                    while at + tag_size <= BLOCK - tail {
                        let (lo, flags, hi) = if csum3 { (be32(&blk, at), be32(&blk, at + 4), be32(&blk, at + 8)) } else { (be32(&blk, at), u16::from_be_bytes([blk[at + 6], blk[at + 7]]) as u32, if bit64 { be32(&blk, at + 8) } else { 0 }) };
                        at += tag_size;
                        if flags & TAG_SAME_UUID == 0 {
                            at += 16;
                        }
                        let b = lo as u64 | if bit64 { (hi as u64) << 32 } else { 0 };
                        cur.push((b, pos, flags & TAG_ESCAPE != 0));
                        pos = next(pos);
                        if flags & TAG_LAST != 0 {
                            break;
                        }
                    }
                }
                COMMIT => {
                    for (b, jb, esc) in cur.drain(..) {
                        done.push((tid, b, jb, esc));
                    }
                    for b in cur_revoked.drain(..) {
                        revoked.insert(b, tid);
                    }
                    tid = tid.wrapping_add(1);
                    pos = next(pos);
                }
                REVOKE => {
                    let used = (be32(&blk, 12) as usize).min(BLOCK - tail);
                    let rec = if bit64 { 8 } else { 4 };
                    let mut at = 16;
                    while at + rec <= used {
                        cur_revoked.push(if bit64 { (be32(&blk, at) as u64) << 32 | be32(&blk, at + 4) as u64 } else { be32(&blk, at) as u64 });
                        at += rec;
                    }
                    pos = next(pos);
                }
                _ => break,
            }
        }
        let mut out = BTreeMap::new();
        for (t, b, jb, esc) in done {
            // revoked by this transaction or a later one: not replayed
            if revoked.get(&b).is_some_and(|&r| r.wrapping_sub(t) as i32 >= 0) {
                continue;
            }
            if b >= self.blocks {
                return Err(Error::Corrupt("journal names a block past the end"));
            }
            let mut data = v.block(j.block(jb)?)?;
            if esc {
                put_be32(&mut data, 0, MAGIC);
            }
            out.insert(b, data);
        }
        Ok((out, tid))
    }

    /// The blocks to their places through the journal: logged and committed
    /// first, so that they all arrive or none (in parts if the log is too
    /// small for all of them at once). False if there is no journal to use.
    pub(crate) fn commit(&mut self, v: &mut Vol, dirty: &[u64]) -> R<bool> {
        let Some(mut j) = self.journal.take().filter(|j| j.usable) else { return Ok(false) };
        let r = self.commit_in(v, &mut j, dirty);
        self.journal = Some(j);
        r.map(|_| true)
    }

    fn commit_in(&mut self, v: &mut Vol, j: &mut Journal, dirty: &[u64]) -> R<()> {
        let room = (j.len - j.first - 1) as usize; // blocks for descriptors and copies, less the commit block
        let per = room / (TAGS_PER_DESCRIPTOR + 1) * TAGS_PER_DESCRIPTOR + (room % (TAGS_PER_DESCRIPTOR + 1)).saturating_sub(1);
        let uuid = self.sb[0x68..0x78].to_vec();
        for part in dirty.chunks(per.max(1)) {
            let tid = j.tid;
            let mut log = Vec::with_capacity((part.len() + part.len().div_ceil(TAGS_PER_DESCRIPTOR)) * BLOCK);
            for group in part.chunks(TAGS_PER_DESCRIPTOR) {
                let mut d = vec![0u8; BLOCK];
                put_be32(&mut d, 0, MAGIC);
                put_be32(&mut d, 4, DESCRIPTOR);
                put_be32(&mut d, 8, tid);
                let mut at = 12;
                let mut copies = Vec::with_capacity(group.len() * BLOCK);
                for (k, &b) in group.iter().enumerate() {
                    let mut data = self.cached(b).to_vec();
                    let mut flags = 0;
                    if be32(&data, 0) == MAGIC {
                        put_be32(&mut data, 0, 0);
                        flags |= TAG_ESCAPE;
                    }
                    if k > 0 {
                        flags |= TAG_SAME_UUID;
                    }
                    if k + 1 == group.len() {
                        flags |= TAG_LAST;
                    }
                    put_be32(&mut d, at, b as u32);
                    d[at + 6..at + 8].copy_from_slice(&(flags as u16).to_be_bytes());
                    at += 8;
                    if k == 0 {
                        d[at..at + 16].copy_from_slice(&uuid);
                        at += 16;
                    }
                    copies.extend_from_slice(&data);
                }
                log.extend_from_slice(&d);
                log.extend_from_slice(&copies);
            }
            j.write(v, j.first, &log)?;
            let mut c = vec![0u8; BLOCK];
            put_be32(&mut c, 0, MAGIC);
            put_be32(&mut c, 4, COMMIT);
            put_be32(&mut c, 8, tid);
            j.write(v, j.first + (log.len() / BLOCK) as u32, &c)?;
            // committed: from here a replay brings it all
            j.write_sb(v, j.first, tid)?;
            self.write_home(v, part)?;
            j.tid = tid.wrapping_add(1);
            j.write_sb(v, 0, j.tid)?;
        }
        Ok(())
    }
}
