//! ext4, no_std: format a partition, then create, read, replace, list and
//! remove files and directories, as Linux reads and checks them (e2fsck).
//!
//! What it makes: 4 KiB blocks, 128 MiB block groups, 256-byte inodes,
//! files and directories mapped by extents, linear directories; features
//! `extents`, `filetype`, `sparse_super`, `large_file`; no journal and no
//! checksums (so after a crash run e2fsck; a journal comes later).
//!
//! What it reads: also file systems Linux made (flex_bg, 64-bit, checksums
//! and journals are ignored when reading). It writes only to those whose
//! features it keeps up (it refuses the rest instead of damaging them).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;

pub const BLOCK: usize = 4096;
const SECTORS_PER_BLOCK: u64 = (BLOCK / 512) as u64;
const BLOCKS_PER_GROUP: u32 = 32768;
const INODES_PER_GROUP: u32 = 2048;
const INODE_SIZE: usize = 256;
const ROOT: u32 = 2;
const LOST_FOUND: u32 = 11;
const FIRST_INO: u32 = 11;
const MAGIC: u16 = 0xEF53;

// features
const COMPAT_HAS_JOURNAL: u32 = 0x4;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const RO_SPARSE_SUPER: u32 = 0x1;
const RO_LARGE_FILE: u32 = 0x2;
const RO_HUGE_FILE: u32 = 0x8;
const RO_DIR_NLINK: u32 = 0x20;
const RO_EXTRA_ISIZE: u32 = 0x40;
/// What this code keeps right when it writes.
const INCOMPAT_WRITABLE: u32 = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_FLEX_BG;
const RO_WRITABLE: u32 = RO_SPARSE_SUPER | RO_LARGE_FILE | RO_HUGE_FILE | RO_DIR_NLINK | RO_EXTRA_ISIZE;

const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const EXT4_EXTENTS_FL: u32 = 0x80000;
/// A hash-indexed directory (dir_index): read as a plain one, and made one when changed.
const EXT4_INDEX_FL: u32 = 0x1000;
const EXTENT_MAGIC: u16 = 0xF30A;
const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
/// One extent covers at most this many blocks.
const EXTENT_MAX: u32 = 32768;

#[derive(Debug, PartialEq)]
pub enum Error {
    Io,
    NotExt4,
    /// It has features this code does not keep up: read only.
    ReadOnly,
    NotFound,
    NotADirectory,
    IsADirectory,
    NotEmpty,
    Exists,
    BadName,
    Full,
    TooBig,
    Corrupt(&'static str),
}

type R<T> = Result<T, Error>;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// A partition of a block device, in 4 KiB blocks.
pub struct Vol<'a> {
    pub dev: &'a mut dyn BlockDevice,
    /// first sector of the partition
    pub start: u64,
}

impl Vol<'_> {
    fn read(&mut self, block: u64, buf: &mut [u8]) -> R<()> {
        if self.dev.read(self.start + block * SECTORS_PER_BLOCK, buf) { Ok(()) } else { Err(Error::Io) }
    }
    fn write(&mut self, block: u64, buf: &[u8]) -> R<()> {
        if self.dev.write(self.start + block * SECTORS_PER_BLOCK, buf) { Ok(()) } else { Err(Error::Io) }
    }
    fn block(&mut self, block: u64) -> R<Vec<u8>> {
        let mut b = vec![0u8; BLOCK];
        self.read(block, &mut b)?;
        Ok(b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stat {
    pub ino: u32,
    pub size: u64,
    pub dir: bool,
    pub mtime: u32,
}

#[derive(Clone, Copy, Debug)]
struct Group {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks: u32,
    free_inodes: u32,
    used_dirs: u32,
}

/// A mounted ext4.
pub struct Fs {
    sb: Vec<u8>,
    groups: Vec<Group>,
    blocks: u64,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: usize,
    desc_size: usize,
    first_data_block: u64,
    pub writable: bool,
}

/// An inode as read from its table.
#[derive(Clone)]
struct Inode {
    ino: u32,
    raw: Vec<u8>,
}

impl Inode {
    fn mode(&self) -> u16 {
        le16(&self.raw, 0)
    }
    fn is_dir(&self) -> bool {
        self.mode() & 0xF000 == S_IFDIR
    }
    fn size(&self) -> u64 {
        le32(&self.raw, 4) as u64 | (le32(&self.raw, 0x6C) as u64) << 32
    }
    fn set_size(&mut self, s: u64) {
        put32(&mut self.raw, 4, s as u32);
        put32(&mut self.raw, 0x6C, (s >> 32) as u32);
    }
    fn links(&self) -> u16 {
        le16(&self.raw, 0x1A)
    }
    fn set_links(&mut self, n: u16) {
        put16(&mut self.raw, 0x1A, n);
    }
    fn flags(&self) -> u32 {
        le32(&self.raw, 0x20)
    }
    /// i_blocks in 512-byte units
    fn set_blocks(&mut self, fs_blocks: u64) {
        let s = fs_blocks * SECTORS_PER_BLOCK;
        put32(&mut self.raw, 0x1C, s as u32);
        put16(&mut self.raw, 0x74, (s >> 32) as u16);
    }
    fn blocks(&self) -> u64 {
        (le32(&self.raw, 0x1C) as u64 | (le16(&self.raw, 0x74) as u64) << 32) / SECTORS_PER_BLOCK
    }
    fn mtime(&self) -> u32 {
        le32(&self.raw, 0x10)
    }
    fn touch(&mut self, now: u32) {
        put32(&mut self.raw, 0x0C, now); // ctime
        put32(&mut self.raw, 0x10, now); // mtime
    }
}

/// A run of the file's blocks: (first logical block, first disk block, count).
type Run = (u32, u64, u32);

fn has_super(g: u32) -> bool {
    let pow = |mut n: u32, b: u32| {
        while n > 1 && n % b == 0 {
            n /= b;
        }
        n == 1
    };
    g == 0 || g == 1 || pow(g, 3) || pow(g, 5) || pow(g, 7)
}

fn check_name(n: &str) -> R<()> {
    if n.is_empty() || n.len() > 255 || n == "." || n == ".." || n.contains('/') || n.contains('\0') {
        Err(Error::BadName)
    } else {
        Ok(())
    }
}

fn components(path: &str) -> R<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    for p in &parts {
        check_name(p)?;
    }
    Ok(parts)
}

impl Fs {
    // ------------------------------------------------------------ format

    /// Make a new ext4 on the partition (`sectors` long): an empty root
    /// directory and lost+found.
    pub fn format(v: &mut Vol, sectors: u64, uuid: [u8; 16], label: &str, now: u32) -> R<Fs> {
        let blocks = (sectors / SECTORS_PER_BLOCK).min(u32::MAX as u64);
        if blocks < 1024 {
            return Err(Error::TooBig);
        }
        let groups = blocks.div_ceil(BLOCKS_PER_GROUP as u64) as u32;
        // a last group too small for its metadata is left out
        let gdt_blocks = (groups as usize * 32).div_ceil(BLOCK) as u64;
        let itable_blocks = (INODES_PER_GROUP as usize * INODE_SIZE / BLOCK) as u64;
        let mut groups = groups;
        let mut blocks = blocks;
        let last_len = blocks - (groups as u64 - 1) * BLOCKS_PER_GROUP as u64;
        let last_meta = if has_super(groups - 1) { 1 + gdt_blocks } else { 0 } + 2 + itable_blocks;
        if groups > 1 && last_len < last_meta + 64 {
            groups -= 1;
            blocks = groups as u64 * BLOCKS_PER_GROUP as u64;
        }
        let mut gs = Vec::new();
        for g in 0..groups {
            let first = g as u64 * BLOCKS_PER_GROUP as u64;
            let meta = if has_super(g) { 1 + gdt_blocks } else { 0 };
            gs.push(Group {
                block_bitmap: first + meta,
                inode_bitmap: first + meta + 1,
                inode_table: first + meta + 2,
                free_blocks: 0,
                free_inodes: INODES_PER_GROUP,
                used_dirs: 0,
            });
        }
        let mut fs = Fs {
            sb: vec![0u8; 1024],
            groups: gs,
            blocks,
            blocks_per_group: BLOCKS_PER_GROUP,
            inodes_per_group: INODES_PER_GROUP,
            inode_size: INODE_SIZE,
            desc_size: 32,
            first_data_block: 0,
            writable: true,
        };
        // bitmaps and empty inode tables
        let zero = vec![0u8; BLOCK * 16];
        for g in 0..groups {
            let gr = fs.groups[g as usize];
            let first = g as u64 * BLOCKS_PER_GROUP as u64;
            let len = (blocks - first).min(BLOCKS_PER_GROUP as u64);
            let used_meta = gr.inode_table + itable_blocks - first;
            let mut bb = vec![0u8; BLOCK];
            for b in 0..used_meta {
                bb[b as usize / 8] |= 1 << (b % 8);
            }
            for b in len..(BLOCK as u64 * 8) {
                bb[b as usize / 8] |= 1 << (b % 8); // past the end of the file system
            }
            v.write(gr.block_bitmap, &bb)?;
            let mut ib = vec![0u8; BLOCK];
            for i in INODES_PER_GROUP as usize..BLOCK * 8 {
                ib[i / 8] |= 1 << (i % 8);
            }
            v.write(gr.inode_bitmap, &ib)?;
            let mut t = 0;
            while t < itable_blocks {
                let n = (itable_blocks - t).min(16);
                v.write(gr.inode_table + t, &zero[..n as usize * BLOCK])?;
                t += n;
            }
            fs.groups[g as usize].free_blocks = (len - used_meta) as u32;
        }
        // reserved inodes 1..=10 are in use
        let mut ib = v.block(fs.groups[0].inode_bitmap)?;
        for i in 0..(FIRST_INO - 1) as usize {
            ib[i / 8] |= 1 << (i % 8);
        }
        v.write(fs.groups[0].inode_bitmap, &ib)?;
        fs.groups[0].free_inodes -= FIRST_INO - 1;

        // the superblock
        let total_inodes = groups * INODES_PER_GROUP;
        let sb = &mut fs.sb;
        put32(sb, 0x00, total_inodes);
        put32(sb, 0x04, blocks as u32);
        put32(sb, 0x08, (blocks / 100) as u32); // reserved for root (stays free)
        put32(sb, 0x14, 0); // first data block
        put32(sb, 0x18, 2); // 4 KiB
        put32(sb, 0x1C, 2);
        put32(sb, 0x20, BLOCKS_PER_GROUP);
        put32(sb, 0x24, BLOCKS_PER_GROUP);
        put32(sb, 0x28, INODES_PER_GROUP);
        put32(sb, 0x2C, 0);
        put32(sb, 0x30, now);
        put16(sb, 0x34, 0);
        put16(sb, 0x36, 0xFFFF); // no forced checks by mount count
        put16(sb, 0x38, MAGIC);
        put16(sb, 0x3A, 1); // clean
        put16(sb, 0x3C, 1); // on errors: continue
        put32(sb, 0x40, now);
        put32(sb, 0x4C, 1); // dynamic revision
        put32(sb, 0x54, FIRST_INO);
        put16(sb, 0x58, INODE_SIZE as u16);
        put32(sb, 0x5C, 0); // compat
        put32(sb, 0x60, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
        put32(sb, 0x64, RO_SPARSE_SUPER | RO_LARGE_FILE | RO_EXTRA_ISIZE);
        sb[0x68..0x78].copy_from_slice(&uuid);
        let l = label.as_bytes();
        sb[0x78..0x78 + l.len().min(16)].copy_from_slice(&l[..l.len().min(16)]);
        put32(sb, 0xEC, u32::from_le_bytes([uuid[0], uuid[1], uuid[2], uuid[3]])); // hash seed
        put32(sb, 0xF0, u32::from_le_bytes([uuid[4], uuid[5], uuid[6], uuid[7]]));
        put32(sb, 0xF4, u32::from_le_bytes([uuid[8], uuid[9], uuid[10], uuid[11]]));
        put32(sb, 0xF8, u32::from_le_bytes([uuid[12], uuid[13], uuid[14], uuid[15]]));
        sb[0xFC] = 1; // half MD4, unused without dir_index
        put32(sb, 0x108, now); // mkfs time
        put16(sb, 0x15C, 32); // min extra isize
        put16(sb, 0x15E, 32); // want extra isize
        put32(sb, 0x160, 0x2); // unsigned directory hash

        // the root directory and lost+found
        let root_block = fs.alloc_blocks(v, 1, 0)?;
        let lf_block = fs.alloc_blocks(v, 1, 0)?;
        let mut d = vec![0u8; BLOCK];
        let mut at = 0;
        at += dirent(&mut d[at..], ROOT, ".", FT_DIR, 12);
        at += dirent(&mut d[at..], ROOT, "..", FT_DIR, 12);
        dirent(&mut d[at..], LOST_FOUND, "lost+found", FT_DIR, BLOCK - at);
        v.write(root_block.1, &d)?;
        let mut d = vec![0u8; BLOCK];
        let at = dirent(&mut d, LOST_FOUND, ".", FT_DIR, 12);
        dirent(&mut d[at..], ROOT, "..", FT_DIR, BLOCK - at);
        v.write(lf_block.1, &d)?;
        for (ino, block, links) in [(ROOT, root_block.1, 3u16), (LOST_FOUND, lf_block.1, 2)] {
            let mut i = Inode { ino, raw: vec![0u8; fs.inode_size] };
            put16(&mut i.raw, 0, S_IFDIR | if ino == ROOT { 0o755 } else { 0o700 });
            put32(&mut i.raw, 0x08, now);
            i.touch(now);
            i.set_links(links);
            i.set_size(BLOCK as u64);
            put32(&mut i.raw, 0x20, EXT4_EXTENTS_FL);
            put16(&mut i.raw, 0x80, 32);
            set_extents(&mut i, &[(0, block, 1)]);
            i.set_blocks(1);
            fs.write_inode(v, &i)?;
            fs.mark_inode(v, ino, true, true)?;
        }
        // the root's inode was in use already (reserved): count it as a directory here
        fs.groups[0].used_dirs += 1;
        fs.write_meta(v, true)?;
        Ok(fs)
    }

    // ------------------------------------------------------------ mount

    pub fn mount(v: &mut Vol) -> R<Fs> {
        let mut first = vec![0u8; BLOCK];
        v.read(0, &mut first)?;
        let sb = first[1024..2048].to_vec();
        if le16(&sb, 0x38) != MAGIC {
            return Err(Error::NotExt4);
        }
        let log = le32(&sb, 0x18);
        if log != 2 {
            return Err(Error::Corrupt("only 4 KiB blocks are supported"));
        }
        let incompat = le32(&sb, 0x60);
        let ro = le32(&sb, 0x64);
        let compat = le32(&sb, 0x5C);
        let bit64 = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if bit64 { (le16(&sb, 0xFE) as usize).max(32) } else { 32 };
        let blocks = le32(&sb, 0x04) as u64 | if bit64 { (le32(&sb, 0x150) as u64) << 32 } else { 0 };
        let bpg = le32(&sb, 0x20);
        let ipg = le32(&sb, 0x28);
        let first_data_block = le32(&sb, 0x14) as u64;
        let inode_size = if le32(&sb, 0x4C) >= 1 { le16(&sb, 0x58) as usize } else { 128 };
        let ngroups = (blocks - first_data_block).div_ceil(bpg as u64) as usize;
        let gdt_blocks = (ngroups * desc_size).div_ceil(BLOCK);
        let mut gdt = vec![0u8; gdt_blocks * BLOCK];
        v.read(first_data_block + 1, &mut gdt)?;
        let hi = |d: &[u8], o: usize| if bit64 && desc_size >= 64 { le32(d, o) as u64 } else { 0 };
        let hi16 = |d: &[u8], o: usize| if bit64 && desc_size >= 64 { le16(d, o) as u32 } else { 0 };
        let groups = (0..ngroups)
            .map(|g| {
                let d = &gdt[g * desc_size..(g + 1) * desc_size];
                Group {
                    block_bitmap: le32(d, 0) as u64 | hi(d, 0x20) << 32,
                    inode_bitmap: le32(d, 4) as u64 | hi(d, 0x24) << 32,
                    inode_table: le32(d, 8) as u64 | hi(d, 0x28) << 32,
                    free_blocks: le16(d, 0xC) as u32 | hi16(d, 0x2C) << 16,
                    free_inodes: le16(d, 0xE) as u32 | hi16(d, 0x2E) << 16,
                    used_dirs: le16(d, 0x10) as u32 | hi16(d, 0x30) << 16,
                }
            })
            .collect();
        // writable only with what this code keeps up, and with no journal to replay
        let writable = incompat & !INCOMPAT_WRITABLE == 0 && ro & !RO_WRITABLE == 0 && compat & COMPAT_HAS_JOURNAL == 0 && incompat & INCOMPAT_RECOVER == 0 && !bit64;
        Ok(Fs { sb, groups, blocks, blocks_per_group: bpg, inodes_per_group: ipg, inode_size, desc_size, first_data_block, writable })
    }

    /// (total, free) bytes.
    pub fn usage(&self) -> (u64, u64) {
        (self.blocks * BLOCK as u64, self.groups.iter().map(|g| g.free_blocks as u64).sum::<u64>() * BLOCK as u64)
    }

    // ------------------------------------------------------------ metadata

    /// Group descriptors and the superblock to disk (`backups`: also the copies).
    fn write_meta(&mut self, v: &mut Vol, backups: bool) -> R<()> {
        let free_blocks: u64 = self.groups.iter().map(|g| g.free_blocks as u64).sum();
        let free_inodes: u32 = self.groups.iter().map(|g| g.free_inodes).sum();
        put32(&mut self.sb, 0x0C, free_blocks as u32);
        put32(&mut self.sb, 0x10, free_inodes);
        let gdt_blocks = (self.groups.len() * self.desc_size).div_ceil(BLOCK);
        let mut gdt = vec![0u8; gdt_blocks * BLOCK];
        for (i, g) in self.groups.iter().enumerate() {
            let d = &mut gdt[i * self.desc_size..(i + 1) * self.desc_size];
            put32(d, 0, g.block_bitmap as u32);
            put32(d, 4, g.inode_bitmap as u32);
            put32(d, 8, g.inode_table as u32);
            put16(d, 0xC, g.free_blocks as u16);
            put16(d, 0xE, g.free_inodes as u16);
            put16(d, 0x10, g.used_dirs as u16);
        }
        let ngroups = if backups { self.groups.len() as u32 } else { 1 };
        for g in (0..ngroups).filter(|&g| has_super(g)) {
            let first = self.first_data_block + g as u64 * self.blocks_per_group as u64;
            let mut b = if g == 0 { v.block(0)? } else { vec![0u8; BLOCK] };
            let off = if g == 0 { 1024 } else { 0 };
            let mut sb = self.sb.clone();
            put16(&mut sb, 0x5A, g as u16); // block group number of this copy
            b[off..off + 1024].copy_from_slice(&sb);
            v.write(first, &b)?;
            v.write(first + 1, &gdt)?;
        }
        Ok(())
    }

    fn inode_loc(&self, ino: u32) -> (u64, usize) {
        let i = (ino - 1) as usize;
        let g = i / self.inodes_per_group as usize;
        let idx = i % self.inodes_per_group as usize;
        let byte = idx * self.inode_size;
        (self.groups[g].inode_table + (byte / BLOCK) as u64, byte % BLOCK)
    }

    fn read_inode(&self, v: &mut Vol, ino: u32) -> R<Inode> {
        if ino == 0 || ino as usize > self.groups.len() * self.inodes_per_group as usize {
            return Err(Error::Corrupt("inode number out of range"));
        }
        let (b, off) = self.inode_loc(ino);
        let blk = v.block(b)?;
        Ok(Inode { ino, raw: blk[off..off + self.inode_size].to_vec() })
    }

    fn write_inode(&self, v: &mut Vol, i: &Inode) -> R<()> {
        let (b, off) = self.inode_loc(i.ino);
        let mut blk = v.block(b)?;
        blk[off..off + self.inode_size].copy_from_slice(&i.raw);
        v.write(b, &blk)
    }

    /// Mark an inode used or free in its bitmap (and the group's counts).
    fn mark_inode(&mut self, v: &mut Vol, ino: u32, used: bool, dir: bool) -> R<()> {
        let i = (ino - 1) as usize;
        let g = i / self.inodes_per_group as usize;
        let bit = i % self.inodes_per_group as usize;
        let mut bm = v.block(self.groups[g].inode_bitmap)?;
        let was = bm[bit / 8] & (1 << (bit % 8)) != 0;
        if used {
            bm[bit / 8] |= 1 << (bit % 8);
        } else {
            bm[bit / 8] &= !(1 << (bit % 8));
        }
        v.write(self.groups[g].inode_bitmap, &bm)?;
        let gr = &mut self.groups[g];
        match (was, used) {
            (false, true) => {
                gr.free_inodes -= 1;
                if dir {
                    gr.used_dirs += 1;
                }
            }
            (true, false) => {
                gr.free_inodes += 1;
                if dir {
                    gr.used_dirs = gr.used_dirs.saturating_sub(1);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn alloc_inode(&mut self, v: &mut Vol, dir: bool) -> R<u32> {
        for g in 0..self.groups.len() {
            if self.groups[g].free_inodes == 0 {
                continue;
            }
            let bm = v.block(self.groups[g].inode_bitmap)?;
            for bit in 0..self.inodes_per_group as usize {
                if bm[bit / 8] & (1 << (bit % 8)) == 0 {
                    let ino = (g * self.inodes_per_group as usize + bit + 1) as u32;
                    if ino < FIRST_INO {
                        continue;
                    }
                    self.mark_inode(v, ino, true, dir)?;
                    return Ok(ino);
                }
            }
        }
        Err(Error::Full)
    }

    /// Up to `want` blocks in one run (fewer if no run is that long), from
    /// group `near` on: (count, first block).
    fn alloc_blocks(&mut self, v: &mut Vol, want: u32, near: usize) -> R<(u32, u64)> {
        let n = self.groups.len();
        let mut best: Option<(usize, usize, u32)> = None; // (group, first bit, len)
        for k in 0..n {
            let g = (near + k) % n;
            if self.groups[g].free_blocks == 0 {
                continue;
            }
            let bm = v.block(self.groups[g].block_bitmap)?;
            let mut run_start = None;
            for bit in 0..=self.blocks_per_group as usize {
                let used = bit == self.blocks_per_group as usize || bm[bit / 8] & (1 << (bit % 8)) != 0;
                match (used, run_start) {
                    (false, None) => run_start = Some(bit),
                    (true, Some(s)) => {
                        let len = (bit - s) as u32;
                        if best.is_none_or(|b| len > b.2) {
                            best = Some((g, s, len));
                        }
                        if len >= want {
                            return self.take(v, g, s, want);
                        }
                        run_start = None;
                    }
                    _ => {}
                }
            }
        }
        match best {
            Some((g, s, len)) if len > 0 => self.take(v, g, s, len.min(want)),
            _ => Err(Error::Full),
        }
    }

    fn take(&mut self, v: &mut Vol, g: usize, first_bit: usize, len: u32) -> R<(u32, u64)> {
        let bmb = self.groups[g].block_bitmap;
        let mut bm = v.block(bmb)?;
        for b in first_bit..first_bit + len as usize {
            bm[b / 8] |= 1 << (b % 8);
        }
        v.write(bmb, &bm)?;
        self.groups[g].free_blocks -= len;
        Ok((len, self.first_data_block + g as u64 * self.blocks_per_group as u64 + first_bit as u64))
    }

    fn free_blocks(&mut self, v: &mut Vol, first: u64, len: u64) -> R<()> {
        let mut b = first;
        while b < first + len {
            let rel = b - self.first_data_block;
            let g = (rel / self.blocks_per_group as u64) as usize;
            let bit = (rel % self.blocks_per_group as u64) as usize;
            let n = (first + len - b).min((self.blocks_per_group as usize - bit) as u64) as usize;
            let bmb = self.groups[g].block_bitmap;
            let mut bm = v.block(bmb)?;
            for k in bit..bit + n {
                bm[k / 8] &= !(1 << (k % 8));
            }
            v.write(bmb, &bm)?;
            self.groups[g].free_blocks += n as u32;
            b += n as u64;
        }
        Ok(())
    }

    // ------------------------------------------------------------ extents

    /// The file's runs, in logical order (depth 0 or more).
    fn runs(&self, v: &mut Vol, i: &Inode) -> R<Vec<Run>> {
        if i.flags() & EXT4_EXTENTS_FL == 0 {
            return Err(Error::Corrupt("a file without extents (old block maps are not supported)"));
        }
        let mut out = Vec::new();
        self.walk(v, &i.raw[0x28..0x28 + 60], &mut out, 0)?;
        Ok(out)
    }

    fn walk(&self, v: &mut Vol, node: &[u8], out: &mut Vec<Run>, level: u32) -> R<()> {
        if le16(node, 0) != EXTENT_MAGIC || level > 5 {
            return Err(Error::Corrupt("bad extent header"));
        }
        let entries = le16(node, 2) as usize;
        let depth = le16(node, 6);
        for k in 0..entries {
            let e = &node[12 + k * 12..24 + k * 12];
            if depth == 0 {
                let mut len = le16(e, 4) as u32;
                if len > EXTENT_MAX {
                    len -= EXTENT_MAX; // unwritten extent: reads as zeros, but blocks are its
                }
                out.push((le32(e, 0), (le16(e, 6) as u64) << 32 | le32(e, 8) as u64, len));
            } else {
                let child = (le16(e, 8) as u64) << 32 | le32(e, 4) as u64;
                let blk = v.block(child)?;
                self.walk(v, &blk, out, level + 1)?;
            }
        }
        Ok(())
    }

    /// Blocks of the extent tree itself (index and leaf blocks).
    fn tree_blocks(&self, _v: &mut Vol, i: &Inode) -> R<Vec<u64>> {
        let mut out = Vec::new();
        let root = i.raw[0x28..0x28 + 60].to_vec();
        if le16(&root, 6) > 0 {
            for k in 0..le16(&root, 2) as usize {
                let e = &root[12 + k * 12..24 + k * 12];
                out.push((le16(e, 8) as u64) << 32 | le32(e, 4) as u64);
            }
        }
        Ok(out)
    }

    /// Map the inode to `runs`: up to 4 in the inode, else one level of leaf blocks.
    fn map(&mut self, v: &mut Vol, i: &mut Inode, runs: &[Run]) -> R<u64> {
        if runs.len() <= 4 {
            set_extents(i, runs);
            return Ok(0);
        }
        let per_leaf = (BLOCK - 12) / 12;
        let leaves: Vec<&[Run]> = runs.chunks(per_leaf).collect();
        if leaves.len() > 4 {
            return Err(Error::TooBig);
        }
        let mut index = Vec::new();
        for leaf in &leaves {
            let (_, b) = self.alloc_blocks(v, 1, 0)?;
            let mut blk = vec![0u8; BLOCK];
            put16(&mut blk, 0, EXTENT_MAGIC);
            put16(&mut blk, 2, leaf.len() as u16);
            put16(&mut blk, 4, per_leaf as u16);
            put16(&mut blk, 6, 0);
            for (k, r) in leaf.iter().enumerate() {
                extent(&mut blk[12 + k * 12..24 + k * 12], r);
            }
            v.write(b, &blk)?;
            index.push((leaf[0].0, b));
        }
        let ib = &mut i.raw[0x28..0x28 + 60];
        ib.fill(0);
        put16(ib, 0, EXTENT_MAGIC);
        put16(ib, 2, index.len() as u16);
        put16(ib, 4, 4);
        put16(ib, 6, 1);
        for (k, (lblk, b)) in index.iter().enumerate() {
            let e = &mut ib[12 + k * 12..24 + k * 12];
            put32(e, 0, *lblk);
            put32(e, 4, *b as u32);
            put16(e, 8, (*b >> 32) as u16);
        }
        Ok(index.len() as u64)
    }

    // ------------------------------------------------------------ directories

    /// (inode, file type, name) of a directory's entries.
    fn entries(&self, v: &mut Vol, dir: &Inode) -> R<Vec<(u32, u8, String)>> {
        let mut out = Vec::new();
        for (lb, pb, n) in self.runs(v, dir)? {
            for k in 0..n as u64 {
                if (lb as u64 + k) * BLOCK as u64 >= dir.size() {
                    break;
                }
                let blk = v.block(pb + k)?;
                let mut at = 0;
                while at + 8 <= BLOCK {
                    let ino = le32(&blk, at);
                    let rec = le16(&blk, at + 4) as usize;
                    let nl = blk[at + 6] as usize;
                    if rec < 8 || at + rec > BLOCK || 8 + nl > rec {
                        return Err(Error::Corrupt("bad directory entry"));
                    }
                    if ino != 0 && nl > 0 {
                        out.push((ino, blk[at + 7], String::from_utf8_lossy(&blk[at + 8..at + 8 + nl]).into_owned()));
                    }
                    at += rec;
                }
            }
        }
        Ok(out)
    }

    fn lookup(&self, v: &mut Vol, dir: &Inode, name: &str) -> R<Option<(u32, u8)>> {
        Ok(self.entries(v, dir)?.into_iter().find(|e| e.2 == name).map(|e| (e.0, e.1)))
    }

    /// The inode of `path` ("" or "/" is the root).
    fn resolve(&self, v: &mut Vol, path: &str) -> R<Inode> {
        let mut cur = self.read_inode(v, ROOT)?;
        for c in components(path)? {
            if !cur.is_dir() {
                return Err(Error::NotADirectory);
            }
            let (ino, _) = self.lookup(v, &cur, c)?.ok_or(Error::NotFound)?;
            cur = self.read_inode(v, ino)?;
        }
        Ok(cur)
    }

    /// A directory about to change: an index it has would go stale, so it
    /// becomes a plain one (its blocks read right as such).
    fn unindex(dir: &mut Inode) {
        let fl = dir.flags();
        if fl & EXT4_INDEX_FL != 0 {
            put32(&mut dir.raw, 0x20, fl & !EXT4_INDEX_FL);
        }
    }

    /// Put an entry into a directory (a new block if no room).
    fn add_entry(&mut self, v: &mut Vol, dir: &mut Inode, ino: u32, name: &str, ft: u8, now: u32) -> R<()> {
        Self::unindex(dir);
        let need = (8 + name.len()).next_multiple_of(4);
        let runs = self.runs(v, dir)?;
        for &(lb, pb, n) in &runs {
            for k in 0..n as u64 {
                if (lb as u64 + k) * BLOCK as u64 >= dir.size() {
                    break;
                }
                let mut blk = v.block(pb + k)?;
                let mut at = 0;
                while at + 8 <= BLOCK {
                    let e_ino = le32(&blk, at);
                    let rec = le16(&blk, at + 4) as usize;
                    let nl = blk[at + 6] as usize;
                    if rec < 8 || at + rec > BLOCK {
                        return Err(Error::Corrupt("bad directory entry"));
                    }
                    let used = if e_ino == 0 { 0 } else { (8 + nl).next_multiple_of(4) };
                    if rec - used >= need {
                        if e_ino == 0 {
                            dirent(&mut blk[at..], ino, name, ft, rec);
                        } else {
                            put16(&mut blk, at + 4, used as u16);
                            dirent(&mut blk[at + used..], ino, name, ft, rec - used);
                        }
                        v.write(pb + k, &blk)?;
                        dir.touch(now);
                        return self.write_inode(v, dir);
                    }
                    at += rec;
                }
            }
        }
        // a new block at the end
        let (_, b) = self.alloc_blocks(v, 1, 0)?;
        let mut blk = vec![0u8; BLOCK];
        dirent(&mut blk, ino, name, ft, BLOCK);
        v.write(b, &blk)?;
        let next = (dir.size() / BLOCK as u64) as u32;
        let mut runs = runs;
        match runs.last_mut() {
            Some(last) if last.0 + last.2 == next && last.1 + last.2 as u64 == b && last.2 < EXTENT_MAX => last.2 += 1,
            _ => runs.push((next, b, 1)),
        }
        let old_tree = self.tree_blocks(v, dir)?;
        let tree = self.map(v, dir, &runs)?;
        for t in old_tree {
            self.free_blocks(v, t, 1)?;
        }
        dir.set_size(dir.size() + BLOCK as u64);
        dir.set_blocks(runs.iter().map(|r| r.2 as u64).sum::<u64>() + tree);
        dir.touch(now);
        self.write_inode(v, dir)
    }

    /// Take an entry out of a directory.
    fn remove_entry(&mut self, v: &mut Vol, dir: &mut Inode, name: &str, now: u32) -> R<()> {
        Self::unindex(dir);
        for (lb, pb, n) in self.runs(v, dir)? {
            for k in 0..n as u64 {
                if (lb as u64 + k) * BLOCK as u64 >= dir.size() {
                    break;
                }
                let mut blk = v.block(pb + k)?;
                let mut at = 0;
                let mut prev: Option<usize> = None;
                while at + 8 <= BLOCK {
                    let rec = le16(&blk, at + 4) as usize;
                    let nl = blk[at + 6] as usize;
                    if rec < 8 || at + rec > BLOCK {
                        return Err(Error::Corrupt("bad directory entry"));
                    }
                    if le32(&blk, at) != 0 && &blk[at + 8..at + 8 + nl] == name.as_bytes() {
                        match prev {
                            Some(p) => {
                                let prec = le16(&blk, p + 4) as usize;
                                put16(&mut blk, p + 4, (prec + rec) as u16);
                            }
                            None => put32(&mut blk, at, 0), // first in its block: emptied, kept
                        }
                        v.write(pb + k, &blk)?;
                        dir.touch(now);
                        return self.write_inode(v, dir);
                    }
                    prev = Some(at);
                    at += rec;
                }
            }
        }
        Err(Error::NotFound)
    }

    fn new_dir(&mut self, v: &mut Vol, parent: &mut Inode, name: &str, now: u32) -> R<Inode> {
        let ino = self.alloc_inode(v, true)?;
        let near = ((ino - 1) / self.inodes_per_group) as usize;
        let (_, b) = self.alloc_blocks(v, 1, near)?;
        let mut d = vec![0u8; BLOCK];
        let at = dirent(&mut d, ino, ".", FT_DIR, 12);
        dirent(&mut d[at..], parent.ino, "..", FT_DIR, BLOCK - at);
        v.write(b, &d)?;
        let mut i = Inode { ino, raw: vec![0u8; self.inode_size] };
        put16(&mut i.raw, 0, S_IFDIR | 0o755);
        put32(&mut i.raw, 0x08, now);
        i.touch(now);
        i.set_links(2);
        i.set_size(BLOCK as u64);
        put32(&mut i.raw, 0x20, EXT4_EXTENTS_FL);
        if self.inode_size > 128 {
            put16(&mut i.raw, 0x80, 32);
        }
        set_extents(&mut i, &[(0, b, 1)]);
        i.set_blocks(1);
        self.write_inode(v, &i)?;
        self.add_entry(v, parent, ino, name, FT_DIR, now)?;
        parent.set_links(parent.links() + 1);
        self.write_inode(v, parent)?;
        Ok(i)
    }

    // ------------------------------------------------------------ the API

    pub fn stat(&self, v: &mut Vol, path: &str) -> R<Stat> {
        let i = self.resolve(v, path)?;
        Ok(Stat { ino: i.ino, size: i.size(), dir: i.is_dir(), mtime: i.mtime() })
    }

    /// Bytes of a file from `offset`: how many (0 at its end).
    pub fn read(&self, v: &mut Vol, path: &str, offset: u64, buf: &mut [u8]) -> R<usize> {
        let i = self.resolve(v, path)?;
        if i.is_dir() {
            return Err(Error::IsADirectory);
        }
        let size = i.size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        buf[..n].fill(0); // holes read as zeros
        let runs = self.runs(v, &i)?;
        let first = offset / BLOCK as u64;
        let last = (offset + n as u64 - 1) / BLOCK as u64;
        let mut blk = vec![0u8; BLOCK];
        for lb in first..=last {
            let Some(&(l0, p0, _)) = runs.iter().find(|r| lb >= r.0 as u64 && lb < r.0 as u64 + r.2 as u64) else { continue };
            v.read(p0 + (lb - l0 as u64), &mut blk)?;
            let bs = lb * BLOCK as u64;
            let from = offset.max(bs);
            let to = (offset + n as u64).min(bs + BLOCK as u64);
            buf[(from - offset) as usize..(to - offset) as usize].copy_from_slice(&blk[(from - bs) as usize..(to - bs) as usize]);
        }
        Ok(n)
    }

    /// The entries of a directory: (name, stat), without "." and "..".
    pub fn list(&self, v: &mut Vol, path: &str) -> R<Vec<(String, Stat)>> {
        let d = self.resolve(v, path)?;
        if !d.is_dir() {
            return Err(Error::NotADirectory);
        }
        let mut out = Vec::new();
        for (ino, _, name) in self.entries(v, &d)? {
            if name == "." || name == ".." {
                continue;
            }
            let i = self.read_inode(v, ino)?;
            out.push((name, Stat { ino, size: i.size(), dir: i.is_dir(), mtime: i.mtime() }));
        }
        Ok(out)
    }

    /// Make a directory and those above it that are missing.
    pub fn mkdir_p(&mut self, v: &mut Vol, path: &str, now: u32) -> R<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let mut cur = self.read_inode(v, ROOT)?;
        for c in components(path)? {
            match self.lookup(v, &cur, c)? {
                Some((ino, _)) => {
                    cur = self.read_inode(v, ino)?;
                    if !cur.is_dir() {
                        return Err(Error::NotADirectory);
                    }
                }
                None => cur = self.new_dir(v, &mut cur, c, now)?,
            }
        }
        self.write_meta(v, false)
    }

    /// Create or replace a file with `data` (the directories above are made).
    pub fn write_file(&mut self, v: &mut Vol, path: &str, data: &[u8], now: u32) -> R<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let mut parts = components(path)?;
        let name = parts.pop().ok_or(Error::BadName)?;
        let dirpath = parts.join("/");
        self.mkdir_p(v, &dirpath, now)?;
        let mut dir = self.resolve(v, &dirpath)?;
        let old = self.lookup(v, &dir, name)?;
        if let Some((ino, _)) = old {
            if self.read_inode(v, ino)?.is_dir() {
                return Err(Error::IsADirectory);
            }
        }
        // the data first, in as few runs as the free space allows
        let total = data.len().div_ceil(BLOCK) as u64;
        if total > (u32::MAX as u64) {
            return Err(Error::TooBig);
        }
        let ino = self.alloc_inode(v, false)?;
        let near = ((ino - 1) / self.inodes_per_group) as usize;
        let mut runs: Vec<Run> = Vec::new();
        let mut done = 0u64;
        let result = (|| -> R<()> {
            while done < total {
                let want = (total - done).min(EXTENT_MAX as u64) as u32;
                let (n, b) = self.alloc_blocks(v, want, near)?;
                runs.push((done as u32, b, n));
                let from = done as usize * BLOCK;
                let to = (from + n as usize * BLOCK).min(data.len());
                let mut chunk = data[from..to].to_vec();
                chunk.resize(n as usize * BLOCK, 0);
                v.write(b, &chunk)?;
                done += n as u64;
            }
            Ok(())
        })();
        let mut i = Inode { ino, raw: vec![0u8; self.inode_size] };
        let tree = match result.and_then(|_| self.map(v, &mut i, &runs)) {
            Ok(t) => t,
            Err(e) => {
                for (_, b, n) in &runs {
                    let _ = self.free_blocks(v, *b, *n as u64);
                }
                let _ = self.mark_inode(v, ino, false, false);
                let _ = self.write_meta(v, false);
                return Err(e);
            }
        };
        put16(&mut i.raw, 0, S_IFREG | 0o644);
        put32(&mut i.raw, 0x08, now);
        i.touch(now);
        i.set_links(1);
        i.set_size(data.len() as u64);
        let fl = EXT4_EXTENTS_FL | le32(&i.raw, 0x20);
        put32(&mut i.raw, 0x20, fl);
        if self.inode_size > 128 {
            put16(&mut i.raw, 0x80, 32);
        }
        i.set_blocks(total + tree);
        self.write_inode(v, &i)?;
        // then the name: the new file replaces the old one
        if old.is_some() {
            self.remove_entry(v, &mut dir, name, now)?;
        }
        self.add_entry(v, &mut dir, ino, name, FT_REG, now)?;
        if let Some((old_ino, _)) = old {
            self.release(v, old_ino, now)?;
        }
        self.write_meta(v, false)
    }

    /// A file's blocks and inode back to the free space.
    fn release(&mut self, v: &mut Vol, ino: u32, now: u32) -> R<()> {
        let mut i = self.read_inode(v, ino)?;
        let dir = i.is_dir();
        for (_, b, n) in self.runs(v, &i)? {
            self.free_blocks(v, b, n as u64)?;
        }
        for t in self.tree_blocks(v, &i)? {
            self.free_blocks(v, t, 1)?;
        }
        i.set_links(0);
        put32(&mut i.raw, 0x14, now); // dtime
        self.write_inode(v, &i)?;
        self.mark_inode(v, ino, false, dir)
    }

    /// Remove a file or an empty directory; false if there was none.
    pub fn remove(&mut self, v: &mut Vol, path: &str, now: u32) -> R<bool> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let mut parts = components(path)?;
        let Some(name) = parts.pop() else { return Err(Error::BadName) };
        let dirpath = parts.join("/");
        let mut dir = match self.resolve(v, &dirpath) {
            Ok(d) => d,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        let Some((ino, _)) = self.lookup(v, &dir, name)? else { return Ok(false) };
        let i = self.read_inode(v, ino)?;
        if i.is_dir() {
            if self.entries(v, &i)?.iter().any(|e| e.2 != "." && e.2 != "..") {
                return Err(Error::NotEmpty);
            }
            dir.set_links(dir.links().saturating_sub(1));
        }
        self.remove_entry(v, &mut dir, name, now)?;
        self.release(v, ino, now)?;
        self.write_meta(v, false)?;
        Ok(true)
    }
}

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

fn extent(e: &mut [u8], r: &Run) {
    put32(e, 0, r.0);
    put16(e, 4, r.2 as u16);
    put16(e, 6, (r.1 >> 32) as u16);
    put32(e, 8, r.1 as u32);
}

/// Up to four runs right in the inode (depth 0).
fn set_extents(i: &mut Inode, runs: &[Run]) {
    let b = &mut i.raw[0x28..0x28 + 60];
    b.fill(0);
    put16(b, 0, EXTENT_MAGIC);
    put16(b, 2, runs.len() as u16);
    put16(b, 4, 4);
    put16(b, 6, 0);
    for (k, r) in runs.iter().enumerate() {
        extent(&mut b[12 + k * 12..24 + k * 12], r);
    }
}

#[cfg(test)]
mod tests;
