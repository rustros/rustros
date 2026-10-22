//! ext4, no_std: format a partition; files, directories, symbolic and hard
//! links, special files, as Linux reads and checks them (e2fsck).
//!
//! Two ways in: by inode, as a VFS wants it (`lookup`, `create`, `mkdir`,
//! `pread`, `pwrite`, `truncate`, `rename`, `link`, `symlink`, `setattr`,
//! ...), and by path for whole files (`write_file`, `read`, `list`, `stat`,
//! `remove`, `mkdir_p`).
//!
//! Metadata (bitmaps, inode tables, directories, extent trees) goes through
//! a block cache and reaches the disk at `sync`, which every changing call
//! does when it ends unless `auto_sync` is off; file data is written
//! straight away. With a journal (see `journal`) a sync is one transaction:
//! after a crash the file system is as it was at one of the syncs.
//!
//! What it makes: 4 KiB blocks, 128 MiB block groups, 256-byte inodes,
//! files and directories mapped by extents (trees of any depth), linear
//! directories, a journal sized as mke2fs sizes it; features `extents`,
//! `filetype`, `sparse_super`, `large_file`, `extra_isize`, `has_journal`;
//! no checksums yet.
//!
//! What it reads: also file systems Linux made (flex_bg, 64-bit, checksums
//! are ignored when reading; their journal is replayed, in memory if the
//! disk is not ours to write). It writes only to those whose features it
//! keeps up (it refuses the rest instead of damaging them).
//!
//! Mounted writable with a journal, the file system is marked as needing
//! recovery until `close` (as Linux does while it has one mounted).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod cache;
mod dir;
mod extent;
mod file;
mod journal;
mod ns;

use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;

pub use ns::SetAttr;

pub const BLOCK: usize = 4096;
const SECTORS_PER_BLOCK: u64 = (BLOCK / 512) as u64;
const BLOCKS_PER_GROUP: u32 = 32768;
const INODES_PER_GROUP: u32 = 2048;
const INODE_SIZE: usize = 256;
pub const ROOT: u32 = 2;
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

const S_IFMT: u16 = 0xF000;
const EXT4_EXTENTS_FL: u32 = 0x80000;
/// A hash-indexed directory (dir_index): read as a plain one, and made one when changed.
const EXT4_INDEX_FL: u32 = 0x1000;
/// The most links an inode takes (a directory: subdirectories + 2).
const MAX_LINKS: u16 = 65000;

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
    /// Not for this kind of inode, or a directory into itself.
    Invalid,
    TooManyLinks,
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

/// What an inode is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    CharDev,
    BlockDev,
    Fifo,
    Socket,
}

impl Kind {
    fn from_mode(mode: u16) -> Option<Kind> {
        Some(match mode & S_IFMT {
            0x8000 => Kind::File,
            0x4000 => Kind::Dir,
            0xA000 => Kind::Symlink,
            0x2000 => Kind::CharDev,
            0x6000 => Kind::BlockDev,
            0x1000 => Kind::Fifo,
            0xC000 => Kind::Socket,
            _ => return None,
        })
    }
    fn ifmt(self) -> u16 {
        match self {
            Kind::File => 0x8000,
            Kind::Dir => 0x4000,
            Kind::Symlink => 0xA000,
            Kind::CharDev => 0x2000,
            Kind::BlockDev => 0x6000,
            Kind::Fifo => 0x1000,
            Kind::Socket => 0xC000,
        }
    }
    /// The directory entry's file type.
    fn ft(self) -> u8 {
        match self {
            Kind::File => 1,
            Kind::Dir => 2,
            Kind::CharDev => 3,
            Kind::BlockDev => 4,
            Kind::Fifo => 5,
            Kind::Socket => 6,
            Kind::Symlink => 7,
        }
    }
    pub fn from_ft(ft: u8) -> Option<Kind> {
        Some(match ft {
            1 => Kind::File,
            2 => Kind::Dir,
            3 => Kind::CharDev,
            4 => Kind::BlockDev,
            5 => Kind::Fifo,
            6 => Kind::Socket,
            7 => Kind::Symlink,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stat {
    pub ino: u32,
    pub kind: Kind,
    /// permission bits (and setuid, setgid, sticky)
    pub mode: u16,
    pub links: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// space used, in 512-byte units
    pub blocks: u64,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    /// a device file's (major, minor)
    pub rdev: (u32, u32),
    pub dir: bool,
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
    /// Every changing call ends with `sync` (on by default).
    pub auto_sync: bool,
    cache: cache::Cache,
    /// the superblock or group descriptors changed since the last sync
    meta_dirty: bool,
    journal: Option<journal::Journal>,
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
    fn kind(&self) -> Option<Kind> {
        Kind::from_mode(self.mode())
    }
    fn is_dir(&self) -> bool {
        self.mode() & S_IFMT == 0x4000
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
    fn set_flags(&mut self, f: u32) {
        put32(&mut self.raw, 0x20, f);
    }
    fn has_extents(&self) -> bool {
        self.flags() & EXT4_EXTENTS_FL != 0
    }
    /// A symbolic link whose target is in the inode itself.
    fn fast_symlink(&self) -> bool {
        self.kind() == Some(Kind::Symlink) && !self.has_extents() && self.size() < 60
    }
    /// i_blocks in 512-byte units
    fn blocks512(&self) -> u64 {
        le32(&self.raw, 0x1C) as u64 | (le16(&self.raw, 0x74) as u64) << 32
    }
    fn set_blocks(&mut self, fs_blocks: u64) {
        let s = fs_blocks * SECTORS_PER_BLOCK;
        put32(&mut self.raw, 0x1C, s as u32);
        put16(&mut self.raw, 0x74, (s >> 32) as u16);
    }
    fn uid(&self) -> u32 {
        le16(&self.raw, 0x02) as u32 | (le16(&self.raw, 0x78) as u32) << 16
    }
    fn set_uid(&mut self, u: u32) {
        put16(&mut self.raw, 0x02, u as u16);
        put16(&mut self.raw, 0x78, (u >> 16) as u16);
    }
    fn gid(&self) -> u32 {
        le16(&self.raw, 0x18) as u32 | (le16(&self.raw, 0x7A) as u32) << 16
    }
    fn set_gid(&mut self, g: u32) {
        put16(&mut self.raw, 0x18, g as u16);
        put16(&mut self.raw, 0x7A, (g >> 16) as u16);
    }
    fn atime(&self) -> u32 {
        le32(&self.raw, 0x08)
    }
    fn mtime(&self) -> u32 {
        le32(&self.raw, 0x10)
    }
    fn ctime(&self) -> u32 {
        le32(&self.raw, 0x0C)
    }
    /// The nanosecond fields (in the extra part) are cleared: times are whole seconds.
    fn extra_times(&self) -> bool {
        self.raw.len() > 128 && le16(&self.raw, 0x80) >= 0x10
    }
    fn set_atime(&mut self, t: u32) {
        put32(&mut self.raw, 0x08, t);
        if self.extra_times() {
            put32(&mut self.raw, 0x8C, 0);
        }
    }
    fn set_mtime(&mut self, t: u32) {
        put32(&mut self.raw, 0x10, t);
        if self.extra_times() {
            put32(&mut self.raw, 0x88, 0);
        }
    }
    fn set_ctime(&mut self, t: u32) {
        put32(&mut self.raw, 0x0C, t);
        if self.extra_times() {
            put32(&mut self.raw, 0x84, 0);
        }
    }
    /// Contents changed: mtime and ctime.
    fn touch(&mut self, now: u32) {
        self.set_ctime(now);
        self.set_mtime(now);
    }
    fn rdev(&self) -> (u32, u32) {
        let (old, new) = (le32(&self.raw, 0x28), le32(&self.raw, 0x2C));
        if old != 0 {
            (old >> 8 & 0xFF, old & 0xFF)
        } else {
            (new >> 8 & 0xFFF, (new & 0xFF) | (new >> 12 & 0xFFF00))
        }
    }
    fn set_rdev(&mut self, (major, minor): (u32, u32)) {
        if major < 256 && minor < 256 {
            put32(&mut self.raw, 0x28, major << 8 | minor);
            put32(&mut self.raw, 0x2C, 0);
        } else {
            put32(&mut self.raw, 0x28, 0);
            put32(&mut self.raw, 0x2C, (minor & 0xFF) | (major & 0xFFF) << 8 | (minor & !0xFF) << 12);
        }
    }
    /// The extended attribute block (0: none).
    fn xattr_block(&self) -> u64 {
        le32(&self.raw, 0x68) as u64 | (le16(&self.raw, 0x76) as u64) << 32
    }
    fn stat(&self) -> Stat {
        let kind = self.kind().unwrap_or(Kind::File);
        Stat {
            ino: self.ino,
            kind,
            mode: self.mode() & 0o7777,
            links: self.links(),
            uid: self.uid(),
            gid: self.gid(),
            size: self.size(),
            blocks: self.blocks512(),
            atime: self.atime(),
            mtime: self.mtime(),
            ctime: self.ctime(),
            rdev: if matches!(kind, Kind::CharDev | Kind::BlockDev) { self.rdev() } else { (0, 0) },
            dir: kind == Kind::Dir,
        }
    }
}

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
            auto_sync: true,
            cache: cache::Cache::default(),
            meta_dirty: true,
            journal: None,
        };
        // bitmaps and empty inode tables (straight to the disk: nothing is cached yet)
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
        for (ino, parent, perm) in [(ROOT, ROOT, 0o755), (LOST_FOUND, ROOT, 0o700)] {
            if ino != ROOT {
                fs.mark_inode(v, ino, true, true)?;
            }
            let mut i = fs.blank_inode(ino, Kind::Dir, perm, 0, 0, now);
            fs.init_dir(v, &mut i, parent)?;
            fs.write_inode(v, &i)?;
        }
        fs.dir_add(v, ROOT, LOST_FOUND, "lost+found", Kind::Dir, now)?;
        fs.adjust_links(v, ROOT, 1, now)?;
        // the root's inode was in use already (reserved): count it as a directory here
        fs.groups[0].used_dirs += 1;
        fs.make_journal(v, &uuid, now)?;
        fs.sync(v)?;
        fs.write_meta(v, true)?;
        Ok(fs)
    }

    // ------------------------------------------------------------ mount

    pub fn mount(v: &mut Vol) -> R<Fs> {
        let mut fs = Self::parse(v, None)?;
        if le32(&fs.sb, 0x5C) & COMPAT_HAS_JOURNAL != 0 {
            let replayed = le32(&fs.sb, 0x60) & INCOMPAT_RECOVER != 0;
            fs.open_journal(v, true)?;
            if replayed {
                // the superblock and descriptors as the log left them
                let again = Self::parse(v, Some(&mut fs))?;
                fs.sb = again.sb;
                fs.groups = again.groups;
            }
            if fs.writable {
                // until close: what is on the disk may need the log
                fs.set_recover(v, true)?;
            }
        }
        Ok(fs)
    }

    /// The superblock and group descriptors (through `cached`'s cache when given).
    fn parse(v: &mut Vol, mut cached: Option<&mut Fs>) -> R<Fs> {
        let mut read = |b: u64, out: &mut [u8]| -> R<()> {
            match cached.as_deref_mut() {
                Some(fs) => {
                    for (k, c) in out.chunks_mut(BLOCK).enumerate() {
                        c.copy_from_slice(fs.mread(v, b + k as u64)?);
                    }
                    Ok(())
                }
                None => v.read(b, out),
            }
        };
        let mut first = vec![0u8; BLOCK];
        read(0, &mut first)?;
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
        let bit64 = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if bit64 { (le16(&sb, 0xFE) as usize).max(32) } else { 32 };
        let blocks = le32(&sb, 0x04) as u64 | if bit64 { (le32(&sb, 0x150) as u64) << 32 } else { 0 };
        let bpg = le32(&sb, 0x20);
        let ipg = le32(&sb, 0x28);
        let first_data_block = le32(&sb, 0x14) as u64;
        let inode_size = if le32(&sb, 0x4C) >= 1 { le16(&sb, 0x58) as usize } else { 128 };
        if bpg == 0 || ipg == 0 || blocks <= first_data_block {
            return Err(Error::Corrupt("bad superblock"));
        }
        let ngroups = (blocks - first_data_block).div_ceil(bpg as u64) as usize;
        let gdt_blocks = (ngroups * desc_size).div_ceil(BLOCK);
        let mut gdt = vec![0u8; gdt_blocks * BLOCK];
        read(first_data_block + 1, &mut gdt)?;
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
        // writable only with what this code keeps up (the journal may say otherwise)
        let writable = (incompat & !INCOMPAT_RECOVER) & !INCOMPAT_WRITABLE == 0 && ro & !RO_WRITABLE == 0 && !bit64;
        Ok(Fs {
            sb,
            groups,
            blocks,
            blocks_per_group: bpg,
            inodes_per_group: ipg,
            inode_size,
            desc_size,
            first_data_block,
            writable,
            auto_sync: true,
            cache: cache::Cache::default(),
            meta_dirty: false,
            journal: None,
        })
    }

    /// Everything to the disk, and the file system marked clean (it is
    /// still usable; the next change marks it again).
    pub fn close(&mut self, v: &mut Vol) -> R<()> {
        // first everything else, then the flag on its own: Linux replays a
        // log only with the flag set, so it must not go before the rest is home
        self.sync(v)?;
        if self.writable && self.journal.is_some() {
            self.set_recover(v, false)?;
        }
        Ok(())
    }

    /// The needs_recovery flag, straight into the superblock (the log is
    /// empty when it changes; the superblock is in the first sectors of
    /// block 0, so it lands whole or not at all).
    fn set_recover(&mut self, v: &mut Vol, on: bool) -> R<()> {
        let f = le32(&self.sb, 0x60);
        let f = if on { f | INCOMPAT_RECOVER } else { f & !INCOMPAT_RECOVER };
        put32(&mut self.sb, 0x60, f);
        let mut b0 = v.block(0)?;
        put32(&mut b0, 1024 + 0x60, f);
        v.write(0, &b0)?;
        self.forget(0, 1);
        Ok(())
    }

    /// (total, free) bytes.
    pub fn usage(&self) -> (u64, u64) {
        (self.blocks * BLOCK as u64, self.groups.iter().map(|g| g.free_blocks as u64).sum::<u64>() * BLOCK as u64)
    }

    // ------------------------------------------------------------ metadata

    /// The superblock (in block 0) and the group descriptors into the cache,
    /// to go out with the rest at sync.
    fn render_meta(&mut self, v: &mut Vol) -> R<()> {
        let free_blocks: u64 = self.groups.iter().map(|g| g.free_blocks as u64).sum();
        let free_inodes: u32 = self.groups.iter().map(|g| g.free_inodes).sum();
        put32(&mut self.sb, 0x0C, free_blocks as u32);
        put32(&mut self.sb, 0x10, free_inodes);
        let gdt = self.gdt();
        let mut sb = self.sb.clone();
        put16(&mut sb, 0x5A, 0);
        let off = if self.first_data_block == 0 { 1024 } else { 0 };
        let b0 = self.mread(v, self.first_data_block)?;
        if b0[off..off + 1024] != sb[..] {
            self.mmod(v, self.first_data_block)?[off..off + 1024].copy_from_slice(&sb);
        }
        for (k, blk) in gdt.chunks(BLOCK).enumerate() {
            self.mset(v, self.first_data_block + 1 + k as u64, blk)?;
        }
        self.meta_dirty = false;
        Ok(())
    }

    fn gdt(&self) -> Vec<u8> {
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
        gdt
    }

    /// Group descriptors and the superblock to disk (`backups`: also the copies).
    fn write_meta(&mut self, v: &mut Vol, backups: bool) -> R<()> {
        let free_blocks: u64 = self.groups.iter().map(|g| g.free_blocks as u64).sum();
        let free_inodes: u32 = self.groups.iter().map(|g| g.free_inodes).sum();
        put32(&mut self.sb, 0x0C, free_blocks as u32);
        put32(&mut self.sb, 0x10, free_inodes);
        let gdt = self.gdt();
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
        self.meta_dirty = false;
        Ok(())
    }

    fn group_of_ino(&self, ino: u32) -> usize {
        ((ino - 1) / self.inodes_per_group) as usize
    }

    fn group_first_block(&self, g: usize) -> u64 {
        self.first_data_block + g as u64 * self.blocks_per_group as u64
    }

    fn inode_loc(&self, ino: u32) -> (u64, usize) {
        let i = (ino - 1) as usize;
        let g = i / self.inodes_per_group as usize;
        let idx = i % self.inodes_per_group as usize;
        let byte = idx * self.inode_size;
        (self.groups[g].inode_table + (byte / BLOCK) as u64, byte % BLOCK)
    }

    fn read_inode(&mut self, v: &mut Vol, ino: u32) -> R<Inode> {
        if ino == 0 || ino as usize > self.groups.len() * self.inodes_per_group as usize {
            return Err(Error::Corrupt("inode number out of range"));
        }
        let (b, off) = self.inode_loc(ino);
        let size = self.inode_size;
        let blk = self.mread(v, b)?;
        Ok(Inode { ino, raw: blk[off..off + size].to_vec() })
    }

    fn write_inode(&mut self, v: &mut Vol, i: &Inode) -> R<()> {
        let (b, off) = self.inode_loc(i.ino);
        let size = self.inode_size;
        self.mmod(v, b)?[off..off + size].copy_from_slice(&i.raw);
        Ok(())
    }

    /// A new inode's fields (not yet written): no links, no blocks.
    fn blank_inode(&self, ino: u32, kind: Kind, perm: u16, uid: u32, gid: u32, now: u32) -> Inode {
        let mut i = Inode { ino, raw: vec![0u8; self.inode_size] };
        put16(&mut i.raw, 0, kind.ifmt() | (perm & 0o7777));
        if self.inode_size > 128 {
            put16(&mut i.raw, 0x80, 32);
            put32(&mut i.raw, 0x90, now); // creation time
        }
        i.set_uid(uid);
        i.set_gid(gid);
        i.set_atime(now);
        i.touch(now);
        if matches!(kind, Kind::File | Kind::Dir) {
            i.set_flags(EXT4_EXTENTS_FL);
            extent::empty_root(&mut i);
        }
        i
    }

    /// Mark an inode used or free in its bitmap (and the group's counts).
    fn mark_inode(&mut self, v: &mut Vol, ino: u32, used: bool, dir: bool) -> R<()> {
        let i = (ino - 1) as usize;
        let g = i / self.inodes_per_group as usize;
        let bit = i % self.inodes_per_group as usize;
        let bm = self.mmod(v, self.groups[g].inode_bitmap)?;
        let was = bm[bit / 8] & (1 << (bit % 8)) != 0;
        if used {
            bm[bit / 8] |= 1 << (bit % 8);
        } else {
            bm[bit / 8] &= !(1 << (bit % 8));
        }
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
        self.meta_dirty = true;
        Ok(())
    }

    /// A free inode, looking from group `near` on.
    fn alloc_inode(&mut self, v: &mut Vol, dir: bool, near: usize) -> R<u32> {
        let n = self.groups.len();
        for k in 0..n {
            let g = (near + k) % n;
            if self.groups[g].free_inodes == 0 {
                continue;
            }
            let ipg = self.inodes_per_group as usize;
            let bm = self.mread(v, self.groups[g].inode_bitmap)?;
            let found = (0..ipg).find(|&bit| bm[bit / 8] & (1 << (bit % 8)) == 0 && (g * ipg + bit + 1) as u32 >= FIRST_INO);
            if let Some(bit) = found {
                let ino = (g * ipg + bit + 1) as u32;
                self.mark_inode(v, ino, true, dir)?;
                return Ok(ino);
            }
        }
        Err(Error::Full)
    }

    /// Up to `want` blocks in one run (fewer if no run is that long), looking
    /// from block `goal` on: (count, first block).
    fn alloc_blocks(&mut self, v: &mut Vol, want: u32, goal: u64) -> R<(u32, u64)> {
        let n = self.groups.len();
        let bpg = self.blocks_per_group as usize;
        let goal = if goal < self.first_data_block || goal >= self.blocks { self.first_data_block } else { goal };
        let g0 = ((goal - self.first_data_block) / bpg as u64) as usize;
        let b0 = ((goal - self.first_data_block) % bpg as u64) as usize;
        let mut best: Option<(usize, usize, u32)> = None; // (group, first bit, len)
        // the goal's group from the goal, the others, then the goal's group before the goal
        for k in 0..=n {
            let g = (g0 + k) % n;
            let (from, to) = match k {
                0 => (b0, bpg),
                _ if k == n => (0, b0),
                _ => (0, bpg),
            };
            if self.groups[g].free_blocks == 0 || from >= to {
                continue;
            }
            let bm = self.mread(v, self.groups[g].block_bitmap)?;
            let mut run_start = None;
            let mut bit = from;
            while bit <= to {
                // whole bytes in use are skipped
                if run_start.is_none() && bit % 8 == 0 && bit + 8 <= to && bm[bit / 8] == 0xFF {
                    bit += 8;
                    continue;
                }
                let used = bit == to || bm[bit / 8] & (1 << (bit % 8)) != 0;
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
                    (false, Some(s)) if (bit - s) as u32 >= want => return self.take(v, g, s, want),
                    _ => {}
                }
                bit += 1;
            }
        }
        match best {
            Some((g, s, len)) if len > 0 => self.take(v, g, s, len.min(want)),
            _ => Err(Error::Full),
        }
    }

    fn take(&mut self, v: &mut Vol, g: usize, first_bit: usize, len: u32) -> R<(u32, u64)> {
        let bm = self.mmod(v, self.groups[g].block_bitmap)?;
        for b in first_bit..first_bit + len as usize {
            bm[b / 8] |= 1 << (b % 8);
        }
        self.groups[g].free_blocks -= len;
        self.meta_dirty = true;
        Ok((len, self.group_first_block(g) + first_bit as u64))
    }

    fn free_blocks(&mut self, v: &mut Vol, first: u64, len: u64) -> R<()> {
        self.forget(first, len);
        let mut b = first;
        while b < first + len {
            let rel = b - self.first_data_block;
            let g = (rel / self.blocks_per_group as u64) as usize;
            let bit = (rel % self.blocks_per_group as u64) as usize;
            let n = (first + len - b).min((self.blocks_per_group as usize - bit) as u64) as usize;
            let bm = self.mmod(v, self.groups[g].block_bitmap)?;
            for k in bit..bit + n {
                bm[k / 8] &= !(1 << (k % 8));
            }
            self.groups[g].free_blocks += n as u32;
            b += n as u64;
        }
        self.meta_dirty = true;
        Ok(())
    }

    /// An inode's blocks and itself back to the free space (no links left).
    fn release(&mut self, v: &mut Vol, ino: u32, now: u32) -> R<()> {
        let mut i = self.read_inode(v, ino)?;
        let dir = i.is_dir();
        if i.has_extents() {
            for e in self.runs(v, &i)? {
                self.free_blocks(v, e.p, e.n as u64)?;
            }
            for t in self.tree_blocks(v, &i)? {
                self.free_blocks(v, t, 1)?;
            }
        } else if !i.fast_symlink() && i.blocks512() != 0 && !matches!(i.kind(), Some(Kind::CharDev | Kind::BlockDev | Kind::Fifo | Kind::Socket)) {
            return Err(Error::Corrupt("a file without extents (old block maps are not supported)"));
        }
        // an extended attribute block: shared by reference count
        let xb = i.xattr_block();
        if xb != 0 {
            let blk = self.mmod(v, xb)?;
            let refs = le32(blk, 4);
            if refs <= 1 {
                self.free_blocks(v, xb, 1)?;
            } else {
                put32(blk, 4, refs - 1);
            }
        }
        i.set_links(0);
        put32(&mut i.raw, 0x14, now); // dtime
        self.write_inode(v, &i)?;
        self.mark_inode(v, ino, false, dir)
    }

    /// One more or one fewer link to an inode; with none left it is released.
    fn adjust_links(&mut self, v: &mut Vol, ino: u32, delta: i32, now: u32) -> R<()> {
        let mut i = self.read_inode(v, ino)?;
        let n = i.links() as i32 + delta;
        if n > MAX_LINKS as i32 {
            return Err(Error::TooManyLinks);
        }
        i.set_links(n.max(0) as u16);
        i.set_ctime(now);
        self.write_inode(v, &i)?;
        if n <= 0 {
            self.release(v, ino, now)?;
        }
        Ok(())
    }

    /// Run a changing call: refused when read only, synced after (even when
    /// it failed half way: what it did is kept consistent).
    fn change<T>(&mut self, v: &mut Vol, f: impl FnOnce(&mut Fs, &mut Vol) -> R<T>) -> R<T> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let r = f(self, v);
        // without auto_sync, still before the changes outgrow the log
        let big = self.journal.as_ref().is_some_and(|j| self.cache.dirty_count() * 4 > j.len() as usize);
        let s = if self.auto_sync || big { self.sync(v) } else { Ok(()) };
        let t = r?;
        s?;
        Ok(t)
    }
}

#[cfg(test)]
mod tests;
