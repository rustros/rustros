use super::*;
use std::collections::BTreeMap;

/// A sparse disk: sectors never written read as zeros.
#[derive(Clone)]
pub struct Sparse {
    pub sectors: BTreeMap<u64, [u8; 512]>,
    pub size: u64,
}

impl BlockDevice for Sparse {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        if lba + (buf.len() as u64).div_ceil(512) > self.size {
            return false;
        }
        for (i, c) in buf.chunks_mut(512).enumerate() {
            c.copy_from_slice(&self.sectors.get(&(lba + i as u64)).copied().unwrap_or([0; 512])[..c.len()]);
        }
        true
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        if lba + (buf.len() as u64).div_ceil(512) > self.size {
            return false;
        }
        for (i, c) in buf.chunks(512).enumerate() {
            let mut s = [0u8; 512];
            s[..c.len()].copy_from_slice(c);
            if s.iter().all(|&b| b == 0) {
                self.sectors.remove(&(lba + i as u64));
            } else {
                self.sectors.insert(lba + i as u64, s);
            }
        }
        true
    }
    fn sectors(&self) -> u64 {
        self.size
    }
}

impl Sparse {
    pub fn new(mib: u64) -> Sparse {
        Sparse { sectors: BTreeMap::new(), size: mib * 2048 }
    }

    /// Write it out as a (sparse) image file.
    pub fn save(&self, path: &str) {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(path).unwrap();
        f.set_len(self.size * 512).unwrap();
        for (lba, s) in &self.sectors {
            f.seek(SeekFrom::Start(lba * 512)).unwrap();
            f.write_all(s).unwrap();
        }
    }

    pub fn load(path: &str) -> Sparse {
        let data = std::fs::read(path).unwrap();
        let mut d = Sparse { sectors: BTreeMap::new(), size: data.len() as u64 / 512 };
        for (i, c) in data.chunks(512).enumerate() {
            if c.iter().any(|&b| b != 0) {
                d.sectors.insert(i as u64, c.try_into().unwrap());
            }
        }
        d
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1] ^ seed).collect()
}

const NOW: u32 = 1_760_000_000;

/// The files the tests leave, for e2fsck and debugfs.
pub fn populate(fs: &mut Fs, v: &mut Vol) {
    fs.write_file(v, "site/index.html", b"<h1>RustROS</h1>\n", NOW).unwrap();
    fs.write_file(v, "site/releases/2026.10.22.1/rustros.elf", &pattern(193_824, 1), NOW).unwrap();
    fs.write_file(v, "site/releases/latest.json", b"{\"format\":1}", NOW).unwrap();
    fs.write_file(v, "empty", b"", NOW).unwrap();
    fs.mkdir_p(v, "panel/cache/a/b", NOW).unwrap();
    for i in 0..300 {
        fs.write_file(v, &format!("many/file-{i:04}.txt"), format!("file {i}\n").as_bytes(), NOW).unwrap();
    }
    for i in (0..300).step_by(3) {
        assert!(fs.remove(v, &format!("many/file-{i:04}.txt"), NOW).unwrap());
    }
    // what a POSIX system makes
    let px = fs.mkdir(v, ROOT, "posix", 0o750, 1000, 1000, NOW).unwrap();
    let data = fs.create(v, px, "data", Kind::File, 0o640, 1000, 1000, (0, 0), NOW).unwrap();
    fs.pwrite(v, data, 0, &pattern(50_000, 2), NOW).unwrap();
    fs.pwrite(v, data, 10_000, b"overwritten in the middle", NOW).unwrap();
    fs.link(v, data, px, "data.link", NOW).unwrap();
    fs.symlink(v, px, "short", "data", 1000, 1000, NOW).unwrap();
    fs.symlink(v, px, "long", &"long/".repeat(30), 1000, 1000, NOW).unwrap();
    fs.create(v, px, "fifo", Kind::Fifo, 0o600, 0, 0, (0, 0), NOW).unwrap();
    fs.create(v, px, "null", Kind::CharDev, 0o666, 0, 0, (1, 3), NOW).unwrap();
    let sparse = fs.create(v, px, "sparse", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    fs.pwrite(v, sparse, 100 << 20, b"end", NOW).unwrap();
    fs.pwrite(v, sparse, 5000, b"start", NOW).unwrap();
    let shrunk = fs.create(v, px, "shrunk", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    fs.pwrite(v, shrunk, 0, &pattern(300_000, 4), NOW).unwrap();
    fs.truncate(v, shrunk, 12_345, NOW).unwrap();
    let old = fs.mkdir(v, px, "old", 0o755, 0, 0, NOW).unwrap();
    fs.mkdir(v, old, "sub", 0o755, 0, 0, NOW).unwrap();
    fs.rename(v, px, "old", px, "new", NOW).unwrap();
    fs.rename(v, old, "sub", px, "sub", NOW).unwrap();
    fs.setattr(v, data, SetAttr { mode: Some(0o600), uid: Some(70000), ..Default::default() }, NOW).unwrap();
    // a fragmented file: a tree two levels deep
    let (a, b) = (fs.create(v, px, "deep", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap(), fs.create(v, px, "deep.other", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap());
    fs.auto_sync = false;
    for k in 0..1500u64 {
        fs.pwrite(v, a, k * 4096, &pattern(4096, k as u8), NOW).unwrap();
        fs.pwrite(v, b, k * 4096, &[7u8; 4096], NOW).unwrap();
    }
    fs.auto_sync = true;
    fs.sync(v).unwrap();
}

#[test]
fn format_write_read_remove() {
    let mut d = Sparse::new(512);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 512 * 2048, [7; 16], "files", NOW).unwrap();
    let (total, free0) = fs.usage();
    assert_eq!(total, 512 << 20);
    let names: Vec<String> = fs.list(&mut v, "/").unwrap().into_iter().map(|x| x.0).collect();
    assert_eq!(names, ["lost+found"]);

    let big = pattern(5_000_000, 9);
    fs.write_file(&mut v, "a/b/c.bin", &big, NOW).unwrap();
    let st = fs.stat(&mut v, "a/b/c.bin").unwrap();
    assert_eq!((st.size, st.dir), (5_000_000, false));
    let mut back = vec![0u8; 5_000_000];
    assert_eq!(fs.read(&mut v, "a/b/c.bin", 0, &mut back).unwrap(), 5_000_000);
    assert!(back == big);
    let mut mid = vec![0u8; 10_000];
    assert_eq!(fs.read(&mut v, "a/b/c.bin", 123_457, &mut mid).unwrap(), 10_000);
    assert_eq!(&mid[..], &big[123_457..133_457]);
    assert_eq!(fs.read(&mut v, "a/b/c.bin", 5_000_000, &mut mid).unwrap(), 0);
    assert!(fs.stat(&mut v, "a/b").unwrap().dir);
    assert_eq!(fs.read(&mut v, "a/b", 0, &mut mid), Err(Error::IsADirectory));
    assert_eq!(fs.stat(&mut v, "a/nope"), Err(Error::NotFound));
    assert_eq!(fs.write_file(&mut v, "a/../x", b"x", NOW), Err(Error::BadName));

    // replaced: the old blocks come back
    fs.write_file(&mut v, "a/b/c.bin", b"short", NOW).unwrap();
    let mut s = [0u8; 16];
    assert_eq!(fs.read(&mut v, "a/b/c.bin", 0, &mut s).unwrap(), 5);
    assert_eq!(&s[..5], b"short");
    assert_eq!(fs.remove(&mut v, "a", NOW), Err(Error::NotEmpty));
    assert!(fs.remove(&mut v, "a/b/c.bin", NOW).unwrap());
    assert!(!fs.remove(&mut v, "a/b/c.bin", NOW).unwrap());
    assert!(fs.remove(&mut v, "a/b", NOW).unwrap());
    assert!(fs.remove(&mut v, "a", NOW).unwrap());
    assert_eq!(fs.usage().1, free0, "everything given back");

    // remounted: the same
    populate(&mut fs, &mut v);
    let free1 = fs.usage().1;
    let mut fs2 = Fs::mount(&mut v).unwrap();
    assert!(fs2.writable);
    assert_eq!(fs2.usage().1, free1);
    let mut k = vec![0u8; 193_824];
    assert_eq!(fs2.read(&mut v, "site/releases/2026.10.22.1/rustros.elf", 0, &mut k).unwrap(), 193_824);
    assert_eq!(k, pattern(193_824, 1));
    assert_eq!(fs2.list(&mut v, "many").unwrap().len(), 200);
}

#[test]
fn fragmented_file_gets_an_extent_tree() {
    // small enough that blocks run out before inodes
    let mut d = Sparse::new(6);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 6 * 2048, [8; 16], "frag", NOW).unwrap();
    // fill the disk with 1-block files, free every other one: only 1-block holes
    let mut n = 0;
    while fs.write_file(&mut v, &format!("fill/{n}"), &[1u8; 4096], NOW).is_ok() {
        n += 1;
    }
    for i in (0..n).step_by(2) {
        fs.remove(&mut v, &format!("fill/{i}"), NOW).unwrap();
    }
    let data = pattern(4096 * 40, 3); // 40 runs: needs a leaf block
    fs.write_file(&mut v, "frag.bin", &data, NOW).unwrap();
    let mut back = vec![0u8; data.len()];
    assert_eq!(fs.read(&mut v, "frag.bin", 0, &mut back).unwrap(), data.len());
    assert!(back == data);
    let ino = fs.resolve(&mut v, "frag.bin").unwrap();
    let i = fs.read_inode(&mut v, ino).unwrap();
    let runs = fs.runs(&mut v, &i).unwrap();
    let depth = le16(&i.raw[0x28..], 6);
    println!("{} runs, depth {depth}", runs.len());
    assert!(runs.len() > 4 && depth == 1, "{} runs at depth {depth}", runs.len());
    let free = fs.usage().1;
    fs.remove(&mut v, "frag.bin", NOW).unwrap();
    assert_eq!(fs.usage().1, free + 41 * 4096, "data and the leaf block freed");
}

/// For the checks with Linux's tools: EXT4_OUT=<file> writes an image.
#[test]
fn image_for_e2fsck() {
    let Ok(out) = std::env::var("EXT4_OUT") else { return };
    let mut d = Sparse::new(1100);
    {
        let mut v = Vol { dev: &mut d, start: 0 };
        let mut fs = Fs::format(&mut v, 1100 * 2048, [9; 16], "rustros", NOW).unwrap();
        populate(&mut fs, &mut v);
        fs.close(&mut v).unwrap();
    }
    d.save(&out);
}

/// EXT4_IN=<file>: read one Linux made (its files listed by the caller).
#[test]
fn read_linux_made() {
    let Ok(path) = std::env::var("EXT4_IN") else { return };
    let mut d = Sparse::load(&path);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::mount(&mut v).unwrap();
    println!("writable: {}", fs.writable);
    fn walk(fs: &mut Fs, v: &mut Vol, dir: &str) {
        for (name, st) in fs.list(v, dir).unwrap() {
            let p = format!("{dir}/{name}");
            if st.dir {
                walk(fs, v, &p);
            } else {
                let mut b = vec![0u8; st.size as usize];
                fs.read(v, &p, 0, &mut b).unwrap();
                let mut h: u64 = 0xcbf29ce484222325;
                for x in &b {
                    h = (h ^ *x as u64).wrapping_mul(0x100000001b3);
                }
                println!("FILE {p} {} {h:016x}", st.size);
            }
        }
    }
    walk(&mut fs, &mut v, "");
    if fs.writable {
        fs.write_file(&mut v, "from-rustros.txt", b"written by RustROS\n", NOW).unwrap();
        // the hash-indexed directory: changed, it becomes a plain one
        fs.write_file(&mut v, "many/new-from-rustros", b"new\n", NOW).unwrap();
        assert!(fs.remove(&mut v, "many/f1", NOW).unwrap());
        fs.write_file(&mut v, "a/big.bin", b"replaced\n", NOW).unwrap();
        fs.mkdir_p(&mut v, "made/by/rustros", NOW).unwrap();
        // the inode calls on what Linux made
        let v = &mut v;
        let many = fs.resolve(v, "many").unwrap();
        let f2 = fs.lookup(v, many, "f2").unwrap().unwrap();
        fs.pwrite(v, f2, 1000, b"past the end", NOW).unwrap();
        let a = fs.resolve(v, "a").unwrap();
        fs.rename(v, many, "f3", a, "f3-moved", NOW).unwrap();
        fs.link(v, f2, a, "f2-link", NOW).unwrap();
        fs.symlink(v, a, "to-f2", "../many/f2", 0, 0, NOW).unwrap();
        let deep = fs.resolve(v, "a/deep").unwrap();
        fs.rename(v, a, "deep", ROOT, "deep-moved", NOW).unwrap();
        assert_eq!(fs.lookup(v, deep, "..").unwrap(), Some(ROOT));
        fs.close(v).unwrap();
        d.save(&path);
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn whole(fs: &mut Fs, v: &mut Vol, ino: u32) -> Vec<u8> {
    let st = fs.getattr(v, ino).unwrap();
    let mut b = vec![0u8; st.size as usize];
    assert_eq!(fs.pread(v, ino, 0, &mut b).unwrap(), b.len());
    b
}

#[test]
fn pwrite_truncate_against_a_model() {
    let mut d = Sparse::new(256);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 256 * 2048, [3; 16], "model", NOW).unwrap();
    let free0 = fs.usage().1;
    let ino = fs.create(&mut v, ROOT, "db", Kind::File, 0o600, 70, 70, (0, 0), NOW).unwrap();
    let mut model: Vec<u8> = Vec::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for step in 0..600 {
        match rng.below(10) {
            0 => {
                let len = rng.below(3 << 20);
                fs.truncate(&mut v, ino, len, NOW + step).unwrap();
                model.resize(len as usize, 0);
            }
            1..=2 => {
                // far past the end: a hole
                let off = model.len() as u64 + rng.below(1 << 20);
                let data = pattern(1 + rng.below(20_000) as usize, step as u8);
                fs.pwrite(&mut v, ino, off, &data, NOW).unwrap();
                model.resize(model.len().max(off as usize + data.len()), 0);
                model[off as usize..off as usize + data.len()].copy_from_slice(&data);
            }
            _ => {
                let off = rng.below(model.len() as u64 + 1);
                let data = pattern(1 + rng.below(70_000) as usize, step as u8 ^ 0x5A);
                fs.pwrite(&mut v, ino, off, &data, NOW).unwrap();
                model.resize(model.len().max(off as usize + data.len()), 0);
                model[off as usize..off as usize + data.len()].copy_from_slice(&data);
            }
        }
        if step % 50 == 0 {
            assert!(whole(&mut fs, &mut v, ino) == model, "step {step}");
            let off = rng.below(model.len() as u64 + 1);
            let mut b = vec![0u8; 5000];
            let n = fs.pread(&mut v, ino, off, &mut b).unwrap();
            assert_eq!(&b[..n], &model[off as usize..(off as usize + 5000).min(model.len())]);
        }
    }
    assert!(whole(&mut fs, &mut v, ino) == model);
    let st = fs.getattr(&mut v, ino).unwrap();
    assert_eq!((st.uid, st.gid, st.mode, st.kind), (70, 70, 0o600, Kind::File));
    let mut fs = Fs::mount(&mut v).unwrap();
    assert!(whole(&mut fs, &mut v, ino) == model, "after remount");
    fs.unlink(&mut v, ROOT, "db", NOW).unwrap();
    assert_eq!(fs.usage().1, free0, "everything given back");
}

#[test]
fn deep_extent_tree() {
    let mut d = Sparse::new(128);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 128 * 2048, [4; 16], "deep", NOW).unwrap();
    let free0 = fs.usage().1;
    fs.auto_sync = false;
    // two files written a block each in turn: every run one block long
    let a = fs.create(&mut v, ROOT, "a", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    let b = fs.create(&mut v, ROOT, "b", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    let blocks = 2000u64;
    for k in 0..blocks {
        fs.pwrite(&mut v, a, k * 4096, &pattern(4096, k as u8), NOW).unwrap();
        fs.pwrite(&mut v, b, k * 4096, &[0xBB; 4096], NOW).unwrap();
    }
    fs.sync(&mut v).unwrap();
    let i = fs.read_inode(&mut v, a).unwrap();
    let runs = fs.runs(&mut v, &i).unwrap();
    let depth = le16(&i.raw[0x28..], 6);
    println!("{} runs, depth {depth}, {} tree blocks", runs.len(), fs.tree_blocks(&mut v, &i).unwrap().len());
    assert!(runs.len() >= 1500 && depth == 2, "{} runs at depth {depth}", runs.len());
    let mut fs = Fs::mount(&mut v).unwrap();
    let data = whole(&mut fs, &mut v, a);
    for k in 0..blocks as usize {
        assert!(data[k * 4096..(k + 1) * 4096] == pattern(4096, k as u8)[..], "block {k}");
    }
    // shrunk: the tree gets small again
    fs.truncate(&mut v, a, 3 * 4096, NOW).unwrap();
    let i = fs.read_inode(&mut v, a).unwrap();
    assert_eq!(le16(&i.raw[0x28..], 6), 0);
    assert_eq!(fs.getattr(&mut v, a).unwrap().blocks, 3 * 8);
    fs.unlink(&mut v, ROOT, "a", NOW).unwrap();
    fs.unlink(&mut v, ROOT, "b", NOW).unwrap();
    assert_eq!(fs.usage().1, free0, "data and tree blocks freed");
}

#[test]
fn unwritten_extents_read_as_zeros() {
    let mut d = Sparse::new(64);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 64 * 2048, [5; 16], "uninit", NOW).unwrap();
    let ino = fs.create(&mut v, ROOT, "f", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    // as fallocate leaves them: 8 blocks allocated, unwritten, with old data on the disk
    let (n, p) = fs.alloc_blocks(&mut v, 8, 0).unwrap();
    assert_eq!(n, 8);
    v.write(p, &vec![0xEE; 8 * 4096]).unwrap();
    let mut i = fs.read_inode(&mut v, ino).unwrap();
    fs.set_runs(&mut v, &mut i, &[extent::Ext { l: 0, p, n: 8, uninit: true }]).unwrap();
    i.set_size(8 * 4096);
    fs.write_inode(&mut v, &i).unwrap();
    fs.sync(&mut v).unwrap();
    assert!(whole(&mut fs, &mut v, ino).iter().all(|&x| x == 0), "unwritten reads as zeros");
    fs.pwrite(&mut v, ino, 3 * 4096 + 100, b"hello", NOW).unwrap();
    let data = whole(&mut fs, &mut v, ino);
    assert_eq!(&data[3 * 4096 + 100..3 * 4096 + 105], b"hello");
    assert!(data.iter().enumerate().all(|(k, &x)| (3 * 4096 + 100..3 * 4096 + 105).contains(&k) || x == 0), "the rest still zeros");
    let i = fs.read_inode(&mut v, ino).unwrap();
    let runs = fs.runs(&mut v, &i).unwrap();
    assert_eq!(runs.iter().map(|e| (e.n, e.uninit)).collect::<Vec<_>>(), [(3, true), (1, false), (4, true)]);
    assert!(runs.iter().all(|e| e.p >= p && e.p < p + 8), "written in place");
}

#[test]
fn names_links_and_renames() {
    let mut d = Sparse::new(64);
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::format(&mut v, 64 * 2048, [6; 16], "names", NOW).unwrap();
    let free0 = (fs.usage().1, fs.groups[0].free_inodes, fs.groups[0].used_dirs);
    let v = &mut v;
    let a = fs.mkdir(v, ROOT, "a", 0o750, 1, 2, NOW).unwrap();
    let b = fs.mkdir(v, a, "b", 0o755, 0, 0, NOW).unwrap();
    assert_eq!(fs.getattr(v, ROOT).unwrap().links, 4); // ".", "..", lost+found, a
    assert_eq!(fs.getattr(v, a).unwrap().links, 3);
    assert_eq!(fs.mkdir(v, a, "b", 0o755, 0, 0, NOW), Err(Error::Exists));

    // hard links
    let f = fs.create(v, a, "f", Kind::File, 0o640, 0, 0, (0, 0), NOW).unwrap();
    fs.pwrite(v, f, 0, b"contents", NOW).unwrap();
    fs.link(v, f, b, "f2", NOW).unwrap();
    assert_eq!(fs.getattr(v, f).unwrap().links, 2);
    assert_eq!(fs.link(v, a, b, "dirlink", NOW), Err(Error::Invalid));
    fs.unlink(v, a, "f", NOW).unwrap();
    assert_eq!(fs.getattr(v, f).unwrap().links, 1);
    assert_eq!(whole(&mut fs, v, f), b"contents");

    // symbolic links, in the inode and in a block
    let s1 = fs.symlink(v, ROOT, "short", "a/b/f2", 0, 0, NOW).unwrap();
    let long = "x/".repeat(100);
    let s2 = fs.symlink(v, ROOT, "long", &long, 0, 0, NOW).unwrap();
    assert_eq!(fs.readlink(v, s1).unwrap(), b"a/b/f2");
    assert_eq!(fs.readlink(v, s2).unwrap(), long.as_bytes());
    assert_eq!(fs.getattr(v, s2).unwrap().blocks, 8);
    assert_eq!(fs.pread(v, s1, 0, &mut [0u8; 4]), Err(Error::Invalid));

    // special files
    let fifo = fs.create(v, ROOT, "fifo", Kind::Fifo, 0o600, 0, 0, (0, 0), NOW).unwrap();
    let null = fs.create(v, ROOT, "null", Kind::CharDev, 0o666, 0, 0, (1, 3), NOW).unwrap();
    let big = fs.create(v, ROOT, "bigdev", Kind::BlockDev, 0o600, 0, 0, (259, 70000), NOW).unwrap();
    assert_eq!(fs.getattr(v, fifo).unwrap().kind, Kind::Fifo);
    assert_eq!(fs.getattr(v, null).unwrap().rdev, (1, 3));
    assert_eq!(fs.getattr(v, big).unwrap().rdev, (259, 70000));

    // renames
    fs.rename(v, b, "f2", ROOT, "moved", NOW).unwrap();
    assert_eq!(fs.lookup(v, ROOT, "moved").unwrap(), Some(f));
    assert_eq!(fs.lookup(v, b, "f2").unwrap(), None);
    let g = fs.create(v, ROOT, "g", Kind::File, 0o644, 0, 0, (0, 0), NOW).unwrap();
    fs.pwrite(v, g, 0, &pattern(100_000, 1), NOW).unwrap();
    let before = fs.usage().1;
    fs.rename(v, ROOT, "g", ROOT, "moved", NOW).unwrap(); // replaces: f's last link goes
    assert_eq!(fs.lookup(v, ROOT, "moved").unwrap(), Some(g));
    assert_eq!(fs.usage().1, before + 4096, "the replaced file's block freed");
    assert_eq!(fs.rename(v, ROOT, "a", b, "inside", NOW), Err(Error::Invalid), "a directory into itself");
    let c = fs.mkdir(v, ROOT, "c", 0o755, 0, 0, NOW).unwrap();
    fs.rename(v, a, "b", c, "b", NOW).unwrap(); // a directory to another parent
    assert_eq!(fs.lookup(v, b, "..").unwrap(), Some(c));
    assert_eq!((fs.getattr(v, a).unwrap().links, fs.getattr(v, c).unwrap().links), (2, 3));
    assert_eq!(fs.rename(v, ROOT, "c", ROOT, "a", NOW), Ok(()), "over an empty directory");
    assert_eq!(fs.lookup(v, ROOT, "a").unwrap(), Some(c));
    assert_eq!(fs.getattr(v, ROOT).unwrap().links, 4);
    assert_eq!(fs.rename(v, ROOT, "moved", ROOT, "a", NOW), Err(Error::IsADirectory));
    assert_eq!(fs.rmdir(v, ROOT, "a", NOW), Err(Error::NotEmpty));
    assert_eq!(fs.unlink(v, ROOT, "a", NOW), Err(Error::IsADirectory));

    // attributes
    fs.setattr(v, g, SetAttr { mode: Some(0o4755), uid: Some(100_000), gid: Some(5), mtime: Some(12345), size: Some(10), ..Default::default() }, NOW + 9).unwrap();
    let st = fs.getattr(v, g).unwrap();
    assert_eq!((st.mode, st.uid, st.gid, st.mtime, st.ctime, st.size, st.kind), (0o4755, 100_000, 5, 12345, NOW + 9, 10, Kind::File));

    // all of it removed: back to the start
    for n in ["short", "long", "fifo", "null", "bigdev", "moved"] {
        fs.unlink(v, ROOT, n, NOW).unwrap();
    }
    fs.rmdir(v, c, "b", NOW).unwrap();
    fs.rmdir(v, ROOT, "a", NOW).unwrap();
    assert_eq!(fs.readdir(v, ROOT).unwrap().len(), 3);
    assert_eq!((fs.usage().1, fs.groups[0].free_inodes, fs.groups[0].used_dirs), free0);
    assert_eq!(fs.getattr(v, ROOT).unwrap().links, 3);
}

/// A disk losing power at its `left`-th write: that one lands half, none after.
struct Cut<'a> {
    disk: &'a mut Sparse,
    left: usize,
    writes: usize,
}

impl BlockDevice for Cut<'_> {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.disk.read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        self.writes += 1;
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        if self.left == 0 {
            let half = (buf.len() / 512 / 2 * 512).max(512).min(buf.len());
            self.disk.write(lba, &buf[..half]);
            return false;
        }
        self.disk.write(lba, buf)
    }
    fn sectors(&self) -> u64 {
        self.disk.size
    }
}

/// A small fsck: the tree from the root against the bitmaps and counts.
pub fn check(fs: &mut Fs, v: &mut Vol) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut refs: BTreeMap<u32, u32> = BTreeMap::new();
    let mut subdirs: BTreeMap<u32, u32> = BTreeMap::new();
    let mut todo = vec![(ROOT, ROOT)];
    let mut seen_dirs = BTreeSet::new();
    while let Some((dir, parent)) = todo.pop() {
        if !seen_dirs.insert(dir) {
            return Err(format!("directory {dir} reached twice"));
        }
        let es = fs.readdir(v, dir).map_err(|e| format!("readdir {dir}: {e:?}"))?;
        let dot = es.iter().find(|e| e.0 == ".").map(|e| e.1);
        let dotdot = es.iter().find(|e| e.0 == "..").map(|e| e.1);
        if dot != Some(dir) || dotdot != Some(parent) {
            return Err(format!("directory {dir}: . {dot:?} .. {dotdot:?} (parent {parent})"));
        }
        for (name, ino, kind) in es {
            if name == "." || name == ".." {
                continue;
            }
            let st = fs.getattr(v, ino).map_err(|e| format!("{name}: {e:?}"))?;
            if kind != Some(st.kind) {
                return Err(format!("{name}: entry says {kind:?}, inode {:?}", st.kind));
            }
            *refs.entry(ino).or_default() += 1;
            if st.kind == Kind::Dir {
                *subdirs.entry(dir).or_default() += 1;
                todo.push((ino, dir));
            }
        }
    }
    let mut used_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut claim = |b: u64, what: &str| -> Result<(), String> { if used_blocks.insert(b) { Ok(()) } else { Err(format!("block {b} used twice ({what})")) } };
    // the file system's own blocks
    let gdt_blocks = (fs.groups.len() * fs.desc_size).div_ceil(BLOCK) as u64;
    for g in 0..fs.groups.len() {
        let first = fs.group_first_block(g);
        if has_super(g as u32) {
            for b in first..first + 1 + gdt_blocks {
                claim(b, "superblock")?;
            }
        }
        let gr = fs.groups[g];
        claim(gr.block_bitmap, "bitmap")?;
        claim(gr.inode_bitmap, "bitmap")?;
        for b in gr.inode_table..gr.inode_table + (fs.inodes_per_group as u64 * fs.inode_size as u64).div_ceil(BLOCK as u64) {
            claim(b, "inode table")?;
        }
    }
    let mut inodes: Vec<u32> = refs.keys().copied().collect();
    inodes.push(ROOT);
    if fs.journal.is_some() {
        inodes.push(8);
    }
    for &ino in &inodes {
        let i = fs.read_inode(v, ino).unwrap();
        let st = i.stat();
        let want = if st.kind == Kind::Dir { 2 + subdirs.get(&ino).copied().unwrap_or(0) } else if ino == 8 { 1 } else { refs[&ino] };
        if st.links as u32 != want {
            return Err(format!("inode {ino}: {} links, {want} found", st.links));
        }
        let runs = fs.runs(v, &i).map_err(|e| format!("inode {ino}: {e:?}"))?;
        let tree = fs.tree_blocks(v, &i).unwrap();
        let n: u64 = runs.iter().map(|e| e.n as u64).sum::<u64>() + tree.len() as u64;
        if n * 8 != st.blocks {
            return Err(format!("inode {ino}: i_blocks {} for {n} blocks", st.blocks));
        }
        for e in runs {
            for b in e.p..e.p + e.n as u64 {
                claim(b, "data")?;
            }
        }
        for b in tree {
            claim(b, "tree")?;
        }
    }
    let mut dirs_per_group = vec![0u32; fs.groups.len()];
    for &ino in &inodes {
        if fs.read_inode(v, ino).unwrap().is_dir() {
            dirs_per_group[fs.group_of_ino(ino)] += 1;
        }
    }
    let inode_set: BTreeSet<u32> = inodes.iter().copied().chain(1..=10).chain([11]).collect();
    for g in 0..fs.groups.len() {
        let gr = fs.groups[g];
        let first = fs.group_first_block(g);
        let len = (fs.blocks - first).min(fs.blocks_per_group as u64);
        let bm = fs.mread(v, gr.block_bitmap).unwrap().to_vec();
        let mut free = 0;
        for k in 0..len {
            let set = bm[k as usize / 8] & (1 << (k % 8)) != 0;
            if set != used_blocks.contains(&(first + k)) {
                return Err(format!("block {}: bitmap says {set}", first + k));
            }
            free += !set as u32;
        }
        if free != gr.free_blocks {
            return Err(format!("group {g}: {} free blocks counted, {free} in the bitmap", gr.free_blocks));
        }
        let ib = fs.mread(v, gr.inode_bitmap).unwrap().to_vec();
        let mut ifree = 0;
        for k in 0..fs.inodes_per_group {
            let ino = g as u32 * fs.inodes_per_group + k + 1;
            let set = ib[k as usize / 8] & (1 << (k % 8)) != 0;
            if set != inode_set.contains(&ino) {
                return Err(format!("inode {ino}: bitmap says {set}"));
            }
            ifree += !set as u32;
        }
        if ifree != gr.free_inodes || dirs_per_group[g] != gr.used_dirs {
            return Err(format!("group {g}: inodes free {} (bitmap {ifree}), dirs {} (found {})", gr.free_inodes, gr.used_dirs, dirs_per_group[g]));
        }
    }
    Ok(())
}

fn file_bytes(fs: &mut Fs, v: &mut Vol, path: &str) -> Option<Vec<u8>> {
    let ino = fs.resolve(v, path).ok()?;
    Some(whole(fs, v, ino))
}

/// The changes the crash test makes, one sync each.
fn crash_ops(fs: &mut Fs, v: &mut Vol) -> Result<(), Error> {
    fs.write_file(v, "replace", &pattern(20_000, 2), NOW)?;
    let d = fs.resolve(v, "d")?;
    fs.rename(v, ROOT, "keep", d, "kept", NOW)?;
    fs.mkdir_p(v, "d/e/f", NOW)?;
    let g = fs.resolve(v, "grow")?;
    for k in 0..6 {
        fs.pwrite(v, g, k * 9000, &pattern(9000, k as u8), NOW)?;
    }
    fs.unlink(v, ROOT, "gone", NOW)?;
    for k in 0..40 {
        fs.write_file(v, &format!("d/many/{k}"), b"x", NOW)?;
    }
    fs.close(v)
}

/// What Linux looks at before it replays: (the log holds something, needs_recovery set).
fn log_state(d: &mut Sparse) -> (bool, bool) {
    let mut v = Vol { dev: d, start: 0 };
    let mut fs = Fs::parse(&mut v, None).unwrap();
    let i = fs.read_inode(&mut v, 8).unwrap();
    let p = fs.runs(&mut v, &i).unwrap()[0].p;
    let jsb = v.block(p).unwrap();
    (u32::from_be_bytes(jsb[0x1C..0x20].try_into().unwrap()) != 0, le32(&fs.sb, 0x60) & INCOMPAT_RECOVER != 0)
}

#[test]
fn power_cut_at_every_write() {
    let mut base = Sparse::new(64);
    {
        let mut v = Vol { dev: &mut base, start: 0 };
        let mut fs = Fs::format(&mut v, 64 * 2048, [11; 16], "crash", NOW).unwrap();
        assert!(fs.journal.is_some());
        fs.write_file(&mut v, "replace", &pattern(50_000, 1), NOW).unwrap();
        fs.write_file(&mut v, "keep", b"kept", NOW).unwrap();
        fs.write_file(&mut v, "gone", &pattern(10_000, 3), NOW).unwrap();
        fs.write_file(&mut v, "grow", b"", NOW).unwrap();
        fs.mkdir_p(&mut v, "d", NOW).unwrap();
        fs.close(&mut v).unwrap();
    }
    // how many writes the changes take
    let total = {
        let mut d = base.clone();
        let mut cut = Cut { disk: &mut d, left: usize::MAX, writes: 0 };
        let mut v = Vol { dev: &mut cut, start: 0 };
        let mut fs = Fs::mount(&mut v).unwrap();
        crash_ops(&mut fs, &mut v).unwrap();
        cut.writes
    };
    println!("{total} writes");
    let mut outcomes = std::collections::BTreeSet::new();
    for n in 1..=total {
        let mut d = base.clone();
        {
            let mut cut = Cut { disk: &mut d, left: n, writes: 0 };
            let mut v = Vol { dev: &mut cut, start: 0 };
            // (the cut may come while mounting: it writes too)
            if let Ok(mut fs) = Fs::mount(&mut v) {
                assert!(crash_ops(&mut fs, &mut v).is_err() || n == total, "cut at {n}");
            }
        }
        let (pending, flagged) = log_state(&mut d);
        assert!(!pending || flagged, "cut at {n}: the log holds a transaction Linux would not replay");
        let mut v = Vol { dev: &mut d, start: 0 };
        let mut fs = Fs::mount(&mut v).unwrap_or_else(|e| panic!("cut at {n}: mount {e:?}"));
        check(&mut fs, &mut v).unwrap_or_else(|e| panic!("cut at {n}: {e}"));
        let r = file_bytes(&mut fs, &mut v, "replace").unwrap_or_else(|| panic!("cut at {n}: replace gone"));
        assert!(r == pattern(50_000, 1) || r == pattern(20_000, 2), "cut at {n}: replace is neither");
        let (old, new) = (file_bytes(&mut fs, &mut v, "keep"), file_bytes(&mut fs, &mut v, "d/kept"));
        assert!(old.is_some() != new.is_some(), "cut at {n}: keep in {} places", old.is_some() as u8 + new.is_some() as u8);
        let grow = file_bytes(&mut fs, &mut v, "grow").unwrap();
        let k = grow.len() / 9000;
        assert_eq!(grow.len() % 9000, 0, "cut at {n}: grow is {} long", grow.len());
        for j in 0..k {
            assert!(grow[j * 9000..(j + 1) * 9000] == pattern(9000, j as u8)[..], "cut at {n}: grow part {j}");
        }
        // and it goes on working
        fs.write_file(&mut v, "after", b"fine", NOW).unwrap();
        check(&mut fs, &mut v).unwrap_or_else(|e| panic!("cut at {n}, then a write: {e}"));
        outcomes.insert((r.len(), old.is_some(), k, file_bytes(&mut fs, &mut v, "gone").is_some(), fs.list(&mut v, "d/many").map(|l| l.len()).unwrap_or(0)));
    }
    println!("{} different states after the cuts", outcomes.len());
}

/// EXT4_CRASH_OUT=<dir>: images cut while a committed transaction was being
/// put in place (for e2fsck to replay).
#[test]
fn images_cut_after_commit() {
    let Ok(dir) = std::env::var("EXT4_CRASH_OUT") else { return };
    let mut base = Sparse::new(64);
    {
        let mut v = Vol { dev: &mut base, start: 0 };
        let mut fs = Fs::format(&mut v, 64 * 2048, [12; 16], "crash", NOW).unwrap();
        fs.write_file(&mut v, "replace", &pattern(50_000, 1), NOW).unwrap();
        fs.write_file(&mut v, "keep", b"kept", NOW).unwrap();
        fs.write_file(&mut v, "gone", &pattern(10_000, 3), NOW).unwrap();
        fs.write_file(&mut v, "grow", b"", NOW).unwrap();
        fs.mkdir_p(&mut v, "d", NOW).unwrap();
        fs.close(&mut v).unwrap();
    }
    let mut saved = 0;
    for n in 1..400 {
        let mut d = base.clone();
        {
            let mut cut = Cut { disk: &mut d, left: n, writes: 0 };
            let mut v = Vol { dev: &mut cut, start: 0 };
            if let Ok(mut fs) = Fs::mount(&mut v) {
                let _ = crash_ops(&mut fs, &mut v);
            }
        }
        // the journal's superblock says the log holds something
        let mut v = Vol { dev: &mut d, start: 0 };
        let fs = Fs::parse(&mut v, None).unwrap();
        let mut fs = fs;
        let i = fs.read_inode(&mut v, 8).unwrap();
        let p = fs.runs(&mut v, &i).unwrap()[0].p;
        let jsb = v.block(p).unwrap();
        if u32::from_be_bytes(jsb[0x1C..0x20].try_into().unwrap()) != 0 && n % 3 == 0 {
            d.save(&format!("{dir}/cut-{n}.img"));
            // what our own replay makes of it
            let mut v = Vol { dev: &mut d, start: 0 };
            let mut fs = Fs::mount(&mut v).unwrap();
            check(&mut fs, &mut v).unwrap();
            let mut names: Vec<String> = fs.list(&mut v, "/").unwrap().into_iter().map(|x| x.0).collect();
            names.extend(fs.list(&mut v, "d").unwrap().into_iter().map(|x| format!("d/{}", x.0)));
            names.sort();
            std::fs::write(format!("{dir}/cut-{n}.ours"), names.join("\n") + "\n").unwrap();
            saved += 1;
            if saved == 6 {
                break;
            }
        }
    }
    assert!(saved > 0);
}

/// EXT4_JIN=<dir>: l1.img (writable features) and l2.img (Linux's defaults),
/// each with a log debugfs wrote: blocks 7000-7001 "A", 7001-7002 "B",
/// 7002 revoked, 7003 "C" never committed.
#[test]
fn replay_linux_written_log() {
    let Ok(dir) = std::env::var("EXT4_JIN") else { return };
    let want = |b: u64| -> Vec<u8> {
        match b {
            7000 => vec![b'A'; 4096],
            7001 => vec![b'B'; 4096],
            _ => vec![0; 4096],
        }
    };
    // writable: replayed onto the disk, the log emptied
    let path = format!("{dir}/l1.img");
    let mut d = Sparse::load(&path);
    {
        let mut v = Vol { dev: &mut d, start: 0 };
        let mut fs = Fs::mount(&mut v).unwrap();
        assert!(fs.writable);
        for b in 7000..7004 {
            assert_eq!(v.block(b).unwrap(), want(b), "l1 block {b}");
        }
        fs.write_file(&mut v, "after-replay", b"ours\n", NOW).unwrap();
        fs.close(&mut v).unwrap();
    }
    assert_eq!(log_state(&mut d), (false, false));
    d.save(&path);
    // not ours to write: replayed in memory only, the disk untouched
    let path = format!("{dir}/l2.img");
    let mut d = Sparse::load(&path);
    let before = d.clone();
    let mut v = Vol { dev: &mut d, start: 0 };
    let mut fs = Fs::mount(&mut v).unwrap();
    assert!(!fs.writable);
    for b in 7000..7004 {
        assert_eq!(fs.mread(&mut v, b).unwrap(), &want(b)[..], "l2 block {b} as read");
    }
    assert!(fs.list(&mut v, "/").unwrap().iter().any(|e| e.0 == "lost+found"));
    assert_eq!(fs.write_file(&mut v, "x", b"x", NOW), Err(Error::ReadOnly));
    assert!(d.sectors == before.sectors, "l2 left as it was");
}

#[test]
fn journal_added_to_a_file_system_without_one() {
    let mut d = Sparse::new(64);
    let mut v = Vol { dev: &mut d, start: 0 };
    Fs::format(&mut v, 64 * 2048, [13; 16], "old", NOW).unwrap();
    // as the files partitions made before journals were: the journal taken out again
    let mut fs = Fs::mount(&mut v).unwrap();
    let i8 = fs.read_inode(&mut v, 8).unwrap();
    for e in fs.runs(&mut v, &i8).unwrap() {
        fs.free_blocks(&mut v, e.p, e.n as u64).unwrap();
    }
    fs.write_inode(&mut v, &Inode { ino: 8, raw: vec![0; 256] }).unwrap();
    fs.journal = None;
    let f = le32(&fs.sb, 0x5C) & !COMPAT_HAS_JOURNAL;
    put32(&mut fs.sb, 0x5C, f);
    let f = le32(&fs.sb, 0x60) & !INCOMPAT_RECOVER;
    put32(&mut fs.sb, 0x60, f);
    fs.meta_dirty = true;
    fs.sync(&mut v).unwrap();
    fs.write_file(&mut v, "before", b"no journal yet", NOW).unwrap();
    let mut fs = Fs::mount(&mut v).unwrap();
    assert!(!fs.has_journal());
    check(&mut fs, &mut v).unwrap();
    assert!(fs.add_journal(&mut v, NOW).unwrap());
    assert!(!fs.add_journal(&mut v, NOW).unwrap());
    fs.write_file(&mut v, "after", b"journaled", NOW).unwrap();
    fs.close(&mut v).unwrap();
    let mut fs = Fs::mount(&mut v).unwrap();
    assert!(fs.has_journal());
    check(&mut fs, &mut v).unwrap();
    assert_eq!(file_bytes(&mut fs, &mut v, "before").unwrap(), b"no journal yet");
    assert_eq!(file_bytes(&mut fs, &mut v, "after").unwrap(), b"journaled");
}
