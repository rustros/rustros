use super::*;
use std::collections::BTreeMap;

/// A sparse disk: sectors never written read as zeros.
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
    let fs2 = Fs::mount(&mut v).unwrap();
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
    let i = fs.resolve(&mut v, "frag.bin").unwrap();
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
    fn walk(fs: &Fs, v: &mut Vol, dir: &str) {
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
    walk(&fs, &mut v, "");
    if fs.writable {
        fs.write_file(&mut v, "from-rustros.txt", b"written by RustROS\n", NOW).unwrap();
        // the hash-indexed directory: changed, it becomes a plain one
        fs.write_file(&mut v, "many/new-from-rustros", b"new\n", NOW).unwrap();
        assert!(fs.remove(&mut v, "many/f1", NOW).unwrap());
        fs.write_file(&mut v, "a/big.bin", b"replaced\n", NOW).unwrap();
        fs.mkdir_p(&mut v, "made/by/rustros", NOW).unwrap();
        d.save(&path);
    }
}
