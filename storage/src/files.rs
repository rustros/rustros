//! Files on the files partition (1 GiB to the end of the disk): each one a
//! run of whole sectors, found through an index entry in the key-value
//! store (`sys/files/<owner>/<name>` → first sector, sectors, bytes,
//! SHA-256). The data is written first and the entry last, so a crash in
//! between loses only the file being written; free space is worked out
//! from the entries at every open, so nothing leaks.

use alloc::string::String;
use alloc::vec::Vec;

use devices::BlockDevice;
use kvstore::Store;

const PREFIX: &str = "sys/files/";
/// One file is at most this (it is handed over whole).
pub const MAX_FILE: usize = 64 << 20;

#[derive(Debug, PartialEq)]
pub enum Error {
    TooLarge,
    Full,
    Io,
    BadName,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Entry {
    pub first: u64,
    pub sectors: u64,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

impl Entry {
    fn encode(&self) -> [u8; 56] {
        let mut b = [0u8; 56];
        b[..8].copy_from_slice(&self.first.to_le_bytes());
        b[8..16].copy_from_slice(&self.sectors.to_le_bytes());
        b[16..24].copy_from_slice(&self.bytes.to_le_bytes());
        b[24..56].copy_from_slice(&self.sha256);
        b
    }

    fn decode(b: &[u8]) -> Option<Entry> {
        if b.len() < 56 {
            return None;
        }
        let n = |i: usize| u64::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]]);
        Some(Entry { first: n(0), sectors: n(8), bytes: n(16), sha256: b[24..56].try_into().ok()? })
    }
}

pub struct Files {
    sectors: u64,
    /// free runs (first, sectors), sorted
    free: Vec<(u64, u64)>,
}

fn key(owner: &str, name: &str) -> Option<String> {
    let ok = |s: &str| !s.is_empty() && !s.contains('\0') && !s.split('/').any(|p| p.is_empty() || p == "." || p == "..");
    (ok(owner) && !owner.contains('/') && ok(name) && PREFIX.len() + owner.len() + 1 + name.len() <= kvstore::MAX_KEY).then(|| alloc::format!("{PREFIX}{owner}/{name}"))
}

impl Files {
    /// The files on `[start, start + sectors)`, as the store's index says.
    pub fn open(store: &Store, start: u64, sectors: u64) -> Files {
        let mut used: Vec<(u64, u64)> = store.keys(PREFIX).filter_map(|k| Entry::decode(store.get(k)?)).map(|e| (e.first, e.sectors)).collect();
        used.sort_unstable();
        let mut free = Vec::new();
        let mut at = start;
        for (f, n) in used {
            if f > at {
                free.push((at, f - at));
            }
            at = at.max(f + n);
        }
        if at < start + sectors {
            free.push((at, start + sectors - at));
        }
        Files { sectors, free }
    }

    /// (total, used) bytes.
    pub fn usage(&self) -> (u64, u64) {
        let free: u64 = self.free.iter().map(|f| f.1).sum();
        (self.sectors * 512, (self.sectors - free) * 512)
    }

    fn alloc(&mut self, n: u64) -> Option<u64> {
        let i = self.free.iter().position(|f| f.1 >= n)?;
        let first = self.free[i].0;
        if self.free[i].1 == n {
            self.free.remove(i);
        } else {
            self.free[i] = (first + n, self.free[i].1 - n);
        }
        Some(first)
    }

    fn release(&mut self, first: u64, n: u64) {
        if n == 0 {
            return;
        }
        let i = self.free.partition_point(|f| f.0 < first);
        self.free.insert(i, (first, n));
        // merge with neighbours
        if i + 1 < self.free.len() && self.free[i].0 + self.free[i].1 == self.free[i + 1].0 {
            self.free[i].1 += self.free[i + 1].1;
            self.free.remove(i + 1);
        }
        if i > 0 && self.free[i - 1].0 + self.free[i - 1].1 == self.free[i].0 {
            self.free[i - 1].1 += self.free[i].1;
            self.free.remove(i);
        }
    }

    pub fn stat(&self, store: &Store, owner: &str, name: &str) -> Option<Entry> {
        Entry::decode(store.get(&key(owner, name)?)?)
    }

    pub fn put(&mut self, disk: &mut dyn BlockDevice, store: &mut Store, owner: &str, name: &str, data: &[u8], sha256: [u8; 32]) -> Result<(), Error> {
        let k = key(owner, name).ok_or(Error::BadName)?;
        if data.len() > MAX_FILE {
            return Err(Error::TooLarge);
        }
        let n = (data.len() as u64).div_ceil(512);
        let first = if n == 0 { 0 } else { self.alloc(n).ok_or(Error::Full)? };
        if n > 0 {
            let whole = data.len() / 512 * 512;
            let ok = (whole == 0 || disk.write(first, &data[..whole])) && (whole == data.len() || {
                let mut last = [0u8; 512];
                last[..data.len() - whole].copy_from_slice(&data[whole..]);
                disk.write(first + whole as u64 / 512, &last)
            });
            if !ok {
                self.release(first, n);
                return Err(Error::Io);
            }
        }
        let old = store.get(&k).and_then(Entry::decode);
        let e = Entry { first, sectors: n, bytes: data.len() as u64, sha256 };
        if store.put(disk, &k, &e.encode()).is_err() {
            self.release(first, n);
            return Err(Error::Io);
        }
        if let Some(o) = old {
            self.release(o.first, o.sectors);
        }
        Ok(())
    }

    /// Bytes from `offset` into `buf`: how many (0 at the end); None if no such file.
    pub fn read(&self, disk: &mut dyn BlockDevice, store: &Store, owner: &str, name: &str, offset: u64, buf: &mut [u8]) -> Option<usize> {
        let e = self.stat(store, owner, name)?;
        if offset >= e.bytes || buf.is_empty() {
            return Some(0);
        }
        let n = (buf.len() as u64).min(e.bytes - offset) as usize;
        let s0 = offset / 512;
        let s1 = (offset + n as u64).div_ceil(512);
        let mut tmp = alloc::vec![0u8; ((s1 - s0) * 512) as usize];
        if !disk.read(e.first + s0, &mut tmp) {
            return None;
        }
        let skip = (offset - s0 * 512) as usize;
        buf[..n].copy_from_slice(&tmp[skip..skip + n]);
        Some(n)
    }

    pub fn delete(&mut self, disk: &mut dyn BlockDevice, store: &mut Store, owner: &str, name: &str) -> bool {
        let Some(k) = key(owner, name) else { return false };
        let Some(e) = store.get(&k).and_then(Entry::decode) else { return false };
        if store.delete(disk, &k).unwrap_or(false) {
            self.release(e.first, e.sectors);
            true
        } else {
            false
        }
    }

    /// (name, bytes) of `owner`'s files under `prefix`.
    pub fn list(&self, store: &Store, owner: &str, prefix: &str) -> Vec<(String, u64)> {
        let base = alloc::format!("{PREFIX}{owner}/");
        let p = alloc::format!("{base}{prefix}");
        store.keys(&p).filter_map(|k| Some((String::from(&k[base.len()..]), Entry::decode(store.get(k)?)?.bytes))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// A sparse disk: sectors never written read as zeros.
    struct Sparse(BTreeMap<u64, [u8; 512]>, u64);
    impl BlockDevice for Sparse {
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
            for (i, c) in buf.chunks_mut(512).enumerate() {
                c.copy_from_slice(&self.0.get(&(lba + i as u64)).copied().unwrap_or([0; 512])[..c.len()]);
            }
            lba + (buf.len() as u64).div_ceil(512) <= self.1
        }
        fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
            for (i, c) in buf.chunks(512).enumerate() {
                let mut s = [0u8; 512];
                s[..c.len()].copy_from_slice(c);
                self.0.insert(lba + i as u64, s);
            }
            lba + (buf.len() as u64).div_ceil(512) <= self.1
        }
        fn sectors(&self) -> u64 {
            self.1
        }
    }

    const START: u64 = 100_000;
    const SECTORS: u64 = 64;

    fn data(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn put_read_overwrite_delete_reopen() {
        let mut disk = Sparse(BTreeMap::new(), 200_000);
        let mut store = Store::open(&mut disk, 0, 4096, 7).unwrap();
        let mut f = Files::open(&store, START, SECTORS);
        assert_eq!(f.usage(), (SECTORS * 512, 0));
        let a = data(5000, 1);
        f.put(&mut disk, &mut store, "www", "site/index.html", &a, [1; 32]).unwrap();
        let mut b = vec![0u8; 6000];
        assert_eq!(f.read(&mut disk, &store, "www", "site/index.html", 0, &mut b), Some(5000));
        assert_eq!(&b[..5000], &a[..]);
        // a slice from the middle, across sector boundaries
        let mut m = [0u8; 700];
        assert_eq!(f.read(&mut disk, &store, "www", "site/index.html", 1000, &mut m), Some(700));
        assert_eq!(&m[..], &a[1000..1700]);
        assert_eq!(f.read(&mut disk, &store, "www", "site/index.html", 5000, &mut m), Some(0));
        assert_eq!(f.stat(&store, "www", "site/index.html").map(|e| (e.bytes, e.sectors)), Some((5000, 10)));
        // owners are apart
        assert_eq!(f.read(&mut disk, &store, "other", "site/index.html", 0, &mut m), None);
        // overwrite: the old space comes back
        let c = data(512 * 20, 2);
        f.put(&mut disk, &mut store, "www", "site/index.html", &c, [2; 32]).unwrap();
        assert_eq!(f.usage().1, 20 * 512);
        f.put(&mut disk, &mut store, "www", "repo/x.mod", &data(100, 3), [3; 32]).unwrap();
        f.put(&mut disk, &mut store, "www", "empty", &[], [0; 32]).unwrap();
        let mut names: Vec<String> = f.list(&store, "www", "").into_iter().map(|x| x.0).collect();
        names.sort();
        assert_eq!(names, ["empty", "repo/x.mod", "site/index.html"]);
        assert_eq!(f.list(&store, "www", "repo/").len(), 1);
        // too big for what is left
        assert_eq!(f.put(&mut disk, &mut store, "www", "big", &data(512 * 50, 4), [0; 32]), Err(Error::Full));
        assert!(f.delete(&mut disk, &mut store, "www", "site/index.html"));
        assert!(!f.delete(&mut disk, &mut store, "www", "site/index.html"));
        // reopened: free space from the index
        let mut store = Store::open(&mut disk, 0, 4096, 7).unwrap();
        let f2 = Files::open(&store, START, SECTORS);
        assert_eq!(f2.usage().1, 512);
        let mut f2 = f2;
        f2.put(&mut disk, &mut store, "www", "big", &data(512 * 60, 5), [5; 32]).unwrap();
        let mut back = vec![0u8; 512 * 60];
        assert_eq!(f2.read(&mut disk, &store, "www", "big", 0, &mut back), Some(512 * 60));
        assert_eq!(back, data(512 * 60, 5));
        // names that would escape
        for bad in ["", "/x", "a//b", "../x", "a/./b"] {
            assert_eq!(f2.put(&mut disk, &mut store, "www", bad, b"x", [0; 32]), Err(Error::BadName), "{bad}");
        }
    }
}
