use super::*;
use std::collections::BTreeMap as Model;

/// In-memory disk that can "lose power": once the write budget is used up,
/// the failing write lands only a random subset of its sectors.
struct Disk {
    data: Vec<u8>,
    budget: Option<usize>,
    rng: u64,
    dead: bool,
}

impl Disk {
    fn new(sectors: usize) -> Disk {
        // start with garbage to make sure nothing relies on zeroed disks
        let mut d = Disk { data: vec![0; sectors * SECTOR], budget: None, rng: 0x9E37_79B9_7F4A_7C15, dead: false };
        for i in 0..d.data.len() {
            d.data[i] = d.rand() as u8;
        }
        d
    }
    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }
}

impl BlockDevice for Disk {
    fn sectors(&self) -> u64 {
        (self.data.len() / SECTOR) as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let o = lba as usize * SECTOR;
        if self.dead || o + buf.len() > self.data.len() {
            return false;
        }
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        true
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        let o = lba as usize * SECTOR;
        assert!(o + buf.len() <= self.data.len(), "write past end");
        assert!(buf.len() % SECTOR == 0);
        if self.dead {
            return false;
        }
        let n = buf.len() / SECTOR;
        if let Some(b) = self.budget {
            if b < n {
                // power loss: a random subset of sectors reaches the disk
                for i in 0..n {
                    if self.rand() % 2 == 0 {
                        let s = o + i * SECTOR;
                        self.data[s..s + SECTOR].copy_from_slice(&buf[i * SECTOR..(i + 1) * SECTOR]);
                    }
                }
                self.dead = true;
                return false;
            }
            self.budget = Some(b - n);
        }
        self.data[o..o + buf.len()].copy_from_slice(buf);
        true
    }
}

fn contents(s: &Store) -> Model<String, Vec<u8>> {
    s.keys("").map(|k| (k.to_string(), s.get(k).unwrap().to_vec())).collect()
}

#[test]
fn crc_known_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn basic_and_reopen() {
    let mut d = Disk::new(64);
    let mut s = Store::open(&mut d, 0, 64, 1).unwrap();
    assert!(s.get("a").is_none());
    s.put(&mut d, "app/a", b"1").unwrap();
    s.put(&mut d, "app/b", b"hello").unwrap();
    s.put(&mut d, "other/c", b"x").unwrap();
    s.put(&mut d, "app/a", b"2").unwrap();
    assert!(s.delete(&mut d, "other/c").unwrap());
    assert!(!s.delete(&mut d, "other/c").unwrap());
    assert_eq!(s.keys("app/").collect::<Vec<_>>(), ["app/a", "app/b"]);
    let s2 = Store::open(&mut d, 0, 64, 2).unwrap();
    assert_eq!(contents(&s2), contents(&s));
    assert_eq!(s2.get("app/a"), Some(&b"2"[..]));
    assert!(s2.get("other/c").is_none());
}

#[test]
fn limits() {
    let mut d = Disk::new(64);
    let mut s = Store::open(&mut d, 0, 64, 1).unwrap();
    assert_eq!(s.put(&mut d, "", b"x"), Err(Error::TooLarge));
    assert_eq!(s.put(&mut d, &"k".repeat(MAX_KEY + 1), b"x"), Err(Error::TooLarge));
    // 32-sector halves cannot hold a 20 KB value
    assert_eq!(s.put(&mut d, "big", &[7; 20_000]), Err(Error::Full));
    assert!(s.get("big").is_none());
    assert!(matches!(Store::open(&mut d, 0, 8, 1), Err(Error::TooSmall)));
}

#[test]
fn compaction_keeps_data() {
    let mut d = Disk::new(64);
    let mut s = Store::open(&mut d, 0, 64, 1).unwrap();
    for i in 0..1000u32 {
        let k = format!("k{}", i % 7);
        s.put(&mut d, &k, &i.to_le_bytes()).unwrap();
    }
    let want = contents(&s);
    assert_eq!(want.len(), 7);
    let s2 = Store::open(&mut d, 0, 64, 9).unwrap();
    assert_eq!(contents(&s2), want);
}

#[test]
fn store_inside_a_partition() {
    // the store must stay within [start, start + sectors)
    let mut d = Disk::new(300);
    let guard: Vec<u8> = d.data[..100 * SECTOR].to_vec();
    let tail: Vec<u8> = d.data[200 * SECTOR..].to_vec();
    let mut s = Store::open(&mut d, 100, 100, 1).unwrap();
    for i in 0..500u32 {
        s.put(&mut d, &format!("k{}", i % 5), &[i as u8; 300]).unwrap();
    }
    assert_eq!(&d.data[..100 * SECTOR], &guard[..]);
    assert_eq!(&d.data[200 * SECTOR..], &tail[..]);
}

/// Random operations with a power cut at a random point; after reopening,
/// everything acknowledged must be there and the interrupted operation must
/// be either fully applied or not at all.
#[test]
fn power_loss() {
    for seed in 1..3000u64 {
        let sectors = 48;
        let mut d = Disk::new(sectors);
        d.rng ^= seed.wrapping_mul(0x1234_5678_9ABC);
        let mut s = Store::open(&mut d, 0, sectors as u64, seed).unwrap();
        let mut model: Model<String, Vec<u8>> = Model::new();
        // warm up without failures, then arm the power cut
        let mut rng = seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let warm = next() % 50;
        let mut pending: Option<(String, Option<Vec<u8>>)> = None;
        for op in 0..300u64 {
            if op == warm {
                d.budget = Some((next() % 40) as usize);
            }
            let key = format!("key{}", next() % 6);
            let r = if next() % 4 == 0 {
                let r = s.delete(&mut d, &key).map(|_| ());
                (r, None)
            } else {
                let len = (next() % 900) as usize;
                let v: Vec<u8> = (0..len).map(|i| (i as u64 ^ op) as u8).collect();
                (s.put(&mut d, &key, &v), Some(v))
            };
            match r {
                (Ok(()), v) => match v {
                    Some(v) => {
                        model.insert(key, v);
                    }
                    None => {
                        model.remove(&key);
                    }
                },
                (Err(Error::Full), _) => {}
                (Err(Error::Io), v) => {
                    pending = Some((key, v));
                    break;
                }
                (Err(e), _) => panic!("seed {seed}: unexpected {e:?}"),
            }
        }
        d.dead = false;
        d.budget = None;
        let s2 = Store::open(&mut d, 0, sectors as u64, seed + 1000).unwrap();
        let got = contents(&s2);
        let mut with_pending = model.clone();
        if let Some((k, v)) = pending {
            match v {
                Some(v) => {
                    with_pending.insert(k, v);
                }
                None => {
                    with_pending.remove(&k);
                }
            }
        }
        assert!(got == model || got == with_pending, "seed {seed}: store does not match before/after the cut");
        // and it keeps working afterwards
        let mut s2 = s2;
        s2.put(&mut d, "after", b"ok").unwrap();
        let s3 = Store::open(&mut d, 0, sectors as u64, seed + 2000).unwrap();
        assert_eq!(s3.get("after"), Some(&b"ok"[..]));
    }
}

/// Reopen after every write, across several compactions.
#[test]
fn reopen_after_every_write() {
    let mut d = Disk::new(64);
    let mut s = Store::open(&mut d, 0, 64, 1).unwrap();
    for i in 0..200u32 {
        let k = format!("k{}", i % 7);
        s.put(&mut d, &k, &i.to_le_bytes()).unwrap();
        let s2 = Store::open(&mut d, 0, 64, 9).unwrap();
        if contents(&s2) != contents(&s) {
            panic!("diverged at i={i}: active={} gen={} tail={} | reopened active={} gen={} tail={}", s.active, s.generation, s.tail, s2.active, s2.generation, s2.tail);
        }
    }
}
