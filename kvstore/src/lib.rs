//! A small crash-safe key-value store on a raw block range.
//!
//! The range is split into two halves; one is active. Each half starts with a
//! header sector `{magic, generation, half size, salt, crc}` followed by an
//! append-only log of records, each starting on a sector boundary:
//!
//! ```text
//! magic "HKVR" | salt u64 | op u8 | key_len u16 | val_len u32 | crc32 u32 | key | value
//! ```
//!
//! On open, the half with the newest valid header is replayed into an
//! in-memory map; the log ends at the first record whose magic, salt or CRC
//! does not match. A torn write therefore loses at most the record being
//! written. When the active half is full, the live data is written to the
//! other half under generation + 1 and a fresh random salt, and its header is
//! written last, which is the commit point: a crash during compaction leaves
//! the old half in charge, and leftovers of an aborted compaction can never
//! match a later salt.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Bound;

pub use devices::{BlockDevice, SECTOR};
/// On-disk format identifier (existing stores carry it).
const HEADER_MAGIC: &[u8; 8] = b"HULLKV01";
const RECORD_MAGIC: &[u8; 4] = b"HKVR";
const RECORD_HDR: usize = 4 + 8 + 1 + 2 + 4 + 4;
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
/// Bytes read per request while replaying the log.
const READ_CHUNK: usize = 64 * 1024;

pub const MAX_KEY: usize = 255;
pub const MAX_VALUE: usize = 1 << 20;
/// Live data is kept in RAM; cap it.
pub const MAX_LIVE: usize = 16 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The device reported a failure.
    Io,
    /// Key or value too long.
    TooLarge,
    /// Not enough room even after compaction.
    Full,
    /// Region too small to hold a store.
    TooSmall,
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn sectors_for(bytes: usize) -> u64 {
    bytes.div_ceil(SECTOR) as u64
}

fn encode(salt: u64, op: u8, key: &str, value: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(RECORD_HDR + key.len() + value.len());
    r.extend_from_slice(RECORD_MAGIC);
    r.extend_from_slice(&salt.to_le_bytes());
    r.push(op);
    r.extend_from_slice(&(key.len() as u16).to_le_bytes());
    r.extend_from_slice(&(value.len() as u32).to_le_bytes());
    r.extend_from_slice(&[0; 4]);
    r.extend_from_slice(key.as_bytes());
    r.extend_from_slice(value);
    let crc = crc32(&[&r[..RECORD_HDR - 4], &r[RECORD_HDR..]].concat());
    r[RECORD_HDR - 4..RECORD_HDR].copy_from_slice(&crc.to_le_bytes());
    r.resize(sectors_for(r.len()) as usize * SECTOR, 0);
    r
}

fn header(generation: u64, half: u64, salt: u64) -> Vec<u8> {
    let mut h = vec![0u8; SECTOR];
    h[..8].copy_from_slice(HEADER_MAGIC);
    h[8..16].copy_from_slice(&generation.to_le_bytes());
    h[16..24].copy_from_slice(&half.to_le_bytes());
    h[24..32].copy_from_slice(&salt.to_le_bytes());
    let crc = crc32(&h[..32]);
    h[32..36].copy_from_slice(&crc.to_le_bytes());
    h
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// (generation, salt) of a valid header for a half of `half` sectors.
fn parse_header(h: &[u8], half: u64) -> Option<(u64, u64)> {
    if &h[..8] != HEADER_MAGIC || crc32(&h[..32]) != u32::from_le_bytes(h[32..36].try_into().ok()?) {
        return None;
    }
    (le64(&h[16..]) == half).then(|| (le64(&h[8..]), le64(&h[24..])))
}

pub struct Store {
    start: u64,
    /// sectors per half
    half: u64,
    active: usize,
    generation: u64,
    salt: u64,
    rng: u64,
    /// next free sector, relative to the active half
    tail: u64,
    map: BTreeMap<String, Vec<u8>>,
    live: usize,
}

impl Store {
    /// Open the store in `[start, start + sectors)`, formatting it if it holds
    /// no valid store. `seed` should differ between boots (e.g. a timestamp).
    pub fn open(dev: &mut dyn BlockDevice, start: u64, sectors: u64, seed: u64) -> Result<Store, Error> {
        let half = sectors / 2;
        if half < 8 {
            return Err(Error::TooSmall);
        }
        let mut best: Option<(usize, u64, u64)> = None;
        let mut h = vec![0u8; SECTOR];
        for i in 0..2 {
            if !dev.read(start + i as u64 * half, &mut h) {
                return Err(Error::Io);
            }
            if let Some((g, salt)) = parse_header(&h, half) {
                if best.is_none_or(|(_, bg, _)| g > bg) {
                    best = Some((i, g, salt));
                }
            }
        }
        let mut s = Store {
            start,
            half,
            active: 0,
            generation: 1,
            salt: 0,
            rng: seed | 1,
            tail: 1,
            map: BTreeMap::new(),
            live: 0,
        };
        match best {
            None => {
                s.salt = s.next_salt();
                if !dev.write(start, &header(1, half, s.salt)) {
                    return Err(Error::Io);
                }
            }
            Some((active, generation, salt)) => {
                s.active = active;
                s.generation = generation;
                s.salt = salt;
                s.replay(dev)?;
            }
        }
        Ok(s)
    }

    fn next_salt(&mut self) -> u64 {
        // xorshift64*, never 0
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1
    }

    fn base(&self, which: usize) -> u64 {
        self.start + which as u64 * self.half
    }

    /// Rebuild the map from the active half's log and find its end.
    fn replay(&mut self, dev: &mut dyn BlockDevice) -> Result<(), Error> {
        let base = self.base(self.active);
        let mut buf: Vec<u8> = Vec::new(); // bytes from sector `buf_at`
        let mut buf_at = 1u64;
        let mut pos = 1u64;
        loop {
            if pos >= self.half {
                break;
            }
            // make sure the record header is buffered
            let need = |len: usize, at: u64, buf: &Vec<u8>, buf_at: u64| {
                let off = (at - buf_at) as usize * SECTOR;
                at >= buf_at && off + len <= buf.len()
            };
            if !need(RECORD_HDR, pos, &buf, buf_at) {
                let n = (READ_CHUNK as u64 / SECTOR as u64).min(self.half - pos);
                buf = vec![0u8; n as usize * SECTOR];
                buf_at = pos;
                if !dev.read(base + pos, &mut buf) {
                    return Err(Error::Io);
                }
            }
            let off = (pos - buf_at) as usize * SECTOR;
            let r = &buf[off..off + RECORD_HDR];
            if &r[..4] != RECORD_MAGIC || le64(&r[4..]) != self.salt {
                break;
            }
            let op = r[12];
            let klen = u16::from_le_bytes([r[13], r[14]]) as usize;
            let vlen = u32::from_le_bytes(r[15..19].try_into().unwrap()) as usize;
            let crc = u32::from_le_bytes(r[19..23].try_into().unwrap());
            if klen > MAX_KEY || vlen > MAX_VALUE {
                break;
            }
            let total = RECORD_HDR + klen + vlen;
            let secs = sectors_for(total);
            if pos + secs > self.half {
                break;
            }
            if !need(total, pos, &buf, buf_at) {
                buf = vec![0u8; (secs as usize * SECTOR).max(READ_CHUNK.min((self.half - pos) as usize * SECTOR))];
                buf_at = pos;
                if !dev.read(base + pos, &mut buf) {
                    return Err(Error::Io);
                }
            }
            let off = (pos - buf_at) as usize * SECTOR;
            let rec = &buf[off..off + total];
            if crc32(&[&rec[..RECORD_HDR - 4], &rec[RECORD_HDR..]].concat()) != crc {
                break;
            }
            let Ok(key) = core::str::from_utf8(&rec[RECORD_HDR..RECORD_HDR + klen]) else { break };
            let value = &rec[RECORD_HDR + klen..];
            match op {
                OP_PUT => self.insert(String::from(key), value.to_vec()),
                OP_DELETE => self.remove(key),
                _ => break,
            }
            pos += secs;
        }
        self.tail = pos;
        Ok(())
    }

    fn insert(&mut self, key: String, value: Vec<u8>) {
        self.live += key.len() + value.len();
        if let Some(old) = self.map.insert(key.clone(), value) {
            self.live -= key.len() + old.len();
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(old) = self.map.remove(key) {
            self.live -= key.len() + old.len();
        }
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.map.get(key).map(|v| v.as_slice())
    }

    pub fn keys<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.map.range::<str, _>((Bound::Included(prefix), Bound::Unbounded)).map(|(k, _)| k.as_str()).take_while(move |k| k.starts_with(prefix))
    }

    /// (live bytes, used sectors in the active half, sectors per half)
    pub fn usage(&self) -> (usize, u64, u64) {
        (self.live, self.tail, self.half)
    }

    fn append(&mut self, dev: &mut dyn BlockDevice, op: u8, key: &str, value: &[u8]) -> Result<(), Error> {
        let secs = sectors_for(RECORD_HDR + key.len() + value.len());
        if self.tail + secs > self.half {
            self.compact(dev)?;
            if self.tail + secs > self.half {
                return Err(Error::Full);
            }
        }
        // encode only now: compaction changes the salt
        let rec = encode(self.salt, op, key, value);
        if !dev.write(self.base(self.active) + self.tail, &rec) {
            return Err(Error::Io);
        }
        self.tail += secs;
        Ok(())
    }

    pub fn put(&mut self, dev: &mut dyn BlockDevice, key: &str, value: &[u8]) -> Result<(), Error> {
        if key.is_empty() || key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return Err(Error::TooLarge);
        }
        let old = self.map.get(key).map_or(0, |v| key.len() + v.len());
        if self.live - old + key.len() + value.len() > MAX_LIVE {
            return Err(Error::Full);
        }
        self.append(dev, OP_PUT, key, value)?;
        self.insert(String::from(key), value.to_vec());
        Ok(())
    }

    /// Returns whether the key existed.
    pub fn delete(&mut self, dev: &mut dyn BlockDevice, key: &str) -> Result<bool, Error> {
        if !self.map.contains_key(key) {
            return Ok(false);
        }
        self.append(dev, OP_DELETE, key, &[])?;
        self.remove(key);
        Ok(true)
    }

    /// Rewrite the live data into the other half under a new generation.
    pub fn compact(&mut self, dev: &mut dyn BlockDevice) -> Result<(), Error> {
        let other = 1 - self.active;
        let generation = self.generation + 1;
        let salt = self.next_salt();
        let base = self.base(other);
        let mut pos = 1u64;
        let mut batch: Vec<u8> = Vec::new();
        let mut batch_at = pos;
        for (k, v) in &self.map {
            let rec = encode(salt, OP_PUT, k, v);
            let secs = (rec.len() / SECTOR) as u64;
            if pos + secs > self.half {
                return Err(Error::Full);
            }
            batch.extend_from_slice(&rec);
            pos += secs;
            if batch.len() >= READ_CHUNK {
                if !dev.write(base + batch_at, &batch) {
                    return Err(Error::Io);
                }
                batch.clear();
                batch_at = pos;
            }
        }
        if !batch.is_empty() && !dev.write(base + batch_at, &batch) {
            return Err(Error::Io);
        }
        // commit point
        if !dev.write(base, &header(generation, self.half, salt)) {
            return Err(Error::Io);
        }
        self.active = other;
        self.generation = generation;
        self.salt = salt;
        self.tail = pos;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
