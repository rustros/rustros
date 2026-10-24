//! The binary form of a service's state as one version hands it to the next
//! (hot replacement, `rustros_api::module`): a tag naming the service and
//! the format version, then the fields in order, little-endian, lengths as
//! u32. Reading checks every bound: a short or damaged state is an error,
//! never a panic.

use alloc::string::String;
use alloc::vec::Vec;

/// A state being written.
pub struct W(pub Vec<u8>);

impl W {
    pub fn new(tag: &[u8; 4], version: u32) -> W {
        let mut w = W(Vec::new());
        w.put(tag);
        w.u32(version);
        w
    }
    // not inlined: a state is written by long runs of these
    #[inline(never)]
    fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    #[inline(never)]
    pub fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    #[inline(never)]
    pub fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    #[inline(never)]
    pub fn u32(&mut self, v: u32) {
        self.put(&v.to_le_bytes());
    }
    #[inline(never)]
    pub fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes());
    }
    /// A count or an index.
    pub fn n(&mut self, v: usize) {
        self.u32(v as u32);
    }
    #[inline(never)]
    pub fn bytes(&mut self, b: &[u8]) {
        self.n(b.len());
        self.put(b);
    }
    pub fn mac(&mut self, m: &[u8; 6]) {
        self.put(m);
    }
}

/// A state being read.
pub struct R<'a> {
    b: &'a [u8],
}

/// The state is short or damaged.
#[derive(Debug)]
pub struct Bad;

impl From<Bad> for String {
    fn from(_: Bad) -> String {
        String::from("damaged state")
    }
}

impl<'a> R<'a> {
    /// A state of service `tag`: the reader after the header, and the
    /// format version.
    pub fn new(b: &'a [u8], tag: &[u8; 4]) -> Result<(R<'a>, u32), String> {
        if !b.starts_with(tag) {
            return Err(String::from("not this service's state"));
        }
        let mut r = R { b: &b[4..] };
        let v = r.u32()?;
        Ok((r, v))
    }
    #[inline(never)]
    fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        if n > self.b.len() {
            return Err(Bad);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    #[inline(never)]
    fn le(&mut self, n: usize) -> Result<u64, Bad> {
        Ok(self.take(n)?.iter().rev().fold(0, |v, &b| v << 8 | b as u64))
    }
    pub fn u8(&mut self) -> Result<u8, Bad> {
        self.le(1).map(|v| v as u8)
    }
    pub fn u16(&mut self) -> Result<u16, Bad> {
        self.le(2).map(|v| v as u16)
    }
    pub fn u32(&mut self) -> Result<u32, Bad> {
        self.le(4).map(|v| v as u32)
    }
    pub fn u64(&mut self) -> Result<u64, Bad> {
        self.le(8)
    }
    pub fn n(&mut self) -> Result<usize, Bad> {
        self.le(4).map(|v| v as usize)
    }
    pub fn bool(&mut self) -> Result<bool, Bad> {
        self.le(1).map(|v| v != 0)
    }
    #[inline(never)]
    pub fn bytes(&mut self) -> Result<Vec<u8>, Bad> {
        let n = self.n()?;
        self.take(n).map(<[u8]>::to_vec)
    }
    pub fn mac(&mut self) -> Result<[u8; 6], Bad> {
        let mut m = [0; 6];
        m.copy_from_slice(self.take(6)?);
        Ok(m)
    }
    /// How many items follow (checked against what is left, so a damaged
    /// count cannot ask for a huge allocation).
    #[inline(never)]
    pub fn count(&mut self) -> Result<usize, Bad> {
        let n = self.n()?;
        if n > self.b.len() { Err(Bad) } else { Ok(n) }
    }
    /// `count` items read by `f`.
    pub fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T, Bad>) -> Result<Vec<T>, Bad> {
        let n = self.count()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(f(self)?);
        }
        Ok(v)
    }
    /// Everything was read.
    pub fn end(&self) -> Result<(), Bad> {
        if self.b.is_empty() { Ok(()) } else { Err(Bad) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut w = W::new(b"TEST", 1);
        w.u8(7);
        w.u16(300);
        w.bytes(b"abc");
        w.n(2);
        w.u64(1);
        w.u64(2);
        let (mut r, v) = R::new(&w.0, b"TEST").unwrap();
        assert_eq!(v, 1);
        assert_eq!((r.u8().unwrap(), r.u16().unwrap(), r.bytes().unwrap()), (7, 300, b"abc".to_vec()));
        assert_eq!(r.list(|r| r.u64()).unwrap(), [1, 2]);
        assert!(r.end().is_ok());
        // short, or a count bigger than what is left: an error
        let (mut r, _) = R::new(&w.0[..w.0.len() - 1], b"TEST").unwrap();
        assert!(r.u8().is_ok() && r.u16().is_ok() && r.bytes().is_ok());
        assert!(r.list(|r| r.u64()).is_err());
        let mut w = W::new(b"TEST", 1);
        w.n(1000);
        assert!(R::new(&w.0, b"TEST").unwrap().0.list(|r| r.u8()).is_err());
        assert!(R::new(&w.0, b"NOPE").is_err());
    }
}
