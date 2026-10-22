//! File contents: reading and writing at any offset (holes read as zeros,
//! blocks allocated as they are first written), and the length.

use alloc::vec;
use alloc::vec::Vec;

use crate::extent::{Ext, INIT_MAX};
use crate::{BLOCK, Error, Fs, Inode, Kind, R, Vol};

/// The most blocks one data request carries.
const CHUNK: u64 = 64;
const B: u64 = BLOCK as u64;

/// Runs of `exts[k]` once blocks `lb..lb + n` of it are written: the
/// written part initialized, the rest as it was.
fn split_written(exts: &mut Vec<Ext>, k: usize, lb: u64, n: u64) {
    let e = exts[k];
    let mut parts = Vec::new();
    if lb > e.l as u64 {
        parts.push(Ext { n: (lb - e.l as u64) as u32, ..e });
    }
    parts.push(Ext { l: lb as u32, p: e.at(lb), n: n as u32, uninit: false });
    if lb + n < e.end() {
        parts.push(Ext { l: (lb + n) as u32, p: e.at(lb + n), n: (e.end() - lb - n) as u32, uninit: true });
    }
    exts.splice(k..k + 1, parts);
}

impl Fs {
    fn file_inode(&mut self, v: &mut Vol, ino: u32) -> R<Inode> {
        let i = self.read_inode(v, ino)?;
        match i.kind() {
            Some(Kind::File) => Ok(i),
            Some(Kind::Dir) => Err(Error::IsADirectory),
            _ => Err(Error::Invalid),
        }
    }

    /// Bytes of a file from `offset`: how many (0 at its end).
    pub fn pread(&mut self, v: &mut Vol, ino: u32, offset: u64, buf: &mut [u8]) -> R<usize> {
        let i = self.file_inode(v, ino)?;
        self.read_data(v, &i, offset, buf)
    }

    pub(crate) fn read_data(&mut self, v: &mut Vol, i: &Inode, offset: u64, buf: &mut [u8]) -> R<usize> {
        let size = i.size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        let end = offset + n as u64;
        buf[..n].fill(0); // holes read as zeros
        let (first, last) = (offset / B, (end - 1) / B);
        let mut tmp = Vec::new();
        for e in self.runs(v, i)? {
            if e.uninit || e.end() <= first || e.l as u64 > last {
                continue;
            }
            let mut lb = first.max(e.l as u64);
            let hi = last.min(e.end() - 1);
            while lb <= hi {
                let cnt = (hi - lb + 1).min(CHUNK);
                tmp.resize((cnt * B) as usize, 0);
                v.read(e.at(lb), &mut tmp)?;
                let from = offset.max(lb * B);
                let to = end.min((lb + cnt) * B);
                buf[(from - offset) as usize..(to - offset) as usize].copy_from_slice(&tmp[(from - lb * B) as usize..(to - lb * B) as usize]);
                lb += cnt;
            }
        }
        Ok(n)
    }

    /// Write `data` at `offset` (the file grows as needed).
    pub fn pwrite(&mut self, v: &mut Vol, ino: u32, offset: u64, data: &[u8], now: u32) -> R<()> {
        self.change(v, |fs, v| {
            let mut i = fs.file_inode(v, ino)?;
            let r = fs.write_data(v, &mut i, offset, data);
            i.touch(now);
            fs.write_inode(v, &i)?;
            r
        })
    }

    /// Blocks `lb..lb + n` of the file at physical `p`, from `data` (which
    /// starts at file `offset`); parts of blocks it does not cover are kept
    /// (`fresh`: zeros, the blocks are new).
    fn put_blocks(&mut self, v: &mut Vol, p: u64, lb: u64, n: u64, offset: u64, data: &[u8], fresh: bool) -> R<()> {
        let end = offset + data.len() as u64;
        let mut k = 0;
        while k < n {
            let cnt = (n - k).min(CHUNK);
            let first = lb + k;
            let mut buf = vec![0u8; (cnt * B) as usize];
            for j in 0..cnt {
                let bs = (first + j) * B;
                let (from, to) = (offset.max(bs), end.min(bs + B));
                let slot = &mut buf[(j * B) as usize..((j + 1) * B) as usize];
                if (from > bs || to < bs + B) && !fresh {
                    v.read(p + k + j, slot)?;
                }
                slot[(from - bs) as usize..(to - bs) as usize].copy_from_slice(&data[(from - offset) as usize..(to - offset) as usize]);
            }
            v.write(p + k, &buf)?;
            k += cnt;
        }
        Ok(())
    }

    /// The data into the file's blocks; the inode (in memory) follows. What
    /// was written before an error stays (and the size covers it).
    pub(crate) fn write_data(&mut self, v: &mut Vol, i: &mut Inode, offset: u64, data: &[u8]) -> R<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::TooBig)?;
        if end.div_ceil(B) > u32::MAX as u64 {
            return Err(Error::TooBig);
        }
        let mut exts = self.runs(v, i)?;
        let (first, last) = (offset / B, (end - 1) / B);
        let mut fresh: Vec<(u64, u32)> = Vec::new();
        let mut changed = false;
        let mut lb = first;
        let result = loop {
            if lb > last {
                break Ok(());
            }
            match exts.iter().position(|e| lb >= e.l as u64 && lb < e.end()) {
                Some(k) => {
                    let e = exts[k];
                    let cnt = last.min(e.end() - 1) - lb + 1;
                    if let Err(err) = self.put_blocks(v, e.at(lb), lb, cnt, offset, data, e.uninit) {
                        break Err(err);
                    }
                    if e.uninit {
                        split_written(&mut exts, k, lb, cnt);
                        changed = true;
                    }
                    lb += cnt;
                }
                None => {
                    // a hole: new blocks, placed after the ones before it
                    let next = exts.iter().map(|e| e.l as u64).filter(|&l| l > lb).min().unwrap_or(u64::MAX);
                    let cnt = (last.min(next - 1) - lb + 1).min(INIT_MAX as u64) as u32;
                    let goal = exts.iter().rev().find(|e| (e.l as u64) < lb).map_or_else(|| self.group_first_block(self.group_of_ino(i.ino)), |e| e.at(lb));
                    let (n, p) = match self.alloc_blocks(v, cnt, goal) {
                        Ok(x) => x,
                        Err(err) => break Err(err),
                    };
                    if let Err(err) = self.put_blocks(v, p, lb, n as u64, offset, data, true) {
                        self.free_blocks(v, p, n as u64)?;
                        break Err(err);
                    }
                    fresh.push((p, n));
                    let at = exts.iter().position(|e| e.l as u64 > lb).unwrap_or(exts.len());
                    exts.insert(at, Ext { l: lb as u32, p, n, uninit: false });
                    changed = true;
                    lb += n as u64;
                }
            }
        };
        if changed {
            if let Err(e) = self.set_runs(v, i, &exts) {
                // nothing mapped: the new blocks go back
                for (p, n) in fresh {
                    self.free_blocks(v, p, n as u64)?;
                }
                return Err(e);
            }
        }
        let written = end.min(lb * B);
        if written > i.size() {
            i.set_size(written);
        }
        result
    }

    /// A new length: blocks past it given back, or a hole up to it.
    pub fn truncate(&mut self, v: &mut Vol, ino: u32, size: u64, now: u32) -> R<()> {
        self.change(v, |fs, v| {
            let mut i = fs.file_inode(v, ino)?;
            fs.set_len(v, &mut i, size)?;
            i.touch(now);
            fs.write_inode(v, &i)
        })
    }

    pub(crate) fn set_len(&mut self, v: &mut Vol, i: &mut Inode, size: u64) -> R<()> {
        if size.div_ceil(B) > u32::MAX as u64 {
            return Err(Error::TooBig);
        }
        // (the same length too: blocks past it, as an unfinished truncate leaves them)
        if size <= i.size() {
            let keep = size.div_ceil(B);
            let mut out = Vec::new();
            for e in self.runs(v, i)? {
                if e.end() <= keep {
                    out.push(e);
                } else if e.l as u64 >= keep {
                    self.free_blocks(v, e.p, e.n as u64)?;
                } else {
                    let k = (keep - e.l as u64) as u32;
                    self.free_blocks(v, e.p + k as u64, (e.n - k) as u64)?;
                    out.push(Ext { n: k, ..e });
                }
            }
            self.set_runs(v, i, &out)?;
            // the rest of the last block: zeros, should the file grow again
            if size % B != 0 {
                let lb = size / B;
                if let Some(e) = out.iter().find(|e| lb >= e.l as u64 && lb < e.end() && !e.uninit) {
                    let pb = e.at(lb);
                    let mut blk = v.block(pb)?;
                    blk[(size % B) as usize..].fill(0);
                    v.write(pb, &blk)?;
                }
            }
        }
        i.set_size(size);
        Ok(())
    }
}
