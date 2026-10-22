//! Names and attributes: lookups, creating and removing, renaming, links;
//! and the whole-file calls by path.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Error, Fs, Kind, MAX_LINKS, R, ROOT, Stat, Vol, check_name, components};

/// What `setattr` changes (None: left as it is).
#[derive(Clone, Copy, Debug, Default)]
pub struct SetAttr {
    /// permission bits (and setuid, setgid, sticky)
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// a file's new length
    pub size: Option<u64>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl Fs {
    // ------------------------------------------------------------ by inode

    pub fn getattr(&mut self, v: &mut Vol, ino: u32) -> R<Stat> {
        Ok(self.read_inode(v, ino)?.stat())
    }

    /// The inode `name` in directory `dir` names.
    pub fn lookup(&mut self, v: &mut Vol, dir: u32, name: &str) -> R<Option<u32>> {
        let d = self.dir_inode(v, dir)?;
        Ok(self.find(v, &d, name)?.map(|e| e.0))
    }

    /// A directory's entries, "." and ".." too: (name, inode, kind from the entry).
    pub fn readdir(&mut self, v: &mut Vol, dir: u32) -> R<Vec<(String, u32, Option<Kind>)>> {
        let d = self.dir_inode(v, dir)?;
        Ok(self.entries(v, &d)?.into_iter().map(|(ino, ft, name)| (name, ino, Kind::from_ft(ft))).collect())
    }

    /// Where a symbolic link points.
    pub fn readlink(&mut self, v: &mut Vol, ino: u32) -> R<Vec<u8>> {
        let i = self.read_inode(v, ino)?;
        if i.kind() != Some(Kind::Symlink) {
            return Err(Error::Invalid);
        }
        if i.fast_symlink() {
            return Ok(i.raw[0x28..0x28 + i.size() as usize].to_vec());
        }
        let mut b = alloc::vec![0u8; i.size() as usize];
        let n = self.read_data(v, &i, 0, &mut b)?;
        b.truncate(n);
        Ok(b)
    }

    /// A name for a new inode: free in `dir`, `dir` a directory.
    fn new_name(&mut self, v: &mut Vol, dir: u32, name: &str) -> R<()> {
        check_name(name)?;
        let d = self.dir_inode(v, dir)?;
        if self.find(v, &d, name)?.is_some() {
            return Err(Error::Exists);
        }
        Ok(())
    }

    /// A file, device, FIFO or socket in `dir` (`rdev`: a device's (major, minor)).
    #[allow(clippy::too_many_arguments)]
    pub fn create(&mut self, v: &mut Vol, dir: u32, name: &str, kind: Kind, perm: u16, uid: u32, gid: u32, rdev: (u32, u32), now: u32) -> R<u32> {
        if matches!(kind, Kind::Dir | Kind::Symlink) {
            return Err(Error::Invalid);
        }
        self.change(v, |fs, v| {
            fs.new_name(v, dir, name)?;
            let ino = fs.alloc_inode(v, false, fs.group_of_ino(dir))?;
            let mut i = fs.blank_inode(ino, kind, perm, uid, gid, now);
            i.set_links(1);
            if matches!(kind, Kind::CharDev | Kind::BlockDev) {
                i.set_rdev(rdev);
            }
            fs.write_inode(v, &i)?;
            fs.link_new(v, dir, ino, name, kind, now)
        })
    }

    /// A new inode's name; without one it is given back.
    fn link_new(&mut self, v: &mut Vol, dir: u32, ino: u32, name: &str, kind: Kind, now: u32) -> R<u32> {
        if let Err(e) = self.dir_add(v, dir, ino, name, kind, now) {
            self.release(v, ino, now)?;
            return Err(e);
        }
        Ok(ino)
    }

    pub fn mkdir(&mut self, v: &mut Vol, dir: u32, name: &str, perm: u16, uid: u32, gid: u32, now: u32) -> R<u32> {
        self.change(v, |fs, v| fs.mkdir_in(v, dir, name, perm, uid, gid, now))
    }

    #[allow(clippy::too_many_arguments)]
    fn mkdir_in(&mut self, v: &mut Vol, dir: u32, name: &str, perm: u16, uid: u32, gid: u32, now: u32) -> R<u32> {
        self.new_name(v, dir, name)?;
        if self.read_inode(v, dir)?.links() >= MAX_LINKS {
            return Err(Error::TooManyLinks);
        }
        let ino = self.alloc_inode(v, true, self.dir_group(dir))?;
        let mut i = self.blank_inode(ino, Kind::Dir, perm, uid, gid, now);
        if let Err(e) = self.init_dir(v, &mut i, dir) {
            self.mark_inode(v, ino, false, true)?;
            return Err(e);
        }
        self.write_inode(v, &i)?;
        self.link_new(v, dir, ino, name, Kind::Dir, now)?;
        self.adjust_links(v, dir, 1, now)?;
        Ok(ino)
    }

    pub fn symlink(&mut self, v: &mut Vol, dir: u32, name: &str, target: &str, uid: u32, gid: u32, now: u32) -> R<u32> {
        if target.is_empty() || target.len() >= crate::BLOCK {
            return Err(Error::BadName);
        }
        self.change(v, |fs, v| {
            fs.new_name(v, dir, name)?;
            let ino = fs.alloc_inode(v, false, fs.group_of_ino(dir))?;
            let mut i = fs.blank_inode(ino, Kind::Symlink, 0o777, uid, gid, now);
            i.set_links(1);
            if target.len() < 60 {
                i.raw[0x28..0x28 + target.len()].copy_from_slice(target.as_bytes());
                i.set_size(target.len() as u64);
            } else {
                i.set_flags(crate::EXT4_EXTENTS_FL);
                crate::extent::empty_root(&mut i);
                let r = fs.write_data(v, &mut i, 0, target.as_bytes());
                fs.write_inode(v, &i)?;
                if let Err(e) = r {
                    fs.release(v, ino, now)?;
                    return Err(e);
                }
            }
            fs.write_inode(v, &i)?;
            fs.link_new(v, dir, ino, name, Kind::Symlink, now)
        })
    }

    /// Another name for inode `ino` (not a directory).
    pub fn link(&mut self, v: &mut Vol, ino: u32, dir: u32, name: &str, now: u32) -> R<()> {
        self.change(v, |fs, v| {
            let i = fs.read_inode(v, ino)?;
            let kind = i.kind().ok_or(Error::Corrupt("unknown inode type"))?;
            if kind == Kind::Dir {
                return Err(Error::Invalid);
            }
            fs.new_name(v, dir, name)?;
            fs.adjust_links(v, ino, 1, now)?;
            if let Err(e) = fs.dir_add(v, dir, ino, name, kind, now) {
                fs.adjust_links(v, ino, -1, now)?;
                return Err(e);
            }
            Ok(())
        })
    }

    /// Remove a name (not a directory's); the inode goes with its last link.
    pub fn unlink(&mut self, v: &mut Vol, dir: u32, name: &str, now: u32) -> R<()> {
        self.change(v, |fs, v| {
            let d = fs.dir_inode(v, dir)?;
            let (ino, _) = fs.find(v, &d, name)?.ok_or(Error::NotFound)?;
            if fs.read_inode(v, ino)?.is_dir() {
                return Err(Error::IsADirectory);
            }
            fs.dir_remove(v, dir, name, now)?;
            fs.adjust_links(v, ino, -1, now)
        })
    }

    /// Remove an empty directory.
    pub fn rmdir(&mut self, v: &mut Vol, dir: u32, name: &str, now: u32) -> R<()> {
        if name == "." || name == ".." {
            return Err(Error::Invalid);
        }
        self.change(v, |fs, v| {
            let d = fs.dir_inode(v, dir)?;
            let (ino, _) = fs.find(v, &d, name)?.ok_or(Error::NotFound)?;
            let i = fs.dir_inode(v, ino)?;
            if !fs.dir_empty(v, &i)? {
                return Err(Error::NotEmpty);
            }
            fs.dir_remove(v, dir, name, now)?;
            fs.release(v, ino, now)?;
            fs.adjust_links(v, dir, -1, now)
        })
    }

    /// Move `oname` in `odir` to `nname` in `ndir`, replacing what is there
    /// (a file by a file, an empty directory by a directory).
    pub fn rename(&mut self, v: &mut Vol, odir: u32, oname: &str, ndir: u32, nname: &str, now: u32) -> R<()> {
        self.change(v, |fs, v| {
            check_name(oname)?;
            check_name(nname)?;
            let od = fs.dir_inode(v, odir)?;
            let (sino, _) = fs.find(v, &od, oname)?.ok_or(Error::NotFound)?;
            let nd = fs.dir_inode(v, ndir)?;
            let target = fs.find(v, &nd, nname)?.map(|t| t.0);
            if target == Some(sino) {
                return Ok(()); // the same inode under both names
            }
            let src = fs.read_inode(v, sino)?;
            let kind = src.kind().ok_or(Error::Corrupt("unknown inode type"))?;
            let is_dir = kind == Kind::Dir;
            let moved_dir = is_dir && odir != ndir;
            if moved_dir {
                // not into itself, nor below it
                let mut cur = ndir;
                while cur != ROOT {
                    if cur == sino {
                        return Err(Error::Invalid);
                    }
                    let c = fs.dir_inode(v, cur)?;
                    cur = fs.find(v, &c, "..")?.ok_or(Error::Corrupt("a directory without .."))?.0;
                }
                if target.is_none() && nd.links() >= MAX_LINKS {
                    return Err(Error::TooManyLinks);
                }
            }
            if let Some(t) = target {
                let ti = fs.read_inode(v, t)?;
                match (is_dir, ti.is_dir()) {
                    (true, false) => return Err(Error::NotADirectory),
                    (false, true) => return Err(Error::IsADirectory),
                    (true, true) if !fs.dir_empty(v, &ti)? => return Err(Error::NotEmpty),
                    _ => {}
                }
                fs.dir_retarget(v, ndir, nname, sino, kind, now)?;
            } else {
                fs.dir_add(v, ndir, sino, nname, kind, now)?;
            }
            fs.dir_remove(v, odir, oname, now)?;
            if moved_dir {
                fs.dir_retarget(v, sino, "..", ndir, Kind::Dir, now)?;
                fs.adjust_links(v, odir, -1, now)?;
                if target.is_none() {
                    fs.adjust_links(v, ndir, 1, now)?;
                }
            }
            if let Some(t) = target {
                if is_dir {
                    // the directory replaced: its parent loses the link its ".." was
                    fs.release(v, t, now)?;
                    if !moved_dir {
                        fs.adjust_links(v, ndir, -1, now)?;
                    }
                } else {
                    fs.adjust_links(v, t, -1, now)?;
                }
            }
            let mut s = fs.read_inode(v, sino)?;
            s.set_ctime(now);
            fs.write_inode(v, &s)
        })
    }

    pub fn setattr(&mut self, v: &mut Vol, ino: u32, a: SetAttr, now: u32) -> R<()> {
        self.change(v, |fs, v| {
            let mut i = fs.read_inode(v, ino)?;
            if let Some(size) = a.size {
                match i.kind() {
                    Some(Kind::File) => {}
                    Some(Kind::Dir) => return Err(Error::IsADirectory),
                    _ => return Err(Error::Invalid),
                }
                if size != i.size() {
                    fs.set_len(v, &mut i, size)?;
                    i.touch(now);
                }
            }
            if let Some(m) = a.mode {
                let mode = i.mode() & crate::S_IFMT | m & 0o7777;
                crate::put16(&mut i.raw, 0, mode);
            }
            if let Some(u) = a.uid {
                i.set_uid(u);
            }
            if let Some(g) = a.gid {
                i.set_gid(g);
            }
            if let Some(t) = a.atime {
                i.set_atime(t);
            }
            if let Some(t) = a.mtime {
                i.set_mtime(t);
            }
            i.set_ctime(now);
            fs.write_inode(v, &i)
        })
    }

    // ------------------------------------------------------------ by path

    /// The inode of `path` ("" or "/" is the root; symbolic links are not followed).
    pub fn resolve(&mut self, v: &mut Vol, path: &str) -> R<u32> {
        let mut cur = ROOT;
        for c in components(path)? {
            cur = self.lookup(v, cur, c)?.ok_or(Error::NotFound)?;
        }
        Ok(cur)
    }

    pub fn stat(&mut self, v: &mut Vol, path: &str) -> R<Stat> {
        let ino = self.resolve(v, path)?;
        self.getattr(v, ino)
    }

    /// Bytes of a file from `offset`: how many (0 at its end).
    pub fn read(&mut self, v: &mut Vol, path: &str, offset: u64, buf: &mut [u8]) -> R<usize> {
        let ino = self.resolve(v, path)?;
        self.pread(v, ino, offset, buf)
    }

    /// The entries of a directory: (name, stat), without "." and "..".
    pub fn list(&mut self, v: &mut Vol, path: &str) -> R<Vec<(String, Stat)>> {
        let dir = self.resolve(v, path)?;
        let mut out = Vec::new();
        for (name, ino, _) in self.readdir(v, dir)? {
            if name != "." && name != ".." {
                let st = self.getattr(v, ino)?;
                out.push((name, st));
            }
        }
        Ok(out)
    }

    /// Make a directory and those above it that are missing.
    pub fn mkdir_p(&mut self, v: &mut Vol, path: &str, now: u32) -> R<()> {
        let parts = components(path)?;
        self.change(v, |fs, v| fs.mkdir_parts(v, &parts, now).map(|_| ()))
    }

    fn mkdir_parts(&mut self, v: &mut Vol, parts: &[&str], now: u32) -> R<u32> {
        let mut cur = ROOT;
        for c in parts {
            cur = match self.lookup(v, cur, c)? {
                Some(ino) => {
                    self.dir_inode(v, ino)?;
                    ino
                }
                None => self.mkdir_in(v, cur, c, 0o755, 0, 0, now)?,
            };
        }
        Ok(cur)
    }

    /// Create or replace a file with `data` (the directories above are made);
    /// the old contents stay until the new are in place.
    pub fn write_file(&mut self, v: &mut Vol, path: &str, data: &[u8], now: u32) -> R<()> {
        let mut parts = components(path)?;
        let name = parts.pop().ok_or(Error::BadName)?;
        self.change(v, |fs, v| {
            let dir = fs.mkdir_parts(v, &parts, now)?;
            let d = fs.dir_inode(v, dir)?;
            let old = fs.find(v, &d, name)?.map(|e| e.0);
            if let Some(o) = old {
                if fs.read_inode(v, o)?.is_dir() {
                    return Err(Error::IsADirectory);
                }
            }
            let ino = fs.alloc_inode(v, false, fs.group_of_ino(dir))?;
            let mut i = fs.blank_inode(ino, Kind::File, 0o644, 0, 0, now);
            i.set_links(1);
            let r = fs.write_data(v, &mut i, 0, data);
            fs.write_inode(v, &i)?;
            if let Err(e) = r {
                fs.release(v, ino, now)?;
                return Err(e);
            }
            match old {
                Some(o) => {
                    fs.dir_retarget(v, dir, name, ino, Kind::File, now)?;
                    fs.adjust_links(v, o, -1, now)
                }
                None => fs.link_new(v, dir, ino, name, Kind::File, now).map(|_| ()),
            }
        })
    }

    /// Remove a file or an empty directory; false if there was none.
    pub fn remove(&mut self, v: &mut Vol, path: &str, now: u32) -> R<bool> {
        let mut parts = components(path)?;
        let name = parts.pop().ok_or(Error::BadName)?;
        let dir = match self.resolve(v, &parts.join("/")) {
            Ok(d) => d,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        let Some(ino) = self.lookup(v, dir, name)? else { return Ok(false) };
        if self.read_inode(v, ino)?.is_dir() {
            self.rmdir(v, dir, name, now)?;
        } else {
            self.unlink(v, dir, name, now)?;
        }
        Ok(true)
    }
}
