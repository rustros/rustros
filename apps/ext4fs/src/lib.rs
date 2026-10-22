//! The ext4 file system driver (journal, metadata checksums), as a module.
//! The kernel lends it the files partition's sectors; apps use it through
//! their `Kv` file calls, which the kernel passes on here.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use devices::BlockDevice;
use ext4::{Error, Fs, Vol};
use rustros_api::KvError;
use rustros_api::module::{Disk, Filesystem};

/// The kernel's sectors as a block device for ext4.
struct Dev<'a>(&'a mut dyn Disk);

impl BlockDevice for Dev<'_> {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.0.read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        self.0.write(lba, buf)
    }
    fn sectors(&self) -> u64 {
        self.0.sectors()
    }
}

#[derive(Default)]
pub struct Ext4 {
    fs: Option<Fs>,
}

impl Ext4 {
    pub fn new() -> Ext4 {
        Ext4::default()
    }

    /// The mounted file system, and the disk as ext4 takes it.
    fn with<T>(&mut self, disk: &mut dyn Disk, f: impl FnOnce(&mut Fs, &mut Vol) -> T) -> Option<T> {
        let fs = self.fs.as_mut()?;
        let mut dev = Dev(disk);
        let mut v = Vol { dev: &mut dev, start: 0 };
        Some(f(fs, &mut v))
    }
}

impl Filesystem for Ext4 {
    fn name(&self) -> &'static str {
        "ext4"
    }

    fn probe(&mut self, disk: &mut dyn Disk) -> bool {
        let mut dev = Dev(disk);
        !matches!(Fs::mount(&mut Vol { dev: &mut dev, start: 0 }), Err(Error::NotExt4))
    }

    fn format(&mut self, disk: &mut dyn Disk, uuid: [u8; 16], now: u32) -> Result<(), String> {
        let sectors = disk.sectors();
        let mut dev = Dev(disk);
        Fs::format(&mut Vol { dev: &mut dev, start: 0 }, sectors, uuid, "rustros-files", now).map(|_| ()).map_err(|e| format!("{e:?}"))
    }

    fn mount(&mut self, disk: &mut dyn Disk, now: u32) -> Result<String, String> {
        let mut dev = Dev(disk);
        let mut v = Vol { dev: &mut dev, start: 0 };
        let mut fs = Fs::mount(&mut v).map_err(|e| format!("{e:?}"))?;
        let journal = match fs.add_journal(&mut v, now) {
            Ok(true) => ", journal added",
            Ok(false) => "",
            Err(_) => ", no journal",
        };
        let (total, free) = fs.usage();
        let how = match (fs.writable, fs.has_journal()) {
            (false, _) => ", read only",
            (true, true) => ", journaled",
            (true, false) => "",
        };
        self.fs = Some(fs);
        Ok(format!("{} MiB (ext4{}), {} MiB used{}", total >> 20, how, (total - free) >> 20, journal))
    }

    fn usage(&self) -> (u64, u64) {
        self.fs.as_ref().map_or((0, 0), |fs| {
            let (total, free) = fs.usage();
            (total, total - free)
        })
    }

    fn put(&mut self, disk: &mut dyn Disk, path: &str, data: &[u8], now: u32) -> Result<(), KvError> {
        let r = self.with(disk, |fs, v| fs.write_file(v, path, data, now)).ok_or(KvError::NoStorage)?;
        r.map_err(|e| match e {
            Error::Full => KvError::Full,
            Error::Io => KvError::Io,
            _ => KvError::TooLarge,
        })
    }

    fn read(&mut self, disk: &mut dyn Disk, path: &str, offset: u64, buf: &mut [u8]) -> Option<usize> {
        self.with(disk, |fs, v| fs.read(v, path, offset, buf).ok())?
    }

    fn stat(&mut self, disk: &mut dyn Disk, path: &str) -> Option<(u64, u64, bool)> {
        let st = self.with(disk, |fs, v| fs.stat(v, path).ok())??;
        Some((st.size, st.mtime as u64, st.dir))
    }

    fn list(&mut self, disk: &mut dyn Disk, path: &str) -> Option<Vec<(String, u64, bool)>> {
        let l = self.with(disk, |fs, v| fs.list(v, path).ok())??;
        Some(l.into_iter().map(|(n, st)| (n, st.size, st.dir)).collect())
    }

    fn remove(&mut self, disk: &mut dyn Disk, path: &str, now: u32) -> bool {
        self.with(disk, |fs, v| fs.remove(v, path, now).unwrap_or(false)).unwrap_or(false)
    }

    fn close(&mut self, disk: &mut dyn Disk) {
        let _ = self.with(disk, |fs, v| fs.close(v));
    }
}
