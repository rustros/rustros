//! Boot modules: the modules that come with the kernel (rescue, dhcp,
//! updater), in its image after the ELF. They start before the installed
//! modules, in safe mode too, and are updated and rolled back with the
//! kernel (one file, one slot). GRUB hands the image over again as a
//! module (`module2`); without that the kernel reads its slot.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use devices::BlockDevice;
use rustros_util::sha256::Sha256;

const MAGIC: &[u8; 8] = b"RRSBNDL1";
const HEAD: usize = 4096;
const ENTRY: usize = 80;

fn le16(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
fn le32(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}

/// Where the bundle starts in a kernel image: after the ELF (its section
/// header table ends it), 4 KiB aligned.
fn bundle_at(img: &[u8]) -> Option<usize> {
    if img.len() < 64 || &img[..4] != b"\x7fELF" {
        return None;
    }
    let shoff = u64::from_le_bytes(img[0x28..0x30].try_into().ok()?) as usize;
    let end = shoff.checked_add(le16(img, 0x3A) * le16(img, 0x3C))?;
    Some(end.next_multiple_of(4096))
}

/// The boot modules in a kernel image: (name, image), each checked against
/// its SHA-256.
pub fn parse(img: &[u8]) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    let at = bundle_at(img).ok_or("not a kernel image")?;
    let head = img.get(at..at + HEAD).ok_or("the kernel image carries no boot modules")?;
    if &head[..8] != MAGIC {
        return Err("the kernel image carries no boot modules");
    }
    let count = le32(head, 8).min((HEAD - 16) / ENTRY);
    let mut out = Vec::new();
    for i in 0..count {
        let e = &head[16 + i * ENTRY..16 + (i + 1) * ENTRY];
        let name = String::from(String::from_utf8_lossy(&e[..32]).trim_end_matches('\0'));
        let (off, len) = (le32(e, 32) * 512, le32(e, 36));
        let data = img.get(at + off..at + off + len).ok_or("a boot module past the image's end")?;
        if Sha256::digest(data)[..] != e[40..72] {
            return Err("a boot module does not match its checksum");
        }
        out.push((name, data.to_vec()));
    }
    Ok(out)
}

/// The running kernel's image, read from its slot (`lba`, `sectors` long).
pub fn read_slot(disk: &mut dyn BlockDevice, lba: u64, sectors: u64) -> Option<Vec<u8>> {
    let mut first = vec![0u8; 4096];
    if !disk.read(lba, &mut first) {
        return None;
    }
    let at = bundle_at(&first)?;
    let mut head = vec![0u8; HEAD];
    if (at + HEAD) as u64 > sectors * 512 || !disk.read(lba + at as u64 / 512, &mut head) || &head[..8] != MAGIC {
        return None;
    }
    let count = le32(&head, 8).min((HEAD - 16) / ENTRY);
    let end = (0..count).map(|i| le32(&head, 16 + i * ENTRY + 32) * 512 + le32(&head, 16 + i * ENTRY + 36)).max()? + at;
    if end as u64 > sectors * 512 {
        return None;
    }
    let mut img = vec![0u8; end.next_multiple_of(512)];
    disk.read(lba, &mut img).then_some(img)
}
