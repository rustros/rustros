//! Boot modules: the modules that come with the kernel (one binary with the
//! disk driver, the storage service, rescue, dhcp and the updater, LZ4-compressed), in its image
//! after the ELF. GRUB loads them with the kernel (tools/pack.py makes them
//! a segment of it), so they are there before any disk is. They start before
//! the installed modules, in safe mode too, and are updated and rolled back
//! with the kernel (one file, one slot).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::Module;
use rustros_api::module::{Driver, Export, Storage};
use rustros_util::sha256::Sha256;

const MAGIC: &[u8; 8] = b"RRSBNDL1";
const HEAD: usize = 4096;
const ENTRY: usize = 80;

/// Where the boot modules are and how long: tools/pack.py writes it here.
#[used]
static BUNDLE: [u8; 16] = *b"RRSBNDL1@ADDRESS";

fn le32(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}

/// The boot modules GRUB loaded with the kernel (None: an unpacked kernel).
pub fn bundle() -> Option<&'static [u8]> {
    // Safety: a plain static; read volatile, pack.py changed it after the build
    let v = unsafe { core::ptr::read_volatile(&raw const BUNDLE) };
    let at = u64::from_le_bytes(v[..8].try_into().ok()?);
    let len = u64::from_le_bytes(v[8..].try_into().ok()?);
    // left as it was (its text is no address below 4 GiB): no boot modules
    if at == 0 || at.checked_add(len)? > 1 << 32 {
        return None;
    }
    // Safety: GRUB loaded the segment there, identity-mapped; nothing else uses it
    Some(unsafe { core::slice::from_raw_parts(at as *const u8, len as usize) })
}

/// The boot modules in the bundle: (name, image), each checked against its
/// SHA-256.
pub fn parse(img: &[u8]) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    let head = img.get(..HEAD).filter(|h| &h[..8] == MAGIC).ok_or("damaged")?;
    let count = le32(head, 8).min((HEAD - 16) / ENTRY);
    let mut out = Vec::new();
    for i in 0..count {
        let e = &head[16 + i * ENTRY..16 + (i + 1) * ENTRY];
        let name = String::from(String::from_utf8_lossy(&e[..32]).trim_end_matches('\0'));
        let (off, len) = (le32(e, 32) * 512, le32(e, 36));
        let stored = img.get(off..off + len).ok_or("a boot module past the bundle's end")?;
        let data = if le32(e, 76) & 1 != 0 { lz4(stored, le32(e, 72)).ok_or("a boot module does not decompress")? } else { stored.to_vec() };
        if Sha256::digest(&data)[..] != e[40..72] {
            return Err("a boot module does not match its checksum");
        }
        out.push((name, data));
    }
    Ok(out)
}

/// Sort what a boot module exports into apps, drivers and the storage service.
pub fn take(e: Export, apps: &mut Vec<Box<dyn Module>>, drivers: &mut Vec<Box<dyn Driver>>, storage: &mut Option<Box<dyn Storage>>) {
    match e {
        Export::Module(a) => apps.push(a),
        Export::Driver(d) => drivers.push(d),
        Export::Storage(s) => *storage = Some(s),
        Export::Many(v) => v.into_iter().for_each(|e| take(e, apps, drivers, storage)),
        _ => crate::kprintln!("modules: a boot module holds apps, drivers and storage only"),
    }
}

/// An LZ4 block (as tools/pack.py makes it) of `len` bytes, unpacked.
fn lz4(src: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    let more = |i: &mut usize, mut n: usize| -> Option<usize> {
        if n == 15 {
            loop {
                let b = *src.get(*i)?;
                *i += 1;
                n += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        Some(n)
    };
    while i < src.len() {
        let token = src[i];
        i += 1;
        let lit = more(&mut i, (token >> 4) as usize)?;
        out.extend_from_slice(src.get(i..i + lit)?);
        i += lit;
        if i >= src.len() {
            break;
        }
        let off = u16::from_le_bytes([*src.get(i)?, *src.get(i + 1)?]) as usize;
        i += 2;
        let n = more(&mut i, (token & 15) as usize)? + 4;
        if off == 0 || off > out.len() || out.len() + n > len {
            return None;
        }
        // byte by byte: a match may overlap what it copies
        let from = out.len() - off;
        for k in 0..n {
            let b = out[from + k];
            out.push(b);
        }
    }
    (out.len() == len).then_some(out)
}
