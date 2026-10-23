//! Device interfaces between the kernel's drivers and the system services.
//! Services are written against these traits only, so they can be tested on
//! the host with in-memory devices.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub const SECTOR: usize = 512;

pub use rustros_api::Offload;
pub use rustros_api::module::{BUF_SIZE, Buf, DevStats, NetDevice, buf_for, new_buf};
/// Free bytes in front of a received frame (headers to add).
pub use rustros_api::HEADROOM;

/// A disk addressed in 512-byte sectors (the trait drivers implement).
pub use rustros_api::module::Disk as BlockDevice;

use alloc::vec;
use alloc::vec::Vec;
use rustros_util::offload::{complete_csum, segment};

/// The frame as plain packets (complete checksums, at most `gso_size` of
/// TCP payload each); an 802.1Q tag stays on every one. For apps that want
/// plain packets, for the system's own stack, and for NICs that cannot
/// finish offloads.
pub fn plain(f: &[u8], off: Offload) -> Vec<Vec<u8>> {
    let tag = (f.len() >= 18 && f[12..14] == [0x81, 0x00]).then(|| [f[12], f[13], f[14], f[15]]);
    let mut inner = match tag {
        Some(_) => [&f[..12], &f[16..]].concat(),
        None => f.to_vec(),
    };
    let mut out = if off.gso_size > 0 {
        segment(&inner, off.gso_size as usize).unwrap_or_default()
    } else {
        if off.csum_partial {
            complete_csum(&mut inner);
        }
        vec![inner]
    };
    if let Some(t) = tag {
        for p in &mut out {
            p.splice(12..12, t);
        }
    }
    out
}

/// Send a frame with offloads pending on a NIC that cannot finish them.
pub fn send_plain(nic: &mut dyn NetDevice, f: &mut [u8], off: Offload) -> bool {
    if off.gso_size == 0 && f.get(12..14) != Some(&[0x81, 0x00]) {
        complete_csum(f);
        return nic.send(f);
    }
    plain(f, off).iter().fold(true, |ok, p| nic.send(p) && ok)
}
