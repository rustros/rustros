//! The WebAssembly application ABI shared by the host (kernel) and the guest
//! library: import module name, exported entry points and error codes.
//!
//! Every import takes and returns only i32/i64; pointers are offsets into the
//! guest's linear memory. Negative return values are errors: for the socket
//! imports `-errno` (Linux's numbers, crate::socket::Errno), for the others
//! the codes below.
//!
//! Socket addresses cross as SOCKADDR bytes: family (u16 LE), port (u16 LE),
//! then 4 (IPv4) or 16 (IPv6) address bytes, flowinfo and scope id (u32 LE).

use crate::sys::KvError;

pub const MODULE: &str = "rustros";

// guest exports
pub const EXPORT_START: &str = "rustros_start";
pub const EXPORT_POLL: &str = "rustros_poll";
pub const EXPORT_KEY: &str = "rustros_key";
/// Optional (packet apps): the host copies a received frame to
/// `rustros_frame_buf() + HEADROOM` and calls `rustros_frame(len) -> i32`, which
/// returns FRAME_PASS / FRAME_DROP / FRAME_CONSUMED, or `start << 16 | len`
/// (> 0) to transmit `buf[start..start + len]`. The buffer is
/// `HEADROOM + FRAME_BUF` bytes.
pub const EXPORT_FRAME: &str = "rustros_frame";
pub const EXPORT_FRAME_BUF: &str = "rustros_frame_buf";
pub const FRAME_BUF: usize = 2048;
pub const FRAME_PASS: i32 = 0;
pub const FRAME_DROP: i32 = -1;
pub const FRAME_CONSUMED: i32 = -2;

pub const E_NO_STORAGE: i32 = -10;
pub const E_KV_TOO_LARGE: i32 = -11;
pub const E_FULL: i32 = -12;
pub const E_IO: i32 = -13;
pub const E_NOT_FOUND: i32 = -20;
/// Bad pointer/length from the guest.
pub const E_FAULT: i32 = -21;
/// The app was not granted the capability this call needs.
pub const E_DENIED: i32 = -22;


pub fn kv_err(e: KvError) -> i32 {
    match e {
        KvError::NoStorage => E_NO_STORAGE,
        KvError::TooLarge => E_KV_TOO_LARGE,
        KvError::Full => E_FULL,
        KvError::Io => E_IO,
    }
}

pub fn to_kv_err(code: i32) -> KvError {
    match code {
        E_NO_STORAGE => KvError::NoStorage,
        E_KV_TOO_LARGE => KvError::TooLarge,
        E_FULL => KvError::Full,
        _ => KvError::Io,
    }
}

/// `net_info` buffer layout (little endian), NET_INFO_LEN bytes:
/// mac[6] pad[2] ip mask gw mtu (u32) rx tx rx_dropped tx_dropped (u64)
pub const NET_INFO_LEN: usize = 56;
/// `arp_table` entry: ip u32, mac[6], pad[2], age_ms u32
pub const ARP_ENTRY_LEN: usize = 16;
/// `storage_info`: partition, store, live, log bytes (u64 each)
pub const STORAGE_INFO_LEN: usize = 32;
/// `update_info`: slot u8, trial u8, safe_mode u8, unstable_boots u8, pad[4], max_bytes u64
pub const UPDATE_INFO_LEN: usize = 16;

/// Bytes of a socket address in guest memory (room for IPv6).
pub const SOCKADDR: usize = 28;

/// A socket address as bytes (SOCKADDR long).
pub fn sockaddr_bytes(a: &crate::socket::SockAddr) -> [u8; SOCKADDR] {
    use crate::socket::SockAddr;
    let mut b = [0u8; SOCKADDR];
    b[0..2].copy_from_slice(&(a.family() as u16).to_le_bytes());
    b[2..4].copy_from_slice(&a.port().to_le_bytes());
    match *a {
        SockAddr::V4 { addr, .. } => b[4..8].copy_from_slice(&addr),
        SockAddr::V6 { addr, flowinfo, scope_id, .. } => {
            b[4..20].copy_from_slice(&addr);
            b[20..24].copy_from_slice(&flowinfo.to_le_bytes());
            b[24..28].copy_from_slice(&scope_id.to_le_bytes());
        }
    }
    b
}

/// A socket address from bytes; None for an unknown family.
pub fn sockaddr_from(b: &[u8; SOCKADDR]) -> Option<crate::socket::SockAddr> {
    use crate::socket::{AF_INET, AF_INET6, SockAddr};
    let port = u16::from_le_bytes([b[2], b[3]]);
    let u32le = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    match u16::from_le_bytes([b[0], b[1]]) as i32 {
        AF_INET => Some(SockAddr::V4 { addr: [b[4], b[5], b[6], b[7]], port }),
        AF_INET6 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&b[4..20]);
            Some(SockAddr::V6 { addr, port, flowinfo: u32le(20), scope_id: u32le(24) })
        }
        _ => None,
    }
}
