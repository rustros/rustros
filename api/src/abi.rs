//! The WebAssembly application ABI shared by the host (kernel) and the guest
//! library: import module name, exported entry points and error codes.
//!
//! Every import takes and returns only i32/i64; pointers are offsets into the
//! guest's linear memory. Negative return values are errors (below).

use crate::sys::{KvError, NetError};

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

pub const E_WOULD_BLOCK: i32 = -1;
pub const E_ADDR_IN_USE: i32 = -2;
pub const E_BAD_HANDLE: i32 = -3;
pub const E_CLOSED: i32 = -4;
pub const E_TOO_LARGE: i32 = -5;
pub const E_NO_ROUTE: i32 = -6;
pub const E_NO_STORAGE: i32 = -10;
pub const E_KV_TOO_LARGE: i32 = -11;
pub const E_FULL: i32 = -12;
pub const E_IO: i32 = -13;
pub const E_NOT_FOUND: i32 = -20;
/// Bad pointer/length from the guest.
pub const E_FAULT: i32 = -21;
/// The app was not granted the capability this call needs.
pub const E_DENIED: i32 = -22;

pub fn net_err(e: NetError) -> i32 {
    match e {
        NetError::WouldBlock => E_WOULD_BLOCK,
        NetError::AddrInUse => E_ADDR_IN_USE,
        NetError::BadHandle => E_BAD_HANDLE,
        NetError::Closed => E_CLOSED,
        NetError::TooLarge => E_TOO_LARGE,
        NetError::NoRoute => E_NO_ROUTE,
    }
}

pub fn to_net_err(code: i64) -> NetError {
    match code as i32 {
        E_WOULD_BLOCK => NetError::WouldBlock,
        E_ADDR_IN_USE => NetError::AddrInUse,
        E_CLOSED => NetError::Closed,
        E_TOO_LARGE => NetError::TooLarge,
        E_NO_ROUTE => NetError::NoRoute,
        _ => NetError::BadHandle,
    }
}

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
