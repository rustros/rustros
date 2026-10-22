//! Helpers for RustROS applications (and the network stack): buffered TCP
//! connections, wire-format and address helpers, SHA-256/HMAC.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod conn;
pub mod lineedit;
pub mod logcmd;
pub mod netcmd;
pub mod secret;
pub mod sha256;
pub mod wire;
