//! Helpers for RustROS applications (and the network stack): buffered TCP
//! connections, wire-format and address helpers, SHA-256/HMAC.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod base64;
pub mod conn;
pub mod dns;
pub mod json;
pub mod lineedit;
pub mod logcmd;
pub mod netcmd;
pub mod netconf;
pub mod offload;
pub mod pem;
pub mod secret;
pub mod sha256;
pub mod sort;
pub mod wire;
