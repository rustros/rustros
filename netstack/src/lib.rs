//! The RustROS network stack (Ethernet, ARP, IPv4, ICMP, UDP, TCP) and the
//! socket layer that shares it between applications. A boot module provides
//! it to the kernel (`rustros_api::module::NetStack`). The per-packet part
//! (interfaces, TCP) is the `tcpip` crate, built for speed; this crate is
//! built for size.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod config;
#[cfg(feature = "handover")]
pub mod handover;
pub mod socket;
pub mod stack;

pub use tcpip::{iface, tcp};

pub use stack::Stack;

/// What the stack needs from the kernel.
pub use rustros_api::module::Link;
