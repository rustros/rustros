//! The RustROS network stack (Ethernet, ARP, IPv4, ICMP, UDP, TCP) and the
//! socket layer that shares it between applications. A boot module provides
//! it to the kernel (`rustros_api::module::NetStack`).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod iface;
pub mod stack;
pub mod tcp;

pub use stack::Stack;

/// What the stack needs from the kernel.
pub use rustros_api::module::Link;
