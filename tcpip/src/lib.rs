//! The per-packet part of the network stack: the IPv4 interfaces (Ethernet,
//! ARP, IP, ICMP, routes) and TCP. Built for speed (-O3); the socket table,
//! the configuration and the rest around it (`netstack`) are built for size,
//! so the boot image keeps fitting its slots.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod iface;
pub mod tcp;

/// What the stack needs from the kernel.
pub use rustros_api::module::Link;
