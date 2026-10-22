//! The RustROS network stack (Ethernet, ARP, IPv4, ICMP, UDP, TCP) and the
//! socket layer that shares it between applications. Run by the kernel.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod iface;
pub mod stack;
pub mod tcp;

pub use stack::Stack;

/// Low-level services the network stack needs from the kernel.
pub trait Link {
    fn now_ms(&self) -> u64;
    /// Transmit one Ethernet frame (without FCS) on NIC `nic`. False if the
    /// TX ring is full.
    fn send(&mut self, nic: usize, frame: &[u8]) -> bool;
    /// Not cryptographically strong; fine for ISNs and port numbers.
    fn random(&mut self) -> u64;
}
