//! The RustROS application interface: what an application implements (`Module`)
//! and what the system offers it (`Sys`), plus the WebAssembly ABI. No
//! dependencies, so applications, the kernel and the WebAssembly guest
//! library all share exactly these definitions.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod abi;
pub mod frame;
pub mod module;
pub mod sys;

pub use frame::{Frame, HEADROOM, Verdict};

// Native modules are only loaded by a kernel built from the same rustc and
// the same rustros-api (see build.rs).
include!(concat!(env!("OUT_DIR"), "/fingerprint.rs"));
pub use sys::*;
