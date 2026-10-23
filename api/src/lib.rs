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
pub mod socket;
pub mod sys;

pub use frame::{Frame, HEADROOM, Offload, Verdict};

// Native modules are only loaded by a kernel built from the same rustc and
// the same rustros-api (see build.rs).
include!(concat!(env!("OUT_DIR"), "/fingerprint.rs"));
pub use sys::*;

/// The release this was built for: `RUSTROS_BUILD` at build time (a release's
/// calendar version, "2026.10.22.1"), else the crate version. Each module
/// compiles its own copy, so it says the module's release.
pub const BUILD: &str = match option_env!("RUSTROS_BUILD") {
    Some(b) => b,
    None => env!("CARGO_PKG_VERSION"),
};
