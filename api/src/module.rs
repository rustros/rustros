//! Loadable native modules and application runtimes.
//!
//! A native module is a position-independent ELF built for
//! `x86_64-unknown-none` (see `modules/`). The kernel copies it into memory,
//! applies its relative relocations and calls `rustros_module_init`:
//!
//! ```text
//! extern "C" fn rustros_module_init(host: *const HostTable, out: *mut Option<Export>) -> u64
//! ```
//!
//! Only plain C values cross until both sides have checked that their
//! `API_FINGERPRINT`s match; after that they talk through Rust trait objects
//! (`Box<dyn Module>`, `&mut dyn Sys`), with no copying or marshalling. Native
//! modules are trusted code: they run in the kernel's address space.

use alloc::boxed::Box;
use alloc::string::String;

use crate::sys::Module;

pub const ENTRY: &str = "rustros_module_init";

/// What the kernel gives a module. The module routes its heap through these
/// so that boxes may be freed on either side.
#[repr(C)]
pub struct HostTable {
    pub fingerprint: u64,
    pub alloc: extern "C" fn(size: usize, align: usize) -> *mut u8,
    pub dealloc: extern "C" fn(ptr: *mut u8, size: usize, align: usize),
    pub realloc: extern "C" fn(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8,
    /// Fatal error in the module (its panic handler): record and reboot.
    pub crash: extern "C" fn(msg: *const u8, len: usize) -> !,
}

/// What a module provides.
pub enum Export {
    Module(Box<dyn Module>),
    /// Runs applications in another format (the WebAssembly runtime).
    Runtime(Box<dyn Runtime>),
}

/// An application runtime: turns application images of its format into apps.
pub trait Runtime {
    /// Short name of the format ("wasm").
    fn format(&self) -> &'static str;
    /// Whether `image` is in this runtime's format (magic number check).
    fn accepts(&self, image: &[u8]) -> bool;
    /// Full check of an image before it is stored.
    fn validate(&self, image: &[u8]) -> Result<(), String>;
    /// A new app instance called `name` running `image`.
    fn instantiate(&mut self, name: &'static str, image: &[u8]) -> Result<Box<dyn Module>, String>;
}
