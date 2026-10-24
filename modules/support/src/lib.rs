//! Support library for RustROS native modules: routes the module's heap and
//! panics to the kernel and exports the entry point.
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! rustros_module::export_module!(echo::Echo::new());
//! ```
#![no_std]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;
use core::sync::atomic::{AtomicPtr, Ordering};

pub use alloc::boxed::Box;
pub use alloc::vec as alloc_vec;
pub use rustros_api;
use rustros_api::module::{Export, HostTable};

static HOST: AtomicPtr<HostTable> = AtomicPtr::new(core::ptr::null_mut());

fn host() -> &'static HostTable {
    // Safety: set by `init` before any module code can allocate or panic,
    // and the table is a static in the kernel.
    unsafe { &*HOST.load(Ordering::Relaxed) }
}

struct HostAlloc;

unsafe impl GlobalAlloc for HostAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        (host().alloc)(l.size(), l.align())
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        (host().dealloc)(p, l.size(), l.align())
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        (host().realloc)(p, l.size(), l.align(), new_size)
    }
}

#[global_allocator]
static ALLOC: HostAlloc = HostAlloc;

/// Fixed buffer for the panic message (no allocation while panicking).
struct Msg {
    buf: [u8; 512],
    len: usize,
}

impl Write for Msg {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut m = Msg { buf: [0; 512], len: 0 };
    let _ = write!(m, "panic: {info}");
    // any address inside this module says whose crash it is
    (host().crash)(m.buf.as_ptr(), m.len, panic as fn(&core::panic::PanicInfo) -> ! as usize)
}

/// Entry point body (see `export_module!`): checks the fingerprint, then builds
/// the export. Returns this module's fingerprint either way.
///
/// # Safety
/// `host` and `out` come from the kernel's loader.
#[doc(hidden)]
pub unsafe fn init(host: *const HostTable, out: *mut Option<Export>, make: impl FnOnce() -> Export) -> u64 {
    let fp = rustros_api::API_FINGERPRINT;
    // only C values may be touched until the fingerprints agree
    if host.is_null() || unsafe { (*host).fingerprint } != fp {
        return fp;
    }
    HOST.store(host as *mut HostTable, Ordering::Relaxed);
    unsafe { out.write(Some(make())) };
    fp
}

/// Export an application as this module's content.
#[macro_export]
macro_rules! export_module {
    ($ctor:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rustros_module_init(
            host: *const $crate::rustros_api::module::HostTable,
            out: *mut Option<$crate::rustros_api::module::Export>,
        ) -> u64 {
            unsafe { $crate::init(host, out, || $crate::rustros_api::module::Export::Module($crate::Box::new($ctor))) }
        }
    };
}

/// Export several things from one binary (they share its code): the boot
/// modules' apps and drivers, each an `Export`.
#[macro_export]
macro_rules! export_many {
    ($($export:expr),+ $(,)?) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rustros_module_init(
            host: *const $crate::rustros_api::module::HostTable,
            out: *mut Option<$crate::rustros_api::module::Export>,
        ) -> u64 {
            unsafe { $crate::init(host, out, || $crate::rustros_api::module::Export::Many($crate::alloc_vec![$($export),+])) }
        }
    };
}

/// Export a file system driver.
#[macro_export]
macro_rules! export_filesystem {
    ($ctor:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rustros_module_init(
            host: *const $crate::rustros_api::module::HostTable,
            out: *mut Option<$crate::rustros_api::module::Export>,
        ) -> u64 {
            unsafe { $crate::init(host, out, || $crate::rustros_api::module::Export::Filesystem($crate::Box::new($ctor))) }
        }
    };
}

/// Export an application runtime (e.g. the WebAssembly runtime).
#[macro_export]
macro_rules! export_runtime {
    ($ctor:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rustros_module_init(
            host: *const $crate::rustros_api::module::HostTable,
            out: *mut Option<$crate::rustros_api::module::Export>,
        ) -> u64 {
            unsafe { $crate::init(host, out, || $crate::rustros_api::module::Export::Runtime($crate::Box::new($ctor))) }
        }
    };
}
