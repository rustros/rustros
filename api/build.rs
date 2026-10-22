//! API_FINGERPRINT: a hash of the compiler version and this crate's sources.
//! Native modules talk to the kernel through Rust trait objects, which have no
//! stable ABI, so a module is only loaded by a kernel with the same
//! fingerprint (same rustc, same rustros-api).
use std::{env, fs, path::Path, process::Command};

fn fnv(h: &mut u64, data: &[u8]) {
    for b in data {
        *h ^= *b as u64;
        *h = h.wrapping_mul(0x100_0000_01b3);
    }
}

fn main() {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = Command::new(rustc).arg("-vV").output().map(|o| o.stdout).unwrap_or_default();
    fnv(&mut h, &version);
    let dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");
    let mut files: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    for f in files {
        fnv(&mut h, f.file_name().unwrap().to_string_lossy().as_bytes());
        fnv(&mut h, &fs::read(&f).unwrap());
        println!("cargo:rerun-if-changed={}", f.display());
    }
    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("fingerprint.rs");
    fs::write(out, format!("pub const API_FINGERPRINT: u64 = {h:#x};\n")).unwrap();
}
