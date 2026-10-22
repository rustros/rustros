fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld");
    // no page-aligned file offsets: the image goes into a 256 KiB slot
    println!("cargo:rustc-link-arg-bins=-n");
    println!("cargo:rerun-if-changed=linker.ld");
}
