#[link(wasm_import_module = "rustros")]
unsafe extern "C" {
    fn kv_put(kp: *const u8, kn: usize, vp: *const u8, vn: usize) -> i32;
}

/// A key and value pointing outside linear memory: the host must answer
/// E_FAULT and carry on.
fn bad_pointer() -> i32 {
    unsafe { kv_put(0xFFFF_0000usize as *const u8, 100, 0xFFFF_FF00usize as *const u8, 1 << 20) }
}

rustros_guest::export_module!(crashy::Crashy::with_bad_pointer_probe(bad_pointer));
