#![no_std]
#![no_main]

rustros_module::export_runtime!(wasmhost::WasmRuntime::new());
