#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the boot disk's services (grubenv, kernel slots, the key-value store,
// the console log, the files partition), replacing the boot image's
rustros_module::export_many!(Export::Storage(Box::new(storage::service::Service::new())));
