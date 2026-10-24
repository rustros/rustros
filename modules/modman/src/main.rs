#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the installed modules' bookkeeping, replacing the boot image's
rustros_module::export_many!(Export::Manager(Box::new(modman::Manager::new())));
