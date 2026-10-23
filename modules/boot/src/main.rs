#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the boot modules: one binary, the disk driver and three apps (their code shared)
rustros_module::export_many!(
    Export::Driver(Box::new(virtio::blk::BlkDriver)),
    Export::Module(Box::new(rescue::Rescue::new())),
    Export::Module(Box::new(dhcp::Dhcp::new())),
    Export::Module(Box::new(updater::Updater::new())),
);
