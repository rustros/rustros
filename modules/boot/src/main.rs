#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the boot modules: one binary with the disk and NIC drivers, the storage
// service and three apps (their code shared)
rustros_module::export_many!(
    Export::Driver(Box::new(virtio::blk::BlkDriver)),
    Export::Driver(Box::new(virtio::net::NetDriver)),
    Export::Storage(Box::new(storage::service::Service::new())),
    Export::Module(Box::new(rescue::Rescue::new())),
    Export::Module(Box::new(dhcp::Dhcp::new())),
    Export::Module(Box::new(updater::Updater::new())),
);
