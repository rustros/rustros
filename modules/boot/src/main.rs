#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the boot modules: one binary with the disk and NIC drivers, the storage
// service, the network stack, the module manager and three apps (their code shared)
rustros_module::export_many!(
    Export::Driver(Box::new(virtio::blk::BlkDriver)),
    Export::Driver(Box::new(virtio::net::NetDriver)),
    Export::Storage(Box::new(storage::service::Service::new())),
    Export::NetStack(Box::new(netstack::Stack::new([0; 6], 0, 0, 0))),
    Export::Manager(Box::new(modman::Manager::new())),
    Export::Module(Box::new(rescue::Rescue::new())),
    Export::Module(Box::new(dhcp::Dhcp::new())),
    Export::Module(Box::new(updater::Updater::new())),
);
