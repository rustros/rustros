#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the virtio disk and NIC drivers, replacing the boot image's (their
// devices are reset and taken again)
rustros_module::export_many!(Export::Driver(Box::new(virtio::blk::BlkDriver)), Export::Driver(Box::new(virtio::net::NetDriver)));
