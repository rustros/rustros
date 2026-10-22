#![no_std]
#![no_main]

rustros_module::export_filesystem!(ext4fs::Ext4::new());
