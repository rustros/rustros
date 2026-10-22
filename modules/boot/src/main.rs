#![no_std]
#![no_main]

// the boot modules: one binary, three apps (their code shared)
rustros_module::export_apps!(rescue::Rescue::new(), dhcp::Dhcp::new(), updater::Updater::new());
