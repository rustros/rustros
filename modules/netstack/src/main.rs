#![no_std]
#![no_main]

use rustros_module::Box;
use rustros_module::rustros_api::module::Export;

// the network stack at full speed, with the state handover: it replaces the
// boot image's bootstrap stack at boot, and the next version replaces it
// while it runs, open connections and all
rustros_module::export_many!(Export::NetStack(Box::new(netstack::Stack::new([0; 6], 0, 0, 0))));
