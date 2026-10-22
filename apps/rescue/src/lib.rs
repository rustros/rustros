//! The built-in rescue console: just enough to get a broken system back on
//! the network and fix its modules. It owns the console when no installed
//! module claims it (Caps::CONSOLE), and always after Ctrl-].
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;


use rustros_api::{Admin, Caps, Module, ModuleKind, Sys, say};

use rustros_util::netcmd;

#[derive(Default)]
pub struct Rescue {
    edit: rustros_util::lineedit::LineEdit,
    ask: Option<netcmd::Ask>,
}

impl Rescue {
    pub fn new() -> Rescue {
        Rescue::default()
    }
}

fn admin(sys: &mut dyn Sys) -> &mut dyn Admin {
    sys.admin().expect("the rescue console is granted ADMIN")
}

fn command(sys: &mut dyn Sys, line: &str) {
    let mut args = line.split_ascii_whitespace();
    let Some(cmd) = args.next() else { return };
    match cmd {
        "help" => say!(
            sys,
            "rescue console (Ctrl-] switches to and from a console module such as the shell):\n  ip                    all NICs\n  ip [nicN] a.b.c.d/n [gw] | none\n  ip [nicN] add|del a.b.c.d   extra addresses\n  mtu [nicN] <n>\n  cand ip|mtu ...        change the candidate only; cand shows it\n  apply [s]             candidate in effect, then asks; reverted if not kept in 10 s\n  revert / discard\n  save                  keep the running network settings across reboots\n  modules               running modules\n  mod                   installed modules\n  mod rm <name> [native|wasm]\n  mod switch <name> native|wasm\n  slot / confirm        kernel slots\n  crash [clear]         last recorded crash\n  log [prev|this|<boot> [lines]]  console log of a boot (40 lines)\n  reboot / poweroff\n"
        ),
        "modules" => {
            let m = sys.modules();
            say!(sys, "{}\n", m.join(", "));
        }
        "mod" => match (args.next(), args.next(), args.next()) {
            (None, _, _) => {
                for m in admin(sys).module_list() {
                    let running = m.running.map_or("not running", |k| k.as_str());
                    say!(sys, "{:<12} {:<12} prefers {}\n", m.name, running, m.preferred.as_str());
                    if let Some(why) = &m.native_off {
                        say!(sys, "             native switched off after a crash: {}\n", why);
                    }
                }
            }
            (Some("rm"), Some(name), kind) => match kind.map(ModuleKind::parse) {
                Some(None) => say!(sys, "kind must be native or wasm\n"),
                kind => {
                    let ok = admin(sys).module_remove(name, kind.flatten());
                    say!(sys, "{}\n", if ok { "removed" } else { "no such module" });
                }
            },
            (Some("switch"), Some(name), Some(kind)) => match ModuleKind::parse(kind).map(|k| admin(sys).module_switch(name, k)) {
                Some(Ok(())) => say!(sys, "switching\n"),
                Some(Err(e)) => say!(sys, "{}\n", e),
                None => say!(sys, "kind must be native or wasm\n"),
            },
            _ => say!(sys, "usage: mod | mod rm <name> [native|wasm] | mod switch <name> native|wasm\n"),
        },
        "slot" => match sys.update_info() {
            Some(i) => {
                say!(sys, "running slot {}{}\n", i.slot, if i.trial { " (trial boot, not confirmed)" } else { "" });
                if i.safe_mode {
                    say!(sys, "SAFE MODE ({} unstable boots in a row): installed modules were not started\n", i.unstable_boots);
                }
            }
            None => say!(sys, "no kernel slots\n"),
        },
        "confirm" => {
            // keeps what runs: a network apply waiting for confirmation, and the kernel
            if admin(sys).net_confirm() {
                say!(sys, "network change confirmed (save keeps it across reboots)\n");
            }
            let ok = admin(sys).confirm_boot();
            say!(sys, "{}\n", if ok { "confirmed" } else { "failed" });
        }
        "crash" => match args.next() {
            Some("clear") => {
                let ok = admin(sys).clear_crash();
                say!(sys, "{}\n", if ok { "cleared" } else { "failed" });
            }
            _ => match sys.last_crash() {
                Some(c) => say!(sys, "{}\n", c),
                None => say!(sys, "no crash recorded\n"),
            },
        },
        "log" => {
            let words: alloc::vec::Vec<&str> = args.collect();
            let out = rustros_util::logcmd::run(sys, &words, 40).unwrap_or_else(|e| e);
            sys.print(&out);
        }
        "reboot" => admin(sys).reboot(),
        "poweroff" | "shutdown" => admin(sys).poweroff(),
        _ => say!(sys, "unknown command '{}', try help\n", cmd),
    }
}

impl Module for Rescue {
    fn poll(&mut self, sys: &mut dyn Sys) {
        if self.ask.is_some() {
            netcmd::console_tick(sys, &mut self.ask);
            if self.ask.is_none() {
                say!(sys, "rescue> ");
            }
        }
    }

    fn name(&self) -> &'static str {
        "rescue"
    }

    fn caps(&self) -> Caps {
        Caps::NET | Caps::ADMIN
    }

    fn key(&mut self, sys: &mut dyn Sys, c: u8) {
        match c {
            _ => {
                const COMMANDS: &[&str] = &["help", "ip", "mtu", "cand", "apply", "revert", "confirm", "discard", "save", "modules", "mod", "slot", "crash", "log", "reboot", "poweroff"];
                if let Some(line) = self.edit.key(sys, c, "rescue> ", &|s, w| netcmd::complete(s, w, COMMANDS)) {
                    if !netcmd::console_line(sys, &mut self.ask, &line) {
                        command(sys, &line);
                    }
                    if self.ask.is_none() {
                        say!(sys, "rescue> "); // else a question is showing
                    }
                }
            }
        }
    }
}
