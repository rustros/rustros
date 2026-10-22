//! The `log` command (consoles and the updater's remote `log`): the console
//! logs of the last boots, kept on disk.
//!
//! ```text
//! log                      boots with a log
//! log prev|this|<boot> [lines]   a boot's log (its last `lines` lines)
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::Sys;

/// `args` without the command name; `default_lines` when none are given
/// (0: all).
pub fn run(sys: &mut dyn Sys, args: &[&str], default_lines: usize) -> Result<String, String> {
    let Some(admin) = sys.admin() else { return Err(String::from("not permitted\n")) };
    let Some(this) = admin.log_this_boot() else { return Err(String::from("no log kept (no cache partition)\n")) };
    let boot = match args.first() {
        None => {
            let mut out = String::new();
            for (seq, bytes) in admin.log_list() {
                let rel = match this - seq {
                    0 => String::from("  (this boot)"),
                    1 => String::from("  (prev)"),
                    _ => String::new(),
                };
                out += &alloc::format!("boot {:<6} {:>8} bytes{}\n", seq, bytes, rel);
            }
            return Ok(out);
        }
        Some(&"this") => this,
        Some(&"prev") => this.saturating_sub(1),
        Some(n) => n.parse().map_err(|_| String::from("usage: log [prev|this|<boot> [lines]]\n"))?,
    };
    let lines = match args.get(1) {
        Some(n) => n.parse().map_err(|_| String::from("usage: log [prev|this|<boot> [lines]]\n"))?,
        None => default_lines,
    };
    let text = admin.log_read(boot).ok_or_else(|| alloc::format!("no log of boot {boot}\n"))?;
    let text = String::from_utf8_lossy(&text);
    // drop terminal escapes (the console's colours)
    let clean: String = strip_escapes(&text);
    if lines == 0 {
        return Ok(clean);
    }
    let all: Vec<&str> = clean.lines().collect();
    let from = all.len().saturating_sub(lines);
    Ok(all[from..].iter().map(|l| alloc::format!("{l}\n")).collect())
}

fn strip_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\x1b' => {
                // ESC [ ... letter
                if it.peek() == Some(&'[') {
                    it.next();
                    for d in it.by_ref() {
                        if d.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            '\r' | '\x08' => {}
            _ => out.push(c),
        }
    }
    out
}
