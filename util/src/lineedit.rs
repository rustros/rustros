//! Line input for the consoles: a cursor (left / right, Home / End or
//! Ctrl-A / Ctrl-E, Delete), backspace, command history on the up and down
//! arrow keys, and Tab completion. The kernel turns PS/2 and serial cursor
//! keys into `KEY_*` codes and understands ANSI cursor moves on the screen.
//! Secrets are echoed as `*` and kept out of the history: a whole line in
//! `hidden` mode, or the value of `cfg <module> <password key> <value>`.

use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{KEY_DELETE, KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT, KEY_UP, Sys};

use crate::secret;

const HISTORY: usize = 32;
const MAX_LINE: usize = 200;
const LEFT: &str = "\x1b[D";
const RIGHT: &str = "\x1b[C";

#[derive(Default)]
pub struct LineEdit {
    /// what was typed (printable ASCII only, so bytes are columns)
    line: String,
    /// the cursor, a byte index into `line`
    cur: usize,
    history: Vec<String>,
    /// position while browsing the history
    pos: Option<usize>,
    /// what was typed before browsing started
    draft: String,
    /// the next line is a secret: echo `*`, no history, no completion
    pub hidden: bool,
}

impl LineEdit {
    /// The line as shown (secrets as `*`).
    fn shown(&self) -> String {
        if self.hidden { "*".repeat(self.line.len()) } else { secret::masked(&self.line) }
    }

    /// Redraw from column `from` (where the cursor is) to the end, blank
    /// out `gone` columns that were removed, and put the cursor back at `cur`.
    fn redraw(&self, sys: &mut dyn Sys, from: usize, gone: usize) {
        let shown = self.shown();
        let mut out = String::from(&shown[from..]);
        out.push_str(&" ".repeat(gone));
        out.push_str(&LEFT.repeat(shown.len() + gone - self.cur));
        sys.print(&out);
    }

    fn move_to(&mut self, sys: &mut dyn Sys, to: usize) {
        let s = if to < self.cur { LEFT.repeat(self.cur - to) } else { RIGHT.repeat(to - self.cur) };
        sys.print(&s);
        self.cur = to;
    }

    /// Feed one key; the finished line on Enter. `complete(sys, words)`
    /// gives the candidates for the word after `words` (Tab); `prompt` is
    /// shown again after a list of candidates.
    pub fn key(&mut self, sys: &mut dyn Sys, c: u8, prompt: &str, complete: &dyn Fn(&mut dyn Sys, &[&str]) -> Vec<String>) -> Option<String> {
        match c {
            // completion works at the end of the line, never on secrets
            b'\t' if self.hidden || self.cur != self.line.len() || secret::value_start(&self.line).is_some() => {}
            b'\t' => {
                let start = self.line.rfind(' ').map_or(0, |i| i + 1);
                let partial = String::from(&self.line[start..]);
                let words: Vec<&str> = self.line[..start].split_ascii_whitespace().collect();
                let mut cands: Vec<String> = complete(sys, &words).into_iter().filter(|c| c.starts_with(partial.as_str())).collect();
                cands.sort();
                cands.dedup();
                let Some(first) = cands.first() else { return None };
                // the longest prefix all candidates share
                let mut common = first.len();
                for c in &cands[1..] {
                    common = first.bytes().zip(c.bytes()).take(common).take_while(|(a, b)| a == b).count();
                }
                let mut add = String::from(&first[partial.len()..common]);
                if cands.len() == 1 {
                    add.push(' ');
                }
                if !add.is_empty() && self.line.len() + add.len() <= MAX_LINE {
                    sys.print(&add);
                    self.line.push_str(&add);
                    self.cur = self.line.len();
                } else if cands.len() > 1 {
                    let list = cands.join("  ");
                    sys.print(&alloc::format!("\n{list}\n{prompt}{}", self.shown()));
                }
            }
            b'\n' => {
                sys.print("\n");
                let line = core::mem::take(&mut self.line);
                self.cur = 0;
                let secret = core::mem::take(&mut self.hidden) || secret::value_start(&line).is_some();
                if !secret && !line.trim().is_empty() && self.history.last() != Some(&line) {
                    if self.history.len() == HISTORY {
                        self.history.remove(0);
                    }
                    self.history.push(line.clone());
                }
                self.pos = None;
                return Some(line);
            }
            8 if self.cur > 0 => {
                self.line.remove(self.cur - 1);
                self.cur -= 1;
                sys.print(LEFT);
                self.redraw(sys, self.cur, 1);
            }
            KEY_DELETE if self.cur < self.line.len() => {
                self.line.remove(self.cur);
                self.redraw(sys, self.cur, 1);
            }
            KEY_LEFT if self.cur > 0 => self.move_to(sys, self.cur - 1),
            KEY_RIGHT if self.cur < self.line.len() => self.move_to(sys, self.cur + 1),
            KEY_HOME | 1 => self.move_to(sys, 0),
            KEY_END | 5 => self.move_to(sys, self.line.len()),
            KEY_UP | KEY_DOWN if self.hidden => {}
            KEY_UP if !self.history.is_empty() => {
                let p = match self.pos {
                    None => {
                        self.draft = self.line.clone();
                        self.history.len() - 1
                    }
                    Some(p) => p.saturating_sub(1),
                };
                self.pos = Some(p);
                let l = self.history[p].clone();
                self.replace(sys, l);
            }
            KEY_DOWN => match self.pos {
                Some(p) if p + 1 < self.history.len() => {
                    self.pos = Some(p + 1);
                    let l = self.history[p + 1].clone();
                    self.replace(sys, l);
                }
                Some(_) => {
                    self.pos = None;
                    let d = core::mem::take(&mut self.draft);
                    self.replace(sys, d);
                }
                None => {}
            },
            32..=126 if self.line.len() < MAX_LINE => {
                self.line.insert(self.cur, c as char);
                let from = self.cur;
                self.cur += 1;
                self.redraw(sys, from, 0);
            }
            _ => {}
        }
        None
    }

    /// Show `new` in place of what was typed, the cursor at its end.
    fn replace(&mut self, sys: &mut dyn Sys, new: String) {
        self.move_to(sys, 0);
        let gone = self.line.len().saturating_sub(new.len());
        self.line = new;
        self.cur = self.line.len();
        self.redraw(sys, 0, gone);
    }
}
