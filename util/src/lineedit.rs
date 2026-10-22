//! Line input for the consoles: backspace, command history on the up and
//! down arrow keys (the kernel turns both PS/2 and serial arrows into
//! `KEY_UP` / `KEY_DOWN`), and Tab completion.

use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{KEY_DOWN, KEY_UP, Sys};

const HISTORY: usize = 32;
const MAX_LINE: usize = 200;

#[derive(Default)]
pub struct LineEdit {
    line: String,
    history: Vec<String>,
    /// position while browsing the history
    pos: Option<usize>,
    /// what was typed before browsing started
    draft: String,
}

impl LineEdit {
    /// Feed one key; the finished line on Enter. `complete(sys, words)`
    /// gives the candidates for the word after `words` (Tab); `prompt` is
    /// shown again after a list of candidates.
    pub fn key(&mut self, sys: &mut dyn Sys, c: u8, prompt: &str, complete: &dyn Fn(&mut dyn Sys, &[&str]) -> Vec<String>) -> Option<String> {
        match c {
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
                } else if cands.len() > 1 {
                    let list = cands.join("  ");
                    sys.print(&alloc::format!("\n{list}\n{prompt}{}", self.line));
                }
            }
            b'\n' => {
                sys.print("\n");
                let line = core::mem::take(&mut self.line);
                if !line.trim().is_empty() && self.history.last() != Some(&line) {
                    if self.history.len() == HISTORY {
                        self.history.remove(0);
                    }
                    self.history.push(line.clone());
                }
                self.pos = None;
                return Some(line);
            }
            8 => {
                if self.line.pop().is_some() {
                    sys.print("\x08");
                }
            }
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
                self.line.push(c as char);
                let mut b = [0u8; 4];
                sys.print((c as char).encode_utf8(&mut b));
            }
            _ => {}
        }
        None
    }

    /// Show `new` in place of what was typed.
    fn replace(&mut self, sys: &mut dyn Sys, new: String) {
        let erase: String = core::iter::repeat_n('\x08', self.line.chars().count()).collect();
        sys.print(&erase);
        sys.print(&new);
        self.line = new;
    }
}
