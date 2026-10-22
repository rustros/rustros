//! Console: COM1 serial + framebuffer / VGA text output, serial + PS/2 keyboard input.

use core::fmt::{self, Write};

use crate::Global;
use crate::arch::{inb, outb};
use crate::font::FONT;
use crate::multiboot::Framebuffer;

const COM1: u16 = 0x3F8;
const FG: (u8, u8, u8) = (0xCC, 0xCC, 0xCC);
const BG: (u8, u8, u8) = (0x10, 0x10, 0x18);

enum Screen {
    None,
    Text { base: *mut u16, cols: usize, rows: usize },
    Fb { base: *mut u8, pitch: usize, bpp: usize, fg: u32, bg: u32, cols: usize, rows: usize },
}

pub struct Console {
    serial: bool,
    kbd: bool,
    screen: Screen,
    col: usize,
    row: usize,
    shift: bool,
    ctrl: bool,
    e0: bool,
    /// serial input escape sequence: 1 after ESC, 2 after ESC [ (then the
    /// number of `ESC [ n ~`), 3 after ESC O
    esc: u8,
    esc_num: u8,
    /// output escape sequence for the screen: 1 after ESC, 2 after ESC [
    out_esc: u8,
    /// nobody drains the serial port: no more waiting for it (output
    /// queues in `sbuf`) until it has room again
    serial_stuck: bool,
    /// serial output not sent yet: a ring, the oldest dropped when full
    /// (the screen and the log keep everything)
    sbuf: [u8; SBUF],
    shead: usize,
    slen: usize,
}

const SBUF: usize = 16384;

static CON: Global<Console> = Global::new(Console {
    serial: false,
    kbd: false,
    screen: Screen::None,
    col: 0,
    row: 0,
    shift: false,
    ctrl: false,
    e0: false,
    esc: 0,
    esc_num: 0,
    out_esc: 0,
    serial_stuck: false,
    sbuf: [0; SBUF],
    shead: 0,
    slen: 0,
});

fn con() -> &'static mut Console {
    // Safety: single core; only the main loop prints (exception handlers print
    // and then halt for good).
    unsafe { CON.get() }
}

fn pack(fb: &Framebuffer, (r, g, b): (u8, u8, u8)) -> u32 {
    let ch = |v: u8, (pos, size): (u8, u8)| ((v as u32) >> (8 - size.min(8))) << pos;
    ch(r, fb.red) | ch(g, fb.green) | ch(b, fb.blue)
}

pub fn init(fb: Option<Framebuffer>, efi: bool) {
    let c = con();
    unsafe {
        // COM1: 115200 8N1, FIFO on. Probe with the scratch register first.
        outb(COM1 + 7, 0x5A);
        if inb(COM1 + 7) == 0x5A {
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x80);
            outb(COM1, 0x01);
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03);
            outb(COM1 + 2, 0xC7);
            outb(COM1 + 4, 0x03);
            c.serial = true;
        }
        c.kbd = inb(0x64) != 0xFF;
    }
    c.screen = match fb {
        Some(f) if f.kind == 1 && matches!(f.bpp, 16 | 24 | 32) => {
            let size = f.pitch as u64 * f.height as u64;
            if crate::mem::map_identity(f.addr, size) {
                let mut f = f;
                if f.red.1 == 0 {
                    // no color info: assume xRGB
                    f.red = (16, 8);
                    f.green = (8, 8);
                    f.blue = (0, 8);
                }
                Screen::Fb {
                    base: f.addr as *mut u8,
                    pitch: f.pitch as usize,
                    bpp: f.bpp as usize / 8,
                    fg: pack(&f, FG),
                    bg: pack(&f, BG),
                    cols: f.width as usize / 8,
                    rows: f.height as usize / 16,
                }
            } else {
                Screen::None
            }
        }
        Some(f) if f.kind == 2 => {
            Screen::Text { base: f.addr as *mut u16, cols: f.width as usize, rows: f.height as usize }
        }
        // legacy BIOS boot without a framebuffer tag: VGA text mode is still there
        None if !efi => Screen::Text { base: 0xB8000 as *mut u16, cols: 80, rows: 25 },
        _ => Screen::None,
    };
    clear();
}

impl Console {
    fn dims(&self) -> (usize, usize) {
        match self.screen {
            Screen::None => (0, 0),
            Screen::Text { cols, rows, .. } | Screen::Fb { cols, rows, .. } => (cols, rows),
        }
    }

    fn put_px(&self, x: usize, y: usize, color: u32) {
        if let Screen::Fb { base, pitch, bpp, .. } = self.screen {
            unsafe {
                let p = base.add(y * pitch + x * bpp);
                match bpp {
                    4 => (p as *mut u32).write_volatile(color),
                    3 => {
                        p.write_volatile(color as u8);
                        p.add(1).write_volatile((color >> 8) as u8);
                        p.add(2).write_volatile((color >> 16) as u8);
                    }
                    _ => (p as *mut u16).write_volatile(color as u16),
                }
            }
        }
    }

    fn draw(&self, col: usize, row: usize, ch: u8) {
        match self.screen {
            Screen::None => {}
            Screen::Text { base, cols, .. } => unsafe {
                base.add(row * cols + col).write_volatile(0x0700 | ch as u16);
            },
            Screen::Fb { fg, bg, .. } => {
                let ch = if (32..127).contains(&ch) { ch } else { b'?' };
                let glyph = &FONT[ch as usize * 16..ch as usize * 16 + 16];
                for (y, bits) in glyph.iter().enumerate() {
                    for x in 0..8 {
                        let on = bits & (0x80 >> x) != 0;
                        self.put_px(col * 8 + x, row * 16 + y, if on { fg } else { bg });
                    }
                }
            }
        }
    }

    fn cursor(&self, show: bool) {
        let (cols, rows) = self.dims();
        if self.col >= cols || self.row >= rows {
            return;
        }
        match self.screen {
            Screen::Fb { fg, bg, .. } => {
                for y in 13..15 {
                    for x in 0..8 {
                        self.put_px(self.col * 8 + x, self.row * 16 + y, if show { fg } else { bg });
                    }
                }
            }
            Screen::Text { cols, .. } => unsafe {
                let pos = (self.row * cols + self.col) as u16;
                outb(0x3D4, 0x0F);
                outb(0x3D5, pos as u8);
                outb(0x3D4, 0x0E);
                outb(0x3D5, (pos >> 8) as u8);
            },
            Screen::None => {}
        }
    }

    fn scroll(&mut self) {
        let (cols, rows) = self.dims();
        match self.screen {
            Screen::None => {}
            Screen::Text { base, .. } => unsafe {
                core::ptr::copy(base.add(cols), base, cols * (rows - 1));
                for c in 0..cols {
                    base.add((rows - 1) * cols + c).write_volatile(0x0720);
                }
            },
            Screen::Fb { base, pitch, .. } => unsafe {
                core::ptr::copy(base.add(16 * pitch), base, pitch * 16 * (rows - 1));
                for c in 0..cols {
                    self.draw(c, rows - 1, b' ');
                }
            },
        }
        self.row = rows - 1;
    }

    fn screen_putc(&mut self, ch: u8) {
        let (cols, rows) = self.dims();
        if cols == 0 {
            return;
        }
        // the line editor's ANSI codes: ESC [ D (left), C (right), K (erase
        // to the end of the line)
        match (self.out_esc, ch) {
            (0, 0x1B) => {
                self.out_esc = 1;
                return;
            }
            (1, b'[') => {
                self.out_esc = 2;
                return;
            }
            (2, b'0'..=b'9' | b';') => return,
            (2, f) => {
                self.out_esc = 0;
                match f {
                    b'D' => self.col = self.col.saturating_sub(1),
                    b'C' => self.col = (self.col + 1).min(cols - 1),
                    b'K' => {
                        for c in self.col..cols {
                            self.draw(c, self.row, b' ');
                        }
                    }
                    _ => {}
                }
                return;
            }
            (1, _) => self.out_esc = 0,
            _ => {}
        }
        match ch {
            b'\n' => {
                self.col = 0;
                self.row += 1;
            }
            b'\r' => self.col = 0,
            8 => {
                if self.col > 0 {
                    self.col -= 1;
                    self.draw(self.col, self.row, b' ');
                }
            }
            b'\t' => self.col = (self.col + 8) & !7,
            _ => {
                if self.col >= cols {
                    self.col = 0;
                    self.row += 1;
                }
                if self.row >= rows {
                    self.scroll();
                }
                self.draw(self.col, self.row, ch);
                self.col += 1;
            }
        }
        if self.row >= rows {
            self.scroll();
        }
    }

    fn serial_putc(&mut self, ch: u8) {
        if !self.serial {
            return;
        }
        if self.slen == SBUF {
            self.shead = (self.shead + 1) % SBUF;
            self.slen -= 1;
        }
        self.sbuf[(self.shead + self.slen) % SBUF] = ch;
        self.slen += 1;
    }

    /// Queued output to the UART, 16 bytes (its FIFO) whenever it is empty.
    /// `patient`: wait a little for it (never long: a serial line nobody
    /// reads must not stall the system); else only what it takes now.
    fn serial_drain(&mut self, patient: bool) {
        while self.slen > 0 {
            unsafe {
                let mut ready = inb(COM1 + 5) & 0x20 != 0;
                if !ready && patient && !self.serial_stuck {
                    for _ in 0..2000 {
                        if inb(COM1 + 5) & 0x20 != 0 {
                            ready = true;
                            break;
                        }
                    }
                    self.serial_stuck = !ready;
                }
                if !ready {
                    return;
                }
                self.serial_stuck = false;
                for _ in 0..self.slen.min(16) {
                    outb(COM1, self.sbuf[self.shead]);
                    self.shead = (self.shead + 1) % SBUF;
                    self.slen -= 1;
                }
            }
        }
    }

    fn write_bytes(&mut self, s: &[u8]) {
        crate::klog::append(s);
        self.cursor(false);
        for &ch in s {
            if ch == b'\n' {
                self.serial_putc(b'\r');
            }
            if ch == 8 {
                // erase on serial terminals too
                self.serial_putc(8);
                self.serial_putc(b' ');
            }
            self.serial_putc(ch);
            self.screen_putc(ch);
        }
        self.serial_drain(true);
        self.cursor(true);
    }

    fn kbd_getc(&mut self) -> Option<u8> {
        const MAP: &[u8; 58] = b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
        const SHIFT: &[u8; 58] = b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";
        if !self.kbd {
            return None;
        }
        let st = unsafe { inb(0x64) };
        if st & 1 == 0 {
            return None;
        }
        let sc = unsafe { inb(0x60) };
        if st & 0x20 != 0 {
            return None; // mouse byte
        }
        if sc == 0xE0 {
            self.e0 = true;
            return None;
        }
        let e0 = core::mem::replace(&mut self.e0, false);
        let release = sc & 0x80 != 0;
        match sc & 0x7F {
            0x2A | 0x36 => self.shift = !release,
            0x1D => self.ctrl = !release,
            0x48 if e0 && !release => return Some(rustros_api::KEY_UP),
            0x50 if e0 && !release => return Some(rustros_api::KEY_DOWN),
            0x4B if e0 && !release => return Some(rustros_api::KEY_LEFT),
            0x4D if e0 && !release => return Some(rustros_api::KEY_RIGHT),
            0x47 if e0 && !release => return Some(rustros_api::KEY_HOME),
            0x4F if e0 && !release => return Some(rustros_api::KEY_END),
            0x53 if e0 && !release => return Some(rustros_api::KEY_DELETE),
            _ if release || e0 => {}
            k if (k as usize) < MAP.len() => {
                let ch = if self.shift { SHIFT[k as usize] } else { MAP[k as usize] };
                if self.ctrl && ch == b']' {
                    return Some(0x1D);
                }
                if self.ctrl && ch.is_ascii_alphabetic() {
                    return Some(ch.to_ascii_lowercase() - b'a' + 1);
                }
                if ch != 0 {
                    return Some(ch);
                }
            }
            _ => {}
        }
        None
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

pub fn print(args: fmt::Arguments) {
    let _ = con().write_fmt(args);
}

pub fn write_str(s: &str) {
    con().write_bytes(s.as_bytes());
}

/// Non-blocking read from serial or keyboard.
pub fn getc() -> Option<u8> {
    let c = con();
    // (called every pass of the main loop: queued output goes out as the line takes it)
    if c.slen > 0 {
        c.serial_drain(false);
    }
    if c.serial && unsafe { inb(COM1 + 5) } & 1 != 0 {
        let ch = unsafe { inb(COM1) };
        // cursor keys arrive as ESC [ A..D / H / F, ESC [ n ~, or ESC O x
        use rustros_api::{KEY_DELETE, KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT, KEY_UP};
        match (c.esc, ch) {
            (0, 0x1B) => {
                c.esc = 1;
                return None;
            }
            (1, b'[') => {
                (c.esc, c.esc_num) = (2, 0);
                return None;
            }
            (1, b'O') => {
                c.esc = 3;
                return None;
            }
            (2, b'0'..=b'9') => {
                c.esc_num = c.esc_num.saturating_mul(10).saturating_add(ch - b'0');
                return None;
            }
            (2 | 3, _) => {
                c.esc = 0;
                return match (ch, c.esc_num) {
                    (b'A', _) => Some(KEY_UP),
                    (b'B', _) => Some(KEY_DOWN),
                    (b'C', _) => Some(KEY_RIGHT),
                    (b'D', _) => Some(KEY_LEFT),
                    (b'H', _) | (b'~', 1 | 7) => Some(KEY_HOME),
                    (b'F', _) | (b'~', 4 | 8) => Some(KEY_END),
                    (b'~', 3) => Some(KEY_DELETE),
                    _ => None,
                };
            }
            _ => c.esc = 0,
        }
        return Some(if ch == b'\r' { b'\n' } else if ch == 0x7F { 8 } else { ch });
    }
    c.kbd_getc()
}

pub fn clear() {
    let c = con();
    let (cols, rows) = c.dims();
    for r in 0..rows {
        for col in 0..cols {
            c.draw(col, r, b' ');
        }
    }
    c.col = 0;
    c.row = 0;
    c.cursor(true);
}

pub fn describe() -> &'static str {
    match con().screen {
        Screen::None => "serial only",
        Screen::Text { .. } => "VGA text",
        Screen::Fb { .. } => "framebuffer",
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::console::print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::console::write_str("\n") };
    ($($arg:tt)*) => {{ $crate::console::print(format_args!($($arg)*)); $crate::console::write_str("\n"); }};
}
