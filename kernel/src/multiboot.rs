//! Multiboot2 boot information parsing.

pub const MAGIC: u32 = 0x36D7_6289;

#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub addr: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    /// 1 = direct RGB, 2 = EGA text
    pub kind: u8,
    pub red: (u8, u8), // (position, size)
    pub green: (u8, u8),
    pub blue: (u8, u8),
}

pub struct BootInfo {
    pub cmdline: &'static [u8],
    pub fb: Option<Framebuffer>,
    pub efi: bool,
    /// Copy of the ACPI RSDP (tag 14 or 15)
    pub rsdp: Option<&'static [u8]>,
    /// The memory map's entries (tag 6): base, length, type (1: RAM)
    pub mmap: &'static [u8],
    pub mmap_entry: usize,
    /// Where this structure is: (address, bytes)
    pub at: (u64, u64),
}

impl BootInfo {
    /// The usable RAM: (base, length).
    pub fn ram(&self) -> impl Iterator<Item = (u64, u64)> + Clone + '_ {
        self.mmap.chunks_exact(self.mmap_entry.max(24)).filter(|e| rd32(e, 16) == 1).map(|e| (rd64(e, 0), rd64(e, 8)))
    }
}

fn rd64(b: &[u8], o: usize) -> u64 {
    rd32(b, o) as u64 | (rd32(b, o + 4) as u64) << 32
}

fn rd32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub fn parse(magic: u32, info: u32) -> BootInfo {
    let mut bi = BootInfo { cmdline: &[], fb: None, efi: false, rsdp: None, mmap: &[], mmap_entry: 24, at: (0, 0) };
    if magic != MAGIC || info == 0 {
        return bi;
    }
    // Safety: GRUB hands us a valid structure of `total_size` bytes, identity-mapped,
    // which nothing else overwrites.
    let total = unsafe { (info as *const u32).read() } as usize;
    let b: &'static [u8] = unsafe { core::slice::from_raw_parts(info as *const u8, total) };
    bi.at = (info as u64, total as u64);
    let mut o = 8;
    while o + 8 <= b.len() {
        let ty = rd32(b, o);
        let size = rd32(b, o + 4) as usize;
        if ty == 0 || size < 8 || o + size > b.len() {
            break;
        }
        let t = &b[o..o + size];
        match ty {
            1 => {
                let s = &t[8..];
                bi.cmdline = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
            }
            8 if size >= 32 => {
                let c = |i: usize| t.get(i).copied().unwrap_or(0);
                bi.fb = Some(Framebuffer {
                    addr: rd32(t, 8) as u64 | (rd32(t, 12) as u64) << 32,
                    pitch: rd32(t, 16),
                    width: rd32(t, 20),
                    height: rd32(t, 24),
                    bpp: t[28],
                    kind: t[29],
                    red: (c(32), c(33)),
                    green: (c(34), c(35)),
                    blue: (c(36), c(37)),
                });
            }
            6 if size >= 16 => {
                bi.mmap_entry = rd32(t, 8) as usize;
                bi.mmap = &t[16..];
            }
            11 | 12 => bi.efi = true,
            // prefer the ACPI 2.0 RSDP (XSDT) when both are there
            14 if bi.rsdp.is_none() => bi.rsdp = Some(&t[8..]),
            15 => bi.rsdp = Some(&t[8..]),
            _ => {}
        }
        o += (size + 7) & !7;
    }
    bi
}
