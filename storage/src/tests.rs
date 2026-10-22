use super::*;

struct Mem {
    data: Vec<u8>,
}

impl BlockDevice for Mem {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let o = lba as usize * 512;
        if o + buf.len() > self.data.len() {
            return false;
        }
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        true
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        let o = lba as usize * 512;
        if o + buf.len() > self.data.len() {
            return false;
        }
        self.data[o..o + buf.len()].copy_from_slice(buf);
        true
    }
    fn sectors(&self) -> u64 {
        (self.data.len() / 512) as u64
    }
}

const MIB: usize = 1 << 20;
const IMAGE_SECTORS: u64 = 4096; // 2 MiB, like mkimg.py

/// A 2 MiB GPT image as mkimg.py makes it: BIOS boot partition and ESP, with
/// the backup GPT at the end of the image.
fn image() -> Vec<u8> {
    let mut d = vec![0u8; IMAGE_SECTORS as usize * 512];
    // protective MBR
    d[446 + 4] = 0xEE;
    d[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    d[446 + 12..446 + 16].copy_from_slice(&((IMAGE_SECTORS - 1) as u32).to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
    let mut entries = vec![0u8; 128 * 128];
    let part = |e: &mut [u8], ty: u8, first: u64, last: u64| {
        e[..16].fill(ty);
        e[16..32].fill(ty ^ 0x5A);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
    };
    part(&mut entries[0..128], 0x11, 64, 575); // BIOS boot
    part(&mut entries[128..256], 0x22, 576, IMAGE_SECTORS - 34); // ESP
    let last = IMAGE_SECTORS - 1;
    let header = |my: u64, alt: u64, entries_lba: u64| {
        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(last - 33).to_le_bytes());
        h[56..72].fill(0xAB);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&kvstore::crc32(&entries).to_le_bytes());
        let crc = kvstore::crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    d[512..1024].copy_from_slice(&header(1, last, 2));
    d[2 * 512..34 * 512].copy_from_slice(&entries);
    let b = (last - 32) as usize * 512;
    d[b..b + entries.len()].copy_from_slice(&entries);
    d[last as usize * 512..].copy_from_slice(&header(last, 1, last - 32));
    d
}

/// The image dd'ed onto a disk of `mib` MiB.
fn disk(mib: usize) -> Mem {
    let mut d = Mem { data: vec![0; mib * MIB] };
    let img = image();
    d.data[..img.len()].copy_from_slice(&img);
    d
}

/// Both GPT copies are valid and the backup is at the end of the disk.
fn assert_consistent(d: &mut Mem) {
    let last = d.sectors() - 1;
    let g = gpt::Gpt::read(d).expect("primary GPT valid");
    assert!(g.backup_at(last));
    let mut h = vec![0u8; 512];
    d.read(last, &mut h);
    assert_eq!(&h[..8], b"EFI PART", "backup header at the end");
    let mut c = h[..92].to_vec();
    c[16..20].fill(0);
    assert_eq!(kvstore::crc32(&c), u32::from_le_bytes(h[16..20].try_into().unwrap()), "backup header CRC");
    assert_eq!(u32::from_le_bytes(d.data[446 + 12..446 + 16].try_into().unwrap()) as u64, last.min(0xFFFF_FFFF));
}

#[test]
fn first_boot_moves_backup_and_creates_partition() {
    let mut d = disk(2048);
    let (mut store, info) = open(&mut d, 1).unwrap();
    assert!(info.created && info.moved_backup);
    assert_eq!(info.start, DATA_START);
    assert_eq!(info.start + info.sectors, DATA_END);
    assert_eq!(info.cache, Some((BOOT_AREA_END, DATA_START - BOOT_AREA_END)));
    assert_consistent(&mut d);
    store.put(&mut d, "app/k", b"v").unwrap();

    let (store, info) = open(&mut d, 2).unwrap();
    assert!(!info.created && !info.moved_backup, "second boot changes nothing");
    assert_eq!(store.get("app/k"), Some(&b"v"[..]));
}

#[test]
fn disk_resize_keeps_data() {
    let mut d = disk(1100);
    let (mut store, _) = open(&mut d, 1).unwrap();
    store.put(&mut d, "keep", b"me").unwrap();
    d.data.resize(3000 * MIB, 0); // the virtual disk was enlarged
    let (store, info) = open(&mut d, 2).unwrap();
    assert!(info.moved_backup && !info.created);
    assert_eq!((info.start, info.start + info.sectors), (DATA_START, DATA_END));
    assert_eq!(store.get("keep"), Some(&b"me"[..]));
    assert_consistent(&mut d);
    assert_eq!(gpt::Gpt::read(&mut d).unwrap().last_usable(), d.sectors() - 34);
}

#[test]
fn rewriting_the_image_keeps_data() {
    let mut d = disk(1100);
    let (mut store, _) = open(&mut d, 1).unwrap();
    store.put(&mut d, "keep", b"me").unwrap();
    // dd of a fresh image: GPT and boot area overwritten, partition entry gone
    let img = image();
    d.data[..img.len()].copy_from_slice(&img);
    let (store, info) = open(&mut d, 2).unwrap();
    assert!(info.created);
    assert_eq!(info.start, DATA_START);
    assert_eq!(store.get("keep"), Some(&b"me"[..]));
    assert_consistent(&mut d);
}

#[test]
fn small_disk_uses_what_there_is() {
    // too small for cache + data: data right after the boot area
    for mib in [200, 515] {
        let mut d = disk(mib);
        let (_, info) = open(&mut d, 1).unwrap();
        assert_eq!(info.start, BOOT_AREA_END, "{mib} MiB");
        assert_eq!(info.start + info.sectors, d.sectors() - 33);
        assert_eq!(info.cache, None);
    }
    // just big enough for the full layout
    let mut d = disk(600);
    let (_, info) = open(&mut d, 1).unwrap();
    assert_eq!(info.start, DATA_START);
    assert_eq!(info.start + info.sectors, d.sectors() - 33);
    assert!(info.cache.is_some());
    assert!(open(&mut disk(70), 1).is_err(), "below 72 MiB there is no room");
}

#[test]
fn small_disk_keeps_its_layout_when_enlarged() {
    let mut d = disk(200);
    let (mut store, _) = open(&mut d, 1).unwrap();
    store.put(&mut d, "keep", b"me").unwrap();
    d.data.resize(4096 * MIB, 0);
    let (store, info) = open(&mut d, 2).unwrap();
    assert_eq!((info.start, info.cache), (BOOT_AREA_END, None), "partitions are not moved");
    assert_eq!(store.get("keep"), Some(&b"me"[..]));
}

#[test]
fn shrunk_disk_is_left_alone() {
    let mut d = disk(2048);
    open(&mut d, 1).unwrap();
    d.data.truncate(1500 * MIB);
    // the primary header still points at the old end
    assert!(open(&mut d, 2).is_err());
}

#[test]
fn not_gpt_or_corrupt() {
    let mut d = Mem { data: vec![0; 100 * MIB] };
    assert!(open(&mut d, 1).is_err());
    let mut d = disk(100);
    d.data[512 + 40] ^= 1; // flip a bit in the header
    assert!(open(&mut d, 1).is_err());
}
