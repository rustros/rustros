#!/usr/bin/env python3
"""Build a raw disk image for RustROS that boots on both BIOS and UEFI: 2 MiB
by default (--size-mb for more).

GPT layout (512-byte sectors) of the 2 MiB image:
  LBA 0            protective MBR, carrying GRUB's boot.img for BIOS
  LBA 1..33        GPT header + 128 partition entries
  LBA 64..575      partition 1: BIOS boot partition (GRUB core.img)
  LBA 576..4062    partition 2: EFI System Partition, FAT12 (FAT16 from 4 MiB on):
                     /EFI/BOOT/BOOTX64.EFI   GRUB for UEFI
                     /boot/grub/grub.cfg
                     /boot/grub/grubenv      boot_slot / try_slot / saved network
                     /boot/kernel-a.elf      kernel slot A (preallocated, contiguous, 256 KiB)
                     /boot/kernel-b.elf      kernel slot B
  LBA 4063..4095   backup GPT (the kernel moves it to the real end of the disk)

Everything below 64 MiB is the boot area: images may grow up to there, and
a running machine's EFI partition can grow into it without losing anything
(rustros-update.py esp-grow). On
first boot the kernel creates a cache partition at 64 - 512 MiB and the
system data partition at 512 MiB - 1 GiB; beyond 1 GiB the disk is left for
a NAS. The kernel gets the slots' and
grubenv's absolute LBAs on its command line, so an online update is a plain
sector write.
"""

import argparse
import os
import secrets
import hashlib
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

GRUB_LIB = "/usr/lib/grub"
SECTOR = 512
BOOT_AREA_SECTORS = 64 * 2048  # images must stay below the data partition
BIOS_FIRST, BIOS_LAST = 64, 575
ESP_FIRST = 576
ENTRIES = 128
ENV_MAGIC = b"# GRUB Environment Block\n"

BIOS_BOOT_TYPE = uuid.UUID("21686148-6449-6E6F-744E-656564454649")
ESP_TYPE = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")

COMMON_MODULES = [
    "part_msdos", "part_gpt", "fat", "multiboot2", "normal", "configfile", "loadenv",
    "test", "echo", "boot", "all_video", "video", "video_fb", "serial", "terminal",
]


def run(*cmd):
    subprocess.run(cmd, check=True)


def grubenv(boot_slot):
    env = ENV_MAGIC + f"boot_slot={boot_slot}\n".encode()
    return env + b"#" * (1024 - len(env))


# ---------------------------------------------------------------- FAT lookup

class Fat:
    """Find a file's sectors in a FAT12/16/32 image (and check it is contiguous)."""

    def __init__(self, img):
        self.f = open(img, "rb")
        bs = self.read(0, 512)
        bps, self.spc, rsvd, nfats, root_entries = struct.unpack_from("<HBHBH", bs, 11)
        assert bps == SECTOR, "expected 512-byte sectors"
        fatsz16 = struct.unpack_from("<H", bs, 22)[0]
        self.fat_start = rsvd
        if fatsz16:  # FAT12/16: fixed root directory before the data area
            total = struct.unpack_from("<H", bs, 19)[0] or struct.unpack_from("<I", bs, 32)[0]
            self.root_start = rsvd + nfats * fatsz16
            root_sectors = (root_entries * 32 + SECTOR - 1) // SECTOR
            self.data_start = self.root_start + root_sectors
            self.root_sectors = root_sectors
            clusters = (total - self.data_start) // self.spc
            self.bits = 12 if clusters < 4085 else 16
            self.root = None
        else:  # FAT32: root directory is a cluster chain
            self.bits = 32
            self.data_start = rsvd + nfats * struct.unpack_from("<I", bs, 36)[0]
            self.root = struct.unpack_from("<I", bs, 44)[0]

    def read(self, sector, n):
        self.f.seek(sector * SECTOR)
        return self.f.read(n)

    def next(self, c):
        base = self.fat_start * SECTOR
        if self.bits == 12:
            self.f.seek(base + c * 3 // 2)
            v = struct.unpack("<H", self.f.read(2))[0]
            return (v >> 4) if c & 1 else (v & 0xFFF)
        if self.bits == 16:
            self.f.seek(base + c * 2)
            return struct.unpack("<H", self.f.read(2))[0]
        self.f.seek(base + c * 4)
        return struct.unpack("<I", self.f.read(4))[0] & 0x0FFFFFFF

    def chain(self, c):
        end = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.bits]
        out = []
        while 2 <= c < end:
            out.append(c)
            c = self.next(c)
        return out

    def cluster_lba(self, c):
        return self.data_start + (c - 2) * self.spc

    def dir_entries(self, cluster):
        if cluster is None:  # FAT12/16 root directory
            data = self.read(self.root_start, self.root_sectors * SECTOR)
        else:
            data = b"".join(self.read(self.cluster_lba(c), self.spc * SECTOR) for c in self.chain(cluster))
        for i in range(0, len(data), 32):
            e = data[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5 or e[11] == 0x0F:
                continue
            hi, lo = struct.unpack_from("<H", e, 20)[0], struct.unpack_from("<H", e, 26)[0]
            yield e[:11], (hi << 16) | lo, struct.unpack_from("<I", e, 28)[0]

    @staticmethod
    def short(name):
        base, _, ext = name.upper().partition(".")
        return (base.ljust(8) + ext.ljust(3)).encode()

    def locate(self, path):
        """Return (first sector, size) of a file, asserting it is contiguous."""
        cluster = self.root
        size = 0
        for p in path.strip("/").split("/"):
            for name, c, sz in self.dir_entries(cluster):
                if name == self.short(p):
                    cluster, size = c, sz
                    break
            else:
                sys.exit(f"mkimg: {path} not found in FAT image")
        chain = self.chain(cluster)
        if chain != list(range(chain[0], chain[0] + len(chain))):
            sys.exit(f"mkimg: {path} is fragmented")
        if len(chain) * self.spc * SECTOR < size:
            sys.exit(f"mkimg: {path} cluster chain too short")
        return self.cluster_lba(chain[0]), size


# ---------------------------------------------------------------- GPT

def gpt_entry(type_guid, first, last, name):
    e = bytearray(128)
    e[0:16] = type_guid.bytes_le
    e[16:32] = uuid.uuid4().bytes_le
    struct.pack_into("<QQ", e, 32, first, last)
    n = name.encode("utf-16-le")[:72]
    e[56:56 + len(n)] = n
    return bytes(e)


def gpt_header(my, alt, entries_lba, entries, disk_guid, last):
    h = bytearray(SECTOR)
    struct.pack_into("<8sIII", h, 0, b"EFI PART", 0x00010000, 92, 0)
    struct.pack_into("<QQQQ", h, 24, my, alt, 34, last - 33)
    h[56:72] = disk_guid
    struct.pack_into("<QIII", h, 72, entries_lba, ENTRIES, 128, zlib.crc32(entries))
    struct.pack_into("<I", h, 16, zlib.crc32(bytes(h[:92])))
    return bytes(h)


# ---------------------------------------------------------------- main

BUNDLE_MAGIC = b"RRSBNDL1"
BUNDLE_HEAD = 4096   # header bytes: magic, count, then 80-byte entries
BUNDLE_ENTRY = 80    # name (32, zero padded), offset in sectors from the bundle (4), bytes (4), SHA-256 (32), pad (8)


def make_bundle(specs):
    """The bundle area: a header listing the modules, then each module
    (sector aligned). Empty when there are none."""
    if not specs:
        return b""
    entries, blobs, at = [], [], BUNDLE_HEAD // SECTOR
    for spec in specs:
        name, path = spec.split("=", 1)
        assert 0 < len(name) <= 32 and name.replace("-", "").replace("_", "").isalnum(), f"bad module name {name!r}"
        data = open(path, "rb").read()
        entries.append(name.encode().ljust(32, b"\0") + struct.pack("<II", at, len(data)) + hashlib.sha256(data).digest() + bytes(8))
        padded = data + bytes(-len(data) % SECTOR)
        blobs.append(padded)
        at += len(padded) // SECTOR
    assert 16 + len(entries) * BUNDLE_ENTRY <= BUNDLE_HEAD, "too many bundled modules"
    head = (BUNDLE_MAGIC + struct.pack("<II", len(entries), 0) + b"".join(entries)).ljust(BUNDLE_HEAD, b"\0")
    return head + b"".join(blobs)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kernel", help="kernel ELF")
    ap.add_argument("output", help="raw disk image to write")
    ap.add_argument("--ip", default="", help="default static address a.b.c.d/prefix (empty: set it on the console)")
    ap.add_argument("--gw", default="", help="default gateway")
    ap.add_argument("--mtu", type=int, default=0, help="default interface MTU (default 1500)")
    ap.add_argument("--key", default="", help="online update key (empty: generate one)")
    ap.add_argument("--key-file", help="read/store the update key in this file")
    ap.add_argument("--size-mb", type=int, default=2, help="image size in MiB (2 to 64; the EFI partition is all of it)")
    ap.add_argument("--slot-kb", type=int, default=0, help="size of each kernel slot in KiB (default 256, 1024 from 8 MiB on)")
    ap.add_argument("--timeout", type=int, default=2, help="GRUB menu timeout in seconds")
    ap.add_argument("--bundle", action="append", default=[], metavar="NAME=FILE",
                    help="a module the image carries (installed at first boot), e.g. panel=build/modules/panel.mod")
    ap.add_argument("--panel", default="", help="the panel this image's machines connect to (rustros.panel=)")
    ap.add_argument("--cmdline", default="", help="more kernel arguments (e.g. rustros.stable=5 for test images)")
    ap.add_argument("--template", action="store_true",
                    help="an image for the installer: no key, network or panel in it; they come from its "
                         "grubenv (update_key, net_ip, net_gw, net_mtu, panel_url), the bundle after it is optional")
    a = ap.parse_args()
    if not 2 <= a.size_mb <= 64:
        sys.exit("mkimg: --size-mb is 2 to 64 (the boot area)")
    IMAGE_SECTORS = a.size_mb * 2048
    ESP_LAST = IMAGE_SECTORS - 34
    a.slot_kb = a.slot_kb or (1024 if a.size_mb >= 8 else 256)
    bundle = make_bundle(a.bundle)
    assert IMAGE_SECTORS + len(bundle) // SECTOR <= BOOT_AREA_SECTORS, "the bundle must fit in the 64 MiB boot area"

    key = a.key
    if a.template:
        if a.key or a.key_file or a.ip or a.gw or a.panel or a.bundle:
            sys.exit("mkimg: a template carries no key, network, panel or bundle (the installer adds them)")
        key = "$update_key"
    if not key and a.key_file and os.path.exists(a.key_file):
        key = open(a.key_file).read().strip()
    if not key:
        key = secrets.token_hex(16)
    if any(c.isspace() for c in key):
        sys.exit("mkimg: key must not contain whitespace")
    if a.key_file:
        with open(a.key_file, "w") as f:
            f.write(key + "\n")
        os.chmod(a.key_file, 0o600)

    kernel = open(a.kernel, "rb").read()
    slot_bytes = a.slot_kb << 10
    if len(kernel) > slot_bytes:
        sys.exit(f"mkimg: the kernel is {len(kernel)} bytes; a slot holds {slot_bytes} ({a.slot_kb} KiB)")
    slot_image = kernel + b"\0" * (slot_bytes - len(kernel))

    with tempfile.TemporaryDirectory() as tmp:
        t = lambda n: os.path.join(tmp, n)

        # GRUB for UEFI: config and modules are found relative to the ESP it was loaded from
        run("grub-mkimage", "-O", "x86_64-efi", "-d", f"{GRUB_LIB}/x86_64-efi", "-p", "/boot/grub",
            "-o", t("BOOTX64.EFI"), *COMMON_MODULES, "efi_gop", "efi_uga")

        # GRUB for BIOS, in the BIOS boot partition; the boot disk is always hd0
        run("grub-mkimage", "-O", "i386-pc", "-d", f"{GRUB_LIB}/i386-pc", "-p", "(hd0,gpt2)/boot/grub",
            "-o", t("core.img"), "biosdisk", *COMMON_MODULES, "vbe", "vga")
        core = bytearray(open(t("core.img"), "rb").read())
        core_sectors = (len(core) + SECTOR - 1) // SECTOR
        if core_sectors > BIOS_LAST - BIOS_FIRST + 1:
            sys.exit("mkimg: core.img does not fit the BIOS boot partition")

        # ESP
        esp = t("esp.img")
        esp_sectors = ESP_LAST - ESP_FIRST + 1
        with open(esp, "wb") as f:
            f.truncate(esp_sectors * SECTOR)
        # one sector per cluster: FAT12 up to about 2 MiB, FAT16 above
        run("mkfs.fat", "-F", "12" if esp_sectors < 4000 else "16", "-s", "1", "-n", "RUSTROS", esp)
        open(t("kernel-a.elf"), "wb").write(slot_image)
        open(t("grubenv"), "wb").write(grubenv("a"))
        mt = ["-i", esp]
        run("mmd", *mt, "::/EFI", "::/EFI/BOOT", "::/boot", "::/boot/grub")
        run("mcopy", *mt, t("BOOTX64.EFI"), "::/EFI/BOOT/BOOTX64.EFI")
        run("mcopy", *mt, t("grubenv"), "::/boot/grub/grubenv")
        run("mcopy", *mt, t("kernel-a.elf"), "::/boot/kernel-a.elf")
        run("mcopy", *mt, t("kernel-a.elf"), "::/boot/kernel-b.elf")

        fat = Fat(esp)
        a_lba, _ = fat.locate("/boot/kernel-a.elf")
        b_lba, _ = fat.locate("/boot/kernel-b.elf")
        env_lba, _ = fat.locate("/boot/grub/grubenv")
        fat.f.close()
        a_lba, b_lba, env_lba = (x + ESP_FIRST for x in (a_lba, b_lba, env_lba))
        slot_sectors = slot_bytes // SECTOR

        disk = f"rustros.slots={a_lba},{b_lba},{slot_sectors} rustros.env={env_lba}"
        if bundle or a.template:
            disk += f" rustros.bundle={IMAGE_SECTORS}"
        if a.panel:
            disk += f" rustros.panel={a.panel}"
        if a.template:
            disk += " $panelarg"
        if a.cmdline:
            disk += " " + a.cmdline
        net = f"$netargs key={key}"
        defaults = "".join(
            f'if [ -z "$net_{k}" ]; then set net_{k}={v}; fi\n'
            for k, v in (("ip", a.ip), ("gw", a.gw), ("mtu", a.mtu or ""))
            if v
        )
        cfg = f"""# RustROS boot configuration.
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
insmod all_video
set timeout={a.timeout}
set default=0
set fallback=1

load_env
# Network settings: saved ones (shell 'save' -> grubenv) win over the image defaults.
{defaults}set panelarg=
if [ -n "$panel_url" ]; then set panelarg="rustros.panel=$panel_url"; fi
set netargs=
if [ -n "$net_ip" ]; then set netargs="ip=$net_ip gw=$net_gw"; fi
if [ -n "$net_mtu" ]; then set netargs="$netargs mtu=$net_mtu"; fi
if [ -z "$boot_slot" ]; then set boot_slot=a; fi

# Boot-loop protection. GRUB cannot count, so boot_count grows by one "x" per
# boot; the kernel clears it after running stable for two minutes. The kernel
# starts in safe mode (no installed modules) at the third unstable boot; at the
# fourth even that failed, so the other kernel slot (the previous kernel)
# takes over for good.
set boot_count="${{boot_count}}x"
if [ "$boot_count" = "xxxx" ]; then
    set rolled_back=$boot_slot
    if [ "$boot_slot" = "a" ]; then set boot_slot=b; else set boot_slot=a; fi
    set boot_count=x
    save_env boot_slot rolled_back
fi
save_env boot_count
set run_slot=$boot_slot
set trial=0
# A freshly uploaded kernel gets exactly one boot; it must confirm itself,
# otherwise the next boot goes back to boot_slot.
if [ -n "$try_slot" ]; then
    set run_slot=$try_slot
    set trial=1
    set try_slot=
    save_env try_slot
fi

menuentry "RustROS (slot $run_slot)" {{
    multiboot2 /boot/kernel-$run_slot.elf rustros.slot=$run_slot rustros.trial=$trial rustros.boots=$boot_count {disk} {net}
    boot
}}

menuentry "RustROS (slot $boot_slot, fallback)" {{
    multiboot2 /boot/kernel-$boot_slot.elf rustros.slot=$boot_slot rustros.trial=0 rustros.boots=$boot_count {disk} {net}
    boot
}}
"""
        open(t("grub.cfg"), "w").write(cfg)
        run("mcopy", *mt, t("grub.cfg"), "::/boot/grub/grub.cfg")

        # protective MBR with GRUB's boot.img, which loads core.img from the
        # BIOS boot partition
        boot = bytearray(open(f"{GRUB_LIB}/i386-pc/boot.img", "rb").read())
        assert len(boot) == SECTOR
        struct.pack_into("<Q", boot, 0x5C, BIOS_FIRST)
        mbr = bytearray(SECTOR)
        mbr[:440] = boot[:440]
        mbr[440:444] = secrets.token_bytes(4)
        mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xfe\xff\xff", 1, IMAGE_SECTORS - 1)
        mbr[510:512] = b"\x55\xaa"

        # diskboot.img (first sector of core.img) loads the rest via its blocklist
        _, _, seg = struct.unpack_from("<QHH", core, SECTOR - 12)
        struct.pack_into("<QHH", core, SECTOR - 12, BIOS_FIRST + 1, core_sectors - 1, seg)

        entries = bytearray(ENTRIES * 128)
        entries[0:128] = gpt_entry(BIOS_BOOT_TYPE, BIOS_FIRST, BIOS_LAST, "BIOS boot")
        entries[128:256] = gpt_entry(ESP_TYPE, ESP_FIRST, ESP_LAST, "EFI system")
        entries = bytes(entries)
        disk_guid = uuid.uuid4().bytes_le
        last = IMAGE_SECTORS - 1

        with open(a.output, "wb") as out:
            out.truncate(IMAGE_SECTORS * SECTOR)
            out.write(mbr)
            out.write(gpt_header(1, last, 2, entries, disk_guid, last))
            out.write(entries)
            out.seek(BIOS_FIRST * SECTOR)
            out.write(core)
            out.seek(ESP_FIRST * SECTOR)
            out.write(open(esp, "rb").read())
            out.seek((last - 32) * SECTOR)
            out.write(entries)
            out.write(gpt_header(last, 1, last - 32, entries, disk_guid, last))
            # the modules it carries, right after the image (in the boot area)
            out.seek(IMAGE_SECTORS * SECTOR)
            out.write(bundle)

    print(f"{a.output}: {(IMAGE_SECTORS * SECTOR + len(bundle)) / 1048576:.1f} MiB raw disk (GPT), BIOS + UEFI")
    for name, _ in a.bundle and [b.split("=", 1) for b in a.bundle] or []:
        print(f"  carries module {name} (installed at first boot)")
    if a.panel:
        print(f"  panel: {a.panel}")
    print(f"  kernel {len(kernel)} bytes in {a.slot_kb} KiB slots: A @ LBA {a_lba}, B @ LBA {b_lba}; grubenv @ LBA {env_lba}")
    print(f"  first boot creates cache 64-512 MiB and data 512 MiB-1 GiB; beyond 1 GiB is free (NAS)")
    print(f"  network: {a.ip or 'DHCP (or set ip/save on the console)'}" + (f" gw {a.gw}" if a.gw else "") + (f" mtu {a.mtu}" if a.mtu else ""))
    if a.template:
        print("  template: key, network and panel from grubenv (update_key, net_*, panel_url)")
    else:
        # printed only when it is nowhere else
        print(f"  update key: saved in {a.key_file}" if a.key_file else f"  update key: {key}")


if __name__ == "__main__":
    main()
