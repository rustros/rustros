#!/usr/bin/env python3
"""Online update client for RustROS.

  rustros-update.py HOST status
  rustros-update.py HOST upload rustros.elf [--wait]   write into the spare slot, reboot into it once
  rustros-update.py HOST confirm                      keep the running (trial) kernel
  rustros-update.py HOST reboot
  rustros-update.py HOST poweroff
  rustros-update.py HOST module-config NAME [KEY [VALUE | -]]   show / set / remove a module setting
  rustros-update.py HOST net ip [nicN] add|del a.b.c.d[-e][,...]   extra addresses; also "net ip ...", "net mtu ...", "net save"
  rustros-update.py HOST net boot [KEY VALUE|-]          network settings for the next boot only (grubenv net*)
  rustros-update.py HOST log [prev|this|BOOT [LINES]]     console logs of the last boots (kept on disk)
  rustros-update.py HOST info                         uptime, slot, address, storage, modules, last crash
  rustros-update.py HOST module-install NAME FILE     install a module: native (.mod) or WebAssembly (.wasm);
                                                     replaces a running one, no reboot
  rustros-update.py HOST module-remove NAME [native|wasm]
  rustros-update.py HOST module-switch NAME native|wasm
  rustros-update.py HOST esp-get FILE                 copy the EFI partition (GRUB, its config, the slots) to FILE
  rustros-update.py HOST esp-put FILE                 write back the sectors of FILE that differ (then verify)
  rustros-update.py HOST esp-grow MIB [SLOT_KIB]      grow the EFI partition (and the kernel slots) into the
                                                     free boot area, losing nothing; then reboot
  rustros-update.py HOST slots-grow [SLOT_KIB]        grow the kernel slots inside the EFI partition as it is
                                                     (default: as far as it has room); then reboot

The key comes from --key, $RUSTROS_KEY or --key-file (default build/update.key).
`upload --wait` waits for the trial boot to come up and confirms it.
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def hello(host, port, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    h = recv_exact(s, 22)
    if h[:4] != b"RRS1":
        raise ConnectionError("not a RustROS update server")
    return s, h[4:20], chr(h[20]), h[21] == 1


def keystream_xor(key, nonce, data):
    out = bytearray(data)
    for i in range(0, len(out), 32):
        k = hmac.new(key, nonce + b"E" + struct.pack(">I", i // 32), hashlib.sha256).digest()
        for j in range(min(32, len(out) - i)):
            out[i + j] ^= k[j]
    return bytes(out)


def command(host, port, key, cmd, payload=b"", encrypt=False):
    s, nonce, slot, trial = hello(host, port)
    command.nonce = nonce
    if encrypt:
        # 'E': the inner command travels encrypted, the MAC covers the ciphertext
        payload = keystream_xor(key, nonce, cmd + payload)
        cmd = b"E"
    head = cmd + struct.pack(">I", len(payload))
    hdr_mac = hmac.new(key, nonce + b"H" + head, hashlib.sha256).digest()
    mac = hmac.new(key, nonce + head + payload, hashlib.sha256).digest()
    s.sendall(head + hdr_mac)
    sent = 0
    t0 = time.time()
    while sent < len(payload):
        n = s.send(payload[sent:sent + 65536])
        sent += n
        if len(payload) > 65536:
            print(f"\r  {sent * 100 // len(payload)}%  {sent // 1024} KiB", end="", flush=True)
    if len(payload) > 65536:
        print(f"  ({time.time() - t0:.1f}s)")
    s.sendall(mac)
    # on a slow link most of the payload may still be on its way: the answer
    # comes once it has arrived and been written
    s.settimeout(max(s.gettimeout() or 10, 30 + len(payload) // 4096))
    reply = b""
    try:
        # 'I' and listings send several lines and close; the others answer one line
        while cmd in (b"I", b"E", b"N", b"L", b"J") or not reply.endswith(b"\n"):
            chunk = s.recv(256)
            if not chunk:
                break
            reply += chunk
    finally:
        s.close()
    return reply.decode(errors="replace").strip(), slot, trial


# The EFI partition: where the GPT says (it starts at 576 in the images
# tools/mkimg.py makes, elsewhere after esp-grow; kernels without boot-area
# reads have it at 576). Its length is in its FAT boot sector.
ESP_FIRST = 576
ESP_CHUNK = 128
ESP_TYPE = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
BOOT_AREA_END = 64 * 2048


def sector_read(a, key, lba, n, inner=b"D"):
    """Sectors of the EFI partition ('D') or of the boot area ('d'); None on an error reply."""
    reply, _, _ = command(a.host, a.port, key, inner, struct.pack("<QH", lba, n), encrypt=True)
    if not reply.startswith("OK "):
        return None
    return keystream_xor(key, command.nonce + b"R", bytes.fromhex(reply[3:]))


def esp_read(a, key, lba, n):
    data = sector_read(a, key, lba, n)
    if data is None:
        sys.exit(f"esp read at {lba} failed")
    return data


def gpt_parts(a, key):
    """The partitions (type, first, last, index) from the primary GPT, None if the
    kernel cannot read the boot area."""
    head = sector_read(a, key, 1, 33, b"d")
    if head is None or head[:8] != b"EFI PART":
        return None
    entries_lba, count, size = struct.unpack_from("<QII", head, 72)
    raw = head[(entries_lba - 1) * 512:] if entries_lba <= 33 else b""
    parts = []
    for i in range(min(count, len(raw) // size)):
        e = raw[i * size:(i + 1) * size]
        if any(e[:16]):
            first, last = struct.unpack_from("<QQ", e, 32)
            parts.append((e[:16], first, last, i))
    return parts


def esp_first(a, key):
    parts = gpt_parts(a, key)
    esp = [p for p in parts or [] if p[0] == ESP_TYPE]
    return esp[0][1] if esp else ESP_FIRST


def esp_get(a, key, first=None):
    first = esp_first(a, key) if first is None else first
    boot = esp_read(a, key, first, 1)
    total = struct.unpack_from("<H", boot, 19)[0] or struct.unpack_from("<I", boot, 32)[0]
    if boot[510:512] != b"\x55\xaa" or not total:
        sys.exit("esp: no FAT boot sector where the EFI partition should start")
    last = first + total - 1
    data = b""
    for lba in range(first, last + 1, ESP_CHUNK):
        data += esp_read(a, key, lba, min(ESP_CHUNK, last + 1 - lba))
    return data


def esp(a, key):
    first = esp_first(a, key)
    if a.action == "esp-get":
        data = esp_get(a, key, first)
        fd = os.open(a.image, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # it holds the key
        os.write(fd, data)
        os.close(fd)
        print(f"{len(data)} bytes ({len(data) // 512} sectors from {first})")
        return 0
    new = open(a.image, "rb").read()
    old = esp_get(a, key, first)
    if len(new) != len(old):
        sys.exit(f"{a.image} is {len(new)} bytes, the EFI partition {len(old)}")
    changed = [i for i in range(len(old) // 512) if old[i * 512:(i + 1) * 512] != new[i * 512:(i + 1) * 512]]
    # runs of changed sectors, at most ESP_CHUNK each
    runs = []
    for i in changed:
        if runs and runs[-1][1] == i and runs[-1][1] - runs[-1][0] < ESP_CHUNK:
            runs[-1][1] = i + 1
        else:
            runs.append([i, i + 1])
    for f, end in runs:
        reply, _, _ = command(a.host, a.port, key, b"B", struct.pack("<Q", first + f) + new[f * 512:end * 512], encrypt=True)
        if reply != "OK":
            sys.exit(f"esp write at {first + f}: {reply}")
    if esp_get(a, key, first) != new:
        sys.exit("verify failed: the EFI partition does not match the file")
    print(f"{len(changed)} sectors written in {len(runs)} runs, verified")
    return 0


class EspFat:
    """A FAT12/16 EFI partition (its bytes), for lookups and in-place edits:
    every change goes to the image here and to all FAT copies."""

    def __init__(self, img):
        self.img = bytearray(img)
        bps, self.spc, rsvd, self.nfats, root_entries = struct.unpack_from("<HBHBH", img, 11)
        self.fatsz = struct.unpack_from("<H", img, 22)[0]
        total = struct.unpack_from("<H", img, 19)[0] or struct.unpack_from("<I", img, 32)[0]
        if bps != 512 or not self.fatsz:
            sys.exit("not a FAT12/16 partition with 512-byte sectors")
        self.fat_start = rsvd
        self.root = rsvd + self.nfats * self.fatsz
        self.data = self.root + (root_entries * 32 + 511) // 512
        self.clusters = (total - self.data) // self.spc
        self.bits = 12 if self.clusters < 4085 else 16
        self.eoc = 0xFFF if self.bits == 12 else 0xFFFF

    def get(self, c):
        o = self.fat_start * 512
        if self.bits == 12:
            v = struct.unpack_from("<H", self.img, o + c * 3 // 2)[0]
            return v >> 4 if c & 1 else v & 0xFFF
        return struct.unpack_from("<H", self.img, o + c * 2)[0]

    def set(self, c, v):
        for k in range(self.nfats):
            o = (self.fat_start + k * self.fatsz) * 512
            if self.bits == 12:
                o += c * 3 // 2
                w = struct.unpack_from("<H", self.img, o)[0]
                w = (w & 0x000F) | (v << 4) if c & 1 else (w & 0xF000) | v
                struct.pack_into("<H", self.img, o, w)
            else:
                struct.pack_into("<H", self.img, o + c * 2, v)

    def chain(self, c):
        out = []
        while 2 <= c < self.eoc - 7 and len(out) <= self.clusters:
            out.append(c)
            c = self.get(c)
        return out

    def lba(self, c):
        """The partition-relative sector of cluster `c`."""
        return self.data + (c - 2) * self.spc

    def entries(self, start):
        """(name, attr, first cluster, size, byte offset of the entry) of a
        directory (None: the root directory), without . and .. or long names."""
        if start is None:
            spans = [(self.root * 512, self.data * 512)]
        else:
            spans = [(self.lba(c) * 512, (self.lba(c) + self.spc) * 512) for c in self.chain(start)]
        for lo, hi in spans:
            for o in range(lo, hi, 32):
                e = self.img[o:o + 32]
                if e[0] == 0:
                    return
                if e[0] == 0xE5 or e[11] == 0x0F or e[:2] in (b". ", b".."):
                    continue
                first = struct.unpack_from("<H", e, 20)[0] << 16 | struct.unpack_from("<H", e, 26)[0]
                yield bytes(e[:11]), e[11], first, struct.unpack_from("<I", e, 28)[0], o

    def find(self, path):
        d, found = None, None
        for p in path.strip("/").split("/"):
            base, _, ext = p.upper().partition(".")
            want = (base.ljust(8) + ext.ljust(3)).encode()
            found = next((e for e in self.entries(d) if e[0] == want), None)
            if found is None:
                sys.exit(f"{path} not in the EFI partition")
            d = found[2]
        return found

    def referenced(self):
        """Every cluster a directory entry's chain reaches."""
        seen, todo = set(), [None]
        while todo:
            for name, attr, first, size, _ in self.entries(todo.pop()):
                if first >= 2:
                    seen.update(self.chain(first))
                    if attr & 0x10:
                        todo.append(first)
        return seen

    def set_entry(self, off, first, size):
        struct.pack_into("<H", self.img, off + 20, first >> 16)
        struct.pack_into("<H", self.img, off + 26, first & 0xFFFF)
        struct.pack_into("<I", self.img, off + 28, size)

    def read(self, path):
        _, _, first, size, _ = self.find(path)
        return b"".join(bytes(self.img[self.lba(c) * 512:(self.lba(c) + self.spc) * 512]) for c in self.chain(first))[:size]

    def contiguous(self, path):
        """(first sector, size) of a file that must be one run of clusters."""
        _, _, first, size, _ = self.find(path)
        ch = self.chain(first)
        if not ch or ch != list(range(ch[0], ch[0] + len(ch))):
            sys.exit(f"{path} is fragmented")
        return self.lba(ch[0]), size


def fat_locate(img, path):
    """(first sector, size) of a contiguous file in a FAT12/16 image."""
    return EspFat(img).contiguous(path)


def slots_grow(a, key, slot_kb, stop_after):
    """Grow both kernel slots inside the EFI partition as it is (no partition
    move, nothing outside it changes): kernel-b.elf moves to free space,
    kernel-a.elf grows over B's old place, then grub.cfg gets the new sector
    numbers, then a reboot. Each step writes its data and FAT entries first
    (unreferenced until then) and commits with one directory sector, so the
    machine boots after a power cut at any point; running this again
    finishes the job. Never during an update."""
    import re
    s, _, slot, trial = hello(a.host, a.port)
    s.close()
    if trial:
        sys.exit("confirm the running trial kernel first")
    first = esp_first(a, key)
    old = esp_get(a, key, first)
    f = EspFat(old)
    if f.spc != 1:
        sys.exit("expected one sector per cluster (images from mkimg.py or esp-grow)")
    A, B, CFG = "/boot/kernel-a.elf", "/boot/kernel-b.elf", "/boot/grub/grub.cfg"
    cfg = f.read(CFG).decode()
    m = re.search(r"rustros\.slots=(\d+),(\d+),(\d+)", cfg)
    if not m:
        sys.exit("grub.cfg has no rustros.slots=")
    # what the kernels use now: both slots hold that much (the smallest, if
    # an interrupted run left the entries different)
    secs = min(int(x) for x in re.findall(r"rustros\.slots=\d+,\d+,(\d+)", cfg))
    a_ch, b_ch = f.chain(f.find(A)[2]), f.chain(f.find(B)[2])
    a0 = a_ch[0]
    if a_ch != list(range(a0, a0 + len(a_ch))) or f.lba(a0) != int(m.group(1)) - first:
        sys.exit("kernel-a.elf is not where grub.cfg says, or fragmented")
    ref = f.referenced()
    b_set = set(b_ch)

    def avail_for_a(c):  # A may grow over free clusters and B's (B moves first)
        return c in a_ch or c in b_set or c not in ref

    def free_runs(exclude):
        runs, run = [], []
        for c in range(2, f.clusters + 2):
            if c not in ref and c not in exclude:
                run.append(c)
                continue
            if run:
                runs.append(run)
            run = []
        if run:
            runs.append(run)
        return runs

    cfg_n = (len(cfg) + 600) // 512  # room for longer sector numbers
    la = 0
    while a0 + la < f.clusters + 2 and avail_for_a(a0 + la):
        la += 1

    def plan(S):
        """Where B goes for slots of S sectors (None: it does not fit)."""
        a_range = set(range(a0, a0 + S))
        if S > la:
            return None
        if b_ch == list(range(b_ch[0], b_ch[0] + len(b_ch))) and len(b_ch) >= S and not a_range & b_set:
            b_new = b_ch[0]  # already moved
        else:
            runs = [r for r in free_runs(a_range) if len(r) >= S]
            if not runs:
                return None
            b_new = max(runs, key=len)[0]
        taken = a_range | set(range(b_new, b_new + S))
        if not any(len(r) >= cfg_n for r in free_runs(taken)):
            return None
        return b_new

    sizes = [f.find(A)[3] // 512, f.find(B)[3] // 512]
    if slot_kb:
        S = slot_kb * 2
    elif max(sizes) > secs:
        S = max(sizes)  # an interrupted run: finish it
    else:
        S = la // 16 * 16
        while S > secs and plan(S) is None:
            S -= 16
    if S < secs:
        sys.exit("the slots cannot shrink")
    b_new = plan(S)
    if b_new is None:
        sys.exit(f"{S // 2} KiB slots do not fit in this EFI partition")
    print(f"kernel slots {secs // 2} -> {S // 2} KiB (running slot {slot}): "
          f"B to sector {first + f.lba(b_new)}, A grows in place at {first + f.lba(a0)}")

    writes = [0]

    def put(lo, hi):
        """Write the partition-relative sectors lo..hi of the image (what the
        disk has already, from an interrupted run, is left alone)."""
        for at in range(lo, hi, ESP_CHUNK - 8):
            n = min(ESP_CHUNK - 8, hi - at)
            data = bytes(f.img[at * 512:(at + n) * 512])
            if data == old[at * 512:(at + n) * 512]:
                continue
            if stop_after is not None and writes[0] >= stop_after:
                print(f"stopped after {writes[0]} writes (--stop-after)")
                sys.exit(3)
            reply, _, _ = command(a.host, a.port, key, b"B", struct.pack("<Q", first + at) + data, encrypt=True)
            if reply != "OK" or esp_read(a, key, first + at, n) != data:
                sys.exit(f"write at {first + at} failed: {reply} (run again to finish)")
            writes[0] += 1

    def put_fat(before):
        """The FAT sectors that changed since `before` (all copies), one by one."""
        for k in range(f.nfats):
            for i in range(f.fatsz):
                sec = f.fat_start + k * f.fatsz + i
                if f.img[sec * 512:(sec + 1) * 512] != before[sec * 512:(sec + 1) * 512]:
                    put(sec, sec + 1)

    def put_entry(path, start, size):
        off = f.find(path)[4]
        f.set_entry(off, start, size)
        put(off // 512, off // 512 + 1)

    def link(run):
        before = bytes(f.img)
        for c in run[:-1]:
            f.set(c, c + 1)
        f.set(run[-1], f.eoc)
        put_fat(before)

    # 1. B: its contents (and zeros) to the new place, FAT chain, then the entry
    if b_new != b_ch[0]:
        src = f.lba(b_ch[0])
        body = bytes(f.img[src * 512:(src + secs) * 512])
        lo = f.lba(b_new)
        f.img[lo * 512:(lo + S) * 512] = body + bytes((S - secs) * 512)
        put(lo, lo + S)
        link(list(range(b_new, b_new + S)))
        put_entry(B, b_new, S * 512)
    # 2. A: the chain over B's old place, then the entry's size
    if f.find(A)[3] < S * 512:
        link(list(range(a0, a0 + S)))
        put_entry(A, a0, S * 512)
    # 3. grub.cfg with the new sector numbers, last
    # every menu entry (the fallback entry has it too)
    new_cfg = re.sub(r"rustros\.slots=\d+,\d+,\d+", f"rustros.slots={first + f.lba(a0)},{first + f.lba(b_new)},{S}", cfg)
    if new_cfg != cfg:
        ref = f.referenced()
        taken = set(range(a0, a0 + S)) | set(range(b_new, b_new + S))
        n = (len(new_cfg) + 511) // 512
        run = next(r for r in free_runs(taken) if len(r) >= n)[:n]
        lo = f.lba(run[0])
        f.img[lo * 512:(lo + n) * 512] = new_cfg.encode().ljust(n * 512, b"\0")
        put(lo, lo + n)
        link(run)
        put_entry(CFG, run[0], len(new_cfg))
    # 4. clusters nothing refers to any more (B's old tail, the old grub.cfg),
    # and the other FAT copies equal to the first (written first every time;
    # an interrupted run may have left the others behind)
    ref = f.referenced()
    before = bytes(f.img)
    fat1 = f.img[f.fat_start * 512:(f.fat_start + f.fatsz) * 512]
    for k in range(1, f.nfats):
        o = (f.fat_start + k * f.fatsz) * 512
        f.img[o:o + len(fat1)] = fat1
    for c in range(2, f.clusters + 2):
        if f.get(c) not in (0, f.eoc - 8) and c not in ref:  # not free, not a bad cluster
            f.set(c, 0)
    put_fat(before)
    if esp_get(a, key, first) != bytes(f.img):
        sys.exit("verify failed: the EFI partition differs (run again)")
    if not writes[0]:
        print(f"nothing to do: the slots are {S // 2} KiB" + (" (no room to grow)" if S == secs else ""))
        return 0
    print(f"done in {writes[0]} writes; rebooting into {S // 2} KiB slots")
    command(a.host, a.port, key, b"R")
    time.sleep(5)
    for _ in range(120):
        try:
            s, _, cur_slot, _ = hello(a.host, a.port, timeout=3)
            s.close()
            print(f"up again on slot {cur_slot}")
            return 0
        except OSError:
            time.sleep(1)
    sys.exit("it did not come back within 2 minutes")


def esp_grow(a, key, mb, slot_kb):
    """Grow the EFI partition (and the kernel slots) into the free boot area:
    a new, bigger copy is built and written next to the old one, read back,
    and only then does the GPT entry move to it (one write: a power cut
    before it leaves the old partition, after it the new one). Then reboot."""
    import re, shutil, subprocess, tempfile
    for tool in ("mkfs.fat", "mcopy", "mmd"):
        if not shutil.which(tool):
            sys.exit(f"esp-grow needs {tool} (dosfstools, mtools)")
    s, _, slot, trial = hello(a.host, a.port)
    s.close()
    if trial:
        sys.exit("confirm the running trial kernel first")
    parts = gpt_parts(a, key)
    if parts is None:
        sys.exit("this kernel cannot read the boot area; update it first")
    esp = [p for p in parts if p[0] == ESP_TYPE]
    if not esp:
        sys.exit("no EFI partition in the GPT")
    _, old_first, old_last, _ = esp[0]
    sectors = mb * 2048
    if sectors <= old_last - old_first + 1:
        sys.exit(f"the EFI partition already has {(old_last - old_first + 1) // 2048} MiB")
    # the new place: after everything in the boot area, 1 MiB aligned
    end = max(p[2] for p in parts if p[1] < BOOT_AREA_END) + 1
    first = (end + 2047) // 2048 * 2048
    last = first + sectors - 1
    if last >= BOOT_AREA_END or any(p[1] <= last and first <= p[2] for p in parts):
        sys.exit(f"no room for {mb} MiB in the boot area (free from sector {end})")
    old = esp_get(a, key, old_first)
    with tempfile.TemporaryDirectory() as tmp:
        t = lambda n: os.path.join(tmp, n)
        open(t("old.img"), "wb").write(old)
        os.makedirs(t("files"))
        subprocess.run(["mcopy", "-s", "-n", "-i", t("old.img"), "::/*", t("files")], check=True)
        cfg = open(t("files/boot/grub/grub.cfg")).read()
        old_slot = os.path.getsize(t("files/boot/kernel-a.elf"))
        slot_bytes = (slot_kb << 10) if slot_kb else old_slot
        if slot_bytes < old_slot:
            sys.exit("the slots cannot shrink")
        # the new FAT: the same volume id, files in mkimg's order (slots contiguous)
        vol = old[39:43] if old[38] == 0x29 else old[67:71]
        with open(t("new.img"), "wb") as f:
            f.truncate(sectors * 512)
        subprocess.run(["mkfs.fat", "-F", "12" if sectors - 34 < 4000 else "16", "-s", "1", "-n", "RUSTROS",
                        "-i", vol[::-1].hex(), t("new.img")], check=True, stdout=subprocess.DEVNULL)
        mt = ["-i", t("new.img")]
        dirs = sorted({os.path.relpath(d, t("files")) for d, _, _ in os.walk(t("files"))} - {"."})
        for d in dirs:
            subprocess.run(["mmd", *mt, "::/" + d], check=True)
        special = ["EFI/BOOT/BOOTX64.EFI", "boot/grub/grubenv", "boot/kernel-a.elf", "boot/kernel-b.elf"]
        for rel in special:
            src = t("files/" + rel)
            if rel.startswith("boot/kernel-"):
                data = open(src, "rb").read()
                open(src, "wb").write(data + bytes(slot_bytes - len(data)))
            subprocess.run(["mcopy", *mt, src, "::/" + rel], check=True)
        for d, _, fs in os.walk(t("files")):
            for f in fs:
                rel = os.path.relpath(os.path.join(d, f), t("files"))
                if rel not in special and rel != "boot/grub/grub.cfg":
                    subprocess.run(["mcopy", *mt, os.path.join(d, f), "::/" + rel], check=True)
        img = open(t("new.img"), "rb").read()
        a_lba, _ = fat_locate(img, "/boot/kernel-a.elf")
        b_lba, _ = fat_locate(img, "/boot/kernel-b.elf")
        env_lba, _ = fat_locate(img, "/boot/grub/grubenv")
        new_args = f"rustros.slots={first + a_lba},{first + b_lba},{slot_bytes // 512} rustros.env={first + env_lba}"
        cfg, n = re.subn(r"rustros\.slots=\d+,\d+,\d+ rustros\.env=\d+", new_args, cfg)
        if n == 0:
            sys.exit("esp-grow: grub.cfg has no rustros.slots= to change")
        # the boot image's module bundle is behind us (installed at the first boot)
        cfg = re.sub(r" rustros\.bundle=\d+", "", cfg)
        open(t("grub.cfg"), "w").write(cfg)
        subprocess.run(["mcopy", *mt, t("grub.cfg"), "::/boot/grub/grub.cfg"], check=True)
        new = open(t("new.img"), "rb").read()
    print(f"EFI partition: {(old_last - old_first + 1) // 2} KiB at {old_first} -> {mb} MiB at {first}, "
          f"kernel slots {old_slot // 1024} -> {slot_bytes // 1024} KiB")
    step = ESP_CHUNK - 8  # under command()'s progress display
    for i in range(0, sectors, step):
        chunk = new[i * 512:(i + step) * 512]
        reply, _, _ = command(a.host, a.port, key, b"b", struct.pack("<Q", first + i) + chunk, encrypt=True)
        if reply != "OK":
            sys.exit(f"write at {first + i}: {reply} (nothing changed: the old partition is still in use)")
        print(f"\r  written {(i + len(chunk) // 512) * 100 // sectors}%", end="", flush=True)
    print()
    back = b"".join(sector_read(a, key, first + i, min(ESP_CHUNK, sectors - i), b"d") or b"" for i in range(0, sectors, ESP_CHUNK))
    if back != new:
        sys.exit("read back differs (nothing changed: the old partition is still in use)")
    # grubenv as it is now (it may have changed since it was copied)
    env = fat_locate(old, "/boot/grub/grubenv")[0]
    cur = esp_read(a, key, old_first + env, 2)
    reply, _, _ = command(a.host, a.port, key, b"b", struct.pack("<Q", first + env_lba) + cur, encrypt=True)
    if reply != "OK" or sector_read(a, key, first + env_lba, 2, b"d") != cur:
        sys.exit("could not bring grubenv up to date (nothing changed)")
    reply, _, _ = command(a.host, a.port, key, b"M", struct.pack("<QQ", first, last), encrypt=True)
    if reply != "OK":
        sys.exit(f"move: {reply} (nothing changed)")
    print("the GPT now points at the new EFI partition; rebooting into it")
    command(a.host, a.port, key, b"R")
    time.sleep(5)
    for _ in range(120):
        try:
            s, _, cur_slot, _ = hello(a.host, a.port, timeout=3)
            s.close()
            print(f"up again on slot {cur_slot}")
            return 0
        except OSError:
            time.sleep(1)
    sys.exit("it did not come back within 2 minutes")


def net_apply(a, key, secs):
    """As iptables-apply: show the changes, apply, then check that NEW
    connections still work before keeping them; otherwise the node reverts
    by itself when `secs` run out."""
    net = lambda text: command(a.host, a.port, key, b"N", text.encode())[0]
    preview = net("cand")
    print(preview)
    if not preview.startswith("candidate"):
        return 1
    if not a.yes and input("apply these changes? [y/N] ").strip().lower() not in ("y", "yes"):
        print("not applied (the candidate stays)")
        return 1
    t0 = time.time()
    r = net(f"apply {secs}")
    if r.startswith("ERR"):
        print(r)
        return 1
    print(f"applied; testing a new connection (reverted by itself in {secs} s unless kept) ...")
    try:
        s, _, _, _ = hello(a.host, a.port, timeout=max(1, min(5, secs - 1)) if secs else 5)
        s.close()
    except OSError as e:
        print(f"cannot open a new connection ({e}): the node goes back to the previous configuration")
        return 1
    if not a.yes:
        left = secs - (time.time() - t0) if secs else None
        q = "new connections work. keep these changes? [y/N]" + (f" ({left:.0f} s left) " if left else " ")
        if input(q).strip().lower() not in ("y", "yes"):
            print(net("revert"))
            return 1
    r = net("confirm")
    print(r)
    if r.startswith("too late") or r.startswith("nothing"):
        return 1
    print(f"keep it across reboots with: {sys.argv[0]} {a.host} net save")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("action", choices=["status", "upload", "confirm", "reboot", "poweroff", "info", "net", "log",
                                       "module-install", "module-remove", "module-switch", "module-config", "run", "ps", "kill",
                                       "esp-get", "esp-put", "esp-grow", "slots-grow"])
    ap.add_argument("image", nargs="?", help="kernel image, or the module name for module-*")
    ap.add_argument("module", nargs="?", help="module file (module-install), native|wasm, or the setting's key (module-config)")
    ap.add_argument("value", nargs="*", help="module-config: the value ('-' removes the setting)")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--key")
    ap.add_argument("--key-file", default="build/update.key")
    ap.add_argument("--wait", action="store_true", help="after upload, wait for the new kernel and confirm it")
    ap.add_argument("--stop-after", type=int, help="slots-grow: stop after this many writes (power-cut tests)")
    ap.add_argument("-y", "--yes", action="store_true", help="net apply: do not ask (keep the change if new connections work)")
    a = ap.parse_args()

    if a.action == "status":
        s, _, slot, trial = hello(a.host, a.port)
        s.close()
        print(f"running slot {slot}" + (" (trial boot, not confirmed)" if trial else ""))
        return

    key = a.key or os.environ.get("RUSTROS_KEY")
    if not key and os.path.exists(a.key_file):
        key = open(a.key_file).read().strip()
    if not key:
        sys.exit("no key: use --key, $RUSTROS_KEY or --key-file")
    key = key.encode()

    if a.action == "upload":
        if not a.image:
            sys.exit("upload needs an image")
        image = open(a.image, "rb").read()
        if image[:4] != b"\x7fELF":
            sys.exit(f"{a.image} is not an ELF file")
        print(f"uploading {a.image} ({len(image)} bytes)")
        reply, slot, _ = command(a.host, a.port, key, b"U", image)
        print(reply)
        if reply != "OK":
            sys.exit(1)
        new_slot = "b" if slot == "a" else "a"
        if not a.wait:
            print(f"rebooting into slot {new_slot}; run '{sys.argv[0]} {a.host} confirm' once it is up")
            return
        print(f"waiting for slot {new_slot} to come up...")
        went_down = False  # the old kernel may still answer for a moment
        t0 = time.time()
        for _ in range(180):
            try:
                s, _, cur, trial = hello(a.host, a.port, timeout=3)
                s.close()
                if cur == new_slot and trial:
                    break
                if cur == slot and not trial and (went_down or time.time() - t0 > 60):
                    sys.exit(f"came back on the old slot {slot}: the new kernel failed to boot")
            except OSError:
                went_down = True
            time.sleep(1)
        else:
            sys.exit("timed out waiting for the new kernel")
        reply, _, _ = command(a.host, a.port, key, b"C")
        print(f"confirm: {reply}")
        sys.exit(0 if reply == "OK" else 1)

    if a.action == "module-install":
        if not a.image or not a.module:
            sys.exit(f"{a.action} needs NAME and a module file")
        module = open(a.module, "rb").read()
        if module[:4] not in (b"\0asm", b"\x7fELF"):
            sys.exit(f"{a.module} is neither a WebAssembly module nor a native module")
        name = a.image.encode()
        reply, _, _ = command(a.host, a.port, key, b"W", bytes([len(name)]) + name + module)
        print(reply)
        sys.exit(0 if reply == "OK" else 1)
    if a.action == "esp-grow":
        if not a.image or not a.image.isdigit():
            sys.exit("esp-grow needs the new size in MiB (and optionally the slot size in KiB)")
        sys.exit(esp_grow(a, key, int(a.image), int(a.module) if a.module else 0))
    if a.action == "slots-grow":
        if a.image and not a.image.isdigit():
            sys.exit("slots-grow takes the slot size in KiB (default: as big as fits)")
        sys.exit(slots_grow(a, key, int(a.image or 0), a.stop_after))
    if a.action in ("esp-get", "esp-put"):
        if not a.image:
            sys.exit(f"{a.action} needs a FILE")
        sys.exit(esp(a, key))
    if a.action == "run":
        if not a.image:
            sys.exit("run needs a program file (and its arguments)")
        args = [os.path.basename(a.image)] + [w for w in [a.module, *a.value] if w]
        payload = bytes([len(args)]) + b"".join(bytes([len(x.encode())]) + x.encode() for x in args) + open(a.image, "rb").read()
        reply, _, _ = command(a.host, a.port, key, b"G", payload)
        print(reply)
        sys.exit(0 if reply.startswith("OK") else 1)
    if a.action in ("ps", "kill"):
        words = [a.action] + [w for w in [a.image] if w]
        reply, _, _ = command(a.host, a.port, key, b"J", " ".join(words).encode())
        print(reply, end="" if reply.endswith("\n") else "\n")
        sys.exit(1 if reply.startswith("ERR") else 0)
    if a.action == "log":
        words = [w for w in [a.image, a.module, *a.value] if w]
        reply, _, _ = command(a.host, a.port, key, b"L", " ".join(words).encode())
        print(reply, end="" if reply.endswith("\n") else "\n")
        sys.exit(1 if reply.startswith("ERR") else 0)
    if a.action == "net":
        words = [w for w in [a.image, a.module, *a.value] if w]
        if not words:
            words = ["ip"]
        if words[0] == "apply":
            sys.exit(net_apply(a, key, int(words[1]) if len(words) > 1 else 10))
        reply, _, _ = command(a.host, a.port, key, b"N", " ".join(words).encode())
        print(reply)
        sys.exit(1 if reply.startswith("ERR") else 0)
    if a.action == "module-config":
        if not a.image:
            sys.exit("module-config needs NAME [KEY [VALUE | -]]")
        if a.module is None:
            reply, _, _ = command(a.host, a.port, key, b"Q", a.image.encode(), encrypt=True)
            print(reply)
            return
        payload = f"{a.image}\n{a.module}"
        value = " ".join(a.value)
        if value and value != "-":
            payload += "\n" + value
        elif not value:
            sys.exit("module-config NAME KEY needs a VALUE, or '-' to remove it")
        reply, _, _ = command(a.host, a.port, key, b"K", payload.encode(), encrypt=True)
        print(reply)
        sys.exit(0 if reply == "OK" else 1)
    if a.action in ("module-remove", "module-switch"):
        if not a.image:
            sys.exit(f"{a.action} needs NAME")
        kind = a.module or ""
        if a.action == "module-switch" and kind not in ("native", "wasm"):
            sys.exit("module-switch needs native or wasm")
        cmd = b"S" if a.action == "module-switch" else b"X"
        reply, _, _ = command(a.host, a.port, key, cmd, f"{a.image} {kind}".strip().encode())
        print(reply)
        sys.exit(0 if reply == "OK" else 1)

    reply, _, _ = command(a.host, a.port, key, a.action[0].upper().encode())
    print(reply)
    ok = not reply.startswith("ERR") if a.action == "info" else reply == "OK"
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
