#!/bin/sh
# Install RustROS on this machine (a Linux VPS or server booted by GRUB).
#
#   curl -fsSL https://rustros.com/install.sh | sh
#   curl -fsSL https://rustros.com/install.sh | sh -s -- --apps ext4,shell,webadmin
#
# Step 1 (this): download the release (its signature and checksums checked),
# make the disk image for this machine, and boot RustROS once as a test:
# the disk is not touched, and after 5 minutes the machine is back in Linux.
# Step 2, back in Linux: python3 /root/rustros/install.py --write
# writes RustROS over the system disk. Everything on it is lost.
#
# Options (python3 /root/rustros/install.py --help for all):
#   --apps a,b      apps installed at first boot (default: ext4,shell)
#   --ip A/N --gw G a static address (default: as Linux has it now; DHCP if Linux got it by DHCP)
#   --dhcp          DHCP whatever Linux uses
#   --panel URL     connect to a management panel
#   --no-test       skip the test boot (the next step still needs --write)
# Not installing after all: python3 /root/rustros/install.py --clean
set -eu
if [ "$(id -u)" != 0 ]; then
    echo "rustros: run this as root" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "rustros: python3 is needed (apt-get install -y python3)" >&2
    exit 1
fi
mkdir -p /root/rustros
chmod 700 /root/rustros
cat > /root/rustros/install.py <<'PYTHON'
#!/usr/bin/env python3
"""RustROS installer (see https://rustros.com/install.sh).

  install.py [options]           prepare and test-boot (default)
  install.py --write [--yes]     write the prepared image over the system disk
"""
import argparse, base64, hashlib, json, os, re, secrets, shutil, struct, subprocess, sys, tempfile, time, urllib.request

REPO = os.environ.get("RUSTROS_REPO", "https://rustros.com/releases/latest.json")
# the release key (public half); a test repository brings its own
REPO_KEY = os.environ.get("RUSTROS_REPO_KEY", "5JddaWkdvKjJte+tGwE9kn6f33EOUj2ixVBBOj45s38=")
DIR = "/root/rustros"
STATE = f"{DIR}/state.json"
TEST_SECS = int(os.environ.get("RUSTROS_TEST_SECS", "300"))
UA = {"User-Agent": "rustros-installer/1"}
ENV_MAGIC = b"# GRUB Environment Block\n"
BUNDLE_MAGIC, BUNDLE_HEAD, BUNDLE_ENTRY = b"RRSBNDL1", 4096, 80


def say(*a):
    print("rustros:", *a, flush=True)


def die(msg):
    print(f"rustros: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"{' '.join(cmd)} failed: {(r.stderr or r.stdout).strip()}")
    return r.stdout.strip()


def have(cmd):
    return shutil.which(cmd) is not None


def ask(question):
    """y/N from the terminal (stdin may be the script itself)."""
    try:
        with open("/dev/tty") as tty:
            print(question, end=" ", flush=True)
            return tty.readline().strip()
    except OSError:
        return ""


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        return r.read()


# ------------------------------------------------------------------ the release

def verify_sig(data, sig_b64u):
    """Ed25519 by openssl (3.0 or later): True if the release key signed `data`."""
    raw = base64.b64decode(REPO_KEY)
    der = bytes.fromhex("302a300506032b6570032100") + raw
    with tempfile.TemporaryDirectory() as t:
        open(f"{t}/pub.pem", "w").write("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n")
        open(f"{t}/data", "wb").write(data)
        s = sig_b64u.strip()
        open(f"{t}/sig", "wb").write(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{t}/pub.pem", "-rawin", "-in", f"{t}/data", "-sigfile", f"{t}/sig"], capture_output=True, text=True)
        return "Signature Verified Successfully" in r.stdout + r.stderr


def fetch(entry, what):
    data = get(entry["url"])
    if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        die(f"{what}: the download does not match the release (SHA-256)")
    return data


# ------------------------------------------------------------------ this machine

def boot_disk():
    src = sh("findmnt", "-no", "SOURCE", "/")
    if not src.startswith("/dev/"):
        die(f"the root file system is on {src}: only a plain disk partition is supported")
    disk = sh("lsblk", "-no", "PKNAME", src).splitlines()
    if not disk or not disk[0]:
        die(f"cannot tell which disk {src} is on (LVM or RAID are not supported)")
    dev = "/dev/" + disk[0].strip()
    size = int(sh("blockdev", "--getsize64", dev))
    return dev, size


def network():
    route = sh("ip", "-4", "route", "show", "default").split()
    if "via" not in route or "dev" not in route:
        die("no IPv4 default route")
    gw, dev = route[route.index("via") + 1], route[route.index("dev") + 1]
    addrs = [l.split() for l in sh("ip", "-4", "-o", "addr", "show", "dev", dev, "scope", "global").splitlines()]
    if not addrs:
        die(f"no IPv4 address on {dev}")
    a = addrs[0]
    cidr = a[a.index("inet") + 1]
    nics = [n for n in os.listdir("/sys/class/net") if os.path.exists(f"/sys/class/net/{n}/device")]
    return {"dev": dev, "ip": cidr, "gw": gw, "dhcp": "dynamic" in a, "nics": sorted(nics)}


def uefi():
    return os.path.isdir("/sys/firmware/efi")


def secure_boot():
    if have("mokutil"):
        return "enabled" in sh("mokutil", "--sb-state", check=False).lower()
    for f in os.listdir("/sys/firmware/efi/efivars") if uefi() else []:
        if f.startswith("SecureBoot-"):
            return open(f"/sys/firmware/efi/efivars/{f}", "rb").read()[-1:] == b"\x01"
    return False


def grub_cmds():
    for pre in ("grub", "grub2"):
        if have(f"{pre}-reboot") and have(f"{pre}-mkconfig"):
            cfg = next((c for c in (f"/boot/{pre}/grub.cfg", "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg") if os.path.exists(c)), None)
            if cfg:
                return pre, cfg
    die("GRUB (grub-reboot, grub-mkconfig) was not found: this machine must boot with GRUB 2")


# ------------------------------------------------------------------ the image

def make_image(template, apps, env):
    img = bytearray(template)
    at = None
    for o in range(0, len(img), 512):
        if img[o:o + len(ENV_MAGIC)] == ENV_MAGIC and b"boot_slot=" in img[o:o + 1024]:
            at = o
            break
    if at is None:
        die("the image has no grubenv block")
    text = ENV_MAGIC + "".join(f"{k}={v}\n" for k, v in env.items() if v).encode()
    if len(text) > 1024 or any("\n" in str(v) or "\\" in str(v) for v in env.values()):
        die("the settings do not fit the image")
    img[at:at + 1024] = text + b"#" * (1024 - len(text))
    m = re.search(rb"rustros\.bundle=(\d+)", img)
    if not m:
        die("the image takes no bundle")
    bundle_lba = int(m.group(1))
    if bundle_lba * 512 != len(img):
        die("the bundle does not start where the image ends")
    entries, blobs, sec = [], [], BUNDLE_HEAD // 512
    for name, data in apps:
        entries.append(name.encode().ljust(32, b"\0") + struct.pack("<II", sec, len(data)) + hashlib.sha256(data).digest() + bytes(8))
        padded = data + bytes(-len(data) % 512)
        blobs.append(padded)
        sec += len(padded) // 512
    head = (BUNDLE_MAGIC + struct.pack("<II", len(entries), 0) + b"".join(entries)).ljust(BUNDLE_HEAD, b"\0")
    img += head + b"".join(blobs)
    if len(img) > 64 << 20:
        die("the image and its apps must stay under 64 MiB")
    return bytes(img)


# ------------------------------------------------------------------ step 1

def prepare(a):
    if os.uname().machine != "x86_64":
        die("RustROS runs on x86_64 only")
    for c in ("openssl", "findmnt", "lsblk", "blockdev", "ip"):
        if not have(c):
            die(f"{c} is needed")
    if uefi() and secure_boot():
        die("Secure Boot is on: RustROS is not signed for it. Turn Secure Boot off first.")
    pre, grub_cfg = grub_cmds()
    disk, size = boot_disk()
    if size < 2 << 30:
        die(f"{disk} is {size >> 20} MiB: RustROS wants at least 2 GiB")
    net = network()

    say(f"reading {REPO}")
    manifest = get(REPO)
    if not verify_sig(manifest, get(REPO + ".sig").decode()):
        die("the release's signature does not check out")
    m = json.loads(manifest)
    say(f"release {m['version']}, signature checked")
    image = m.get("image", {}).get("x86_64")
    if not image:
        die("this release has no disk image")
    apps = []
    for name in [x for x in a.apps.split(",") if x]:
        e = m["modules"].get(name)
        if not e or "x86_64" not in e.get("native", {}):
            die(f"no app {name} in release {m['version']}")
        apps.append((name, fetch(e["native"]["x86_64"], name)))
    template = fetch(image, "the disk image")
    kernel = fetch(m["kernel"]["x86_64"], "the kernel")

    key = a.key or secrets.token_hex(16)
    if a.dhcp:
        ip, gw = "", ""
    elif a.ip:
        ip, gw = a.ip, a.gw or net["gw"]
    else:
        ip, gw = ("", "") if net["dhcp"] else (net["ip"], net["gw"])
    env = {"boot_slot": "a", "update_key": key, "net_ip": ip, "net_gw": gw, "panel_url": a.panel}
    img = make_image(template, apps, env)
    os.makedirs(DIR, exist_ok=True)
    open(f"{DIR}/rustros.img", "wb").write(img)
    fd = os.open(f"{DIR}/update.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, (key + "\n").encode())
    os.close(fd)
    st = {"version": m["version"], "disk": disk, "size": size, "image_sha256": hashlib.sha256(img).hexdigest(),
          "ip": ip or f"DHCP (now {net['ip']})", "gw": gw, "apps": [n for n, _ in apps], "tested": False, "uefi": uefi()}
    json.dump(st, open(STATE, "w"))
    say(f"image for this machine: {DIR}/rustros.img ({len(img) >> 20} MiB), apps: {', '.join(st['apps']) or 'none'}")
    say(f"network: {st['ip']}" + (f" gw {gw}" if gw else "") + (f"  (NICs: {', '.join(net['nics'])}: RustROS uses the first)" if len(net["nics"]) > 1 else ""))
    say(f"update key (saved in {DIR}/update.key; copy it off this machine): {key}")

    if a.no_test:
        say(f"no test boot. To install: python3 {DIR}/install.py --write")
        return
    # the test boot: GRUB boots the kernel once, with the network but without the disk
    open("/boot/rustros-test.elf", "wb").write(kernel)
    rel = sh(f"{pre}-mkrelpath", "/boot/rustros-test.elf")
    uuid = sh(f"{pre}-probe", "--target=fs_uuid", "/boot")
    fsmod = sh(f"{pre}-probe", "--target=fs", "/boot")
    parts = sh(f"{pre}-probe", "--target=partmap", "/boot", check=False).split()
    args = f"rustros.testboot={TEST_SECS} key={key}" + (f" ip={ip} gw={gw}" if ip else "")
    entry = (f"#!/bin/sh\nexec tail -n +3 $0\nmenuentry 'RustROS test' {{\n" + "".join(f"    insmod part_{p}\n" for p in parts) +
             f"    insmod {fsmod}\n    insmod multiboot2\n    search --no-floppy --fs-uuid --set=root {uuid}\n    multiboot2 {rel} {args}\n    module2 {rel}\n    boot\n}}\n")
    fd = os.open("/etc/grub.d/45_rustros_test", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)  # it holds the key
    os.write(fd, entry.encode())
    os.close(fd)
    # grub-reboot needs GRUB_DEFAULT=saved; the saved default stays what it was
    dflt = "/etc/default/grub"
    text = open(dflt).read() if os.path.exists(dflt) else ""
    cur = re.search(r"^GRUB_DEFAULT=(.*)$", text, re.M)
    if not cur or cur.group(1).strip().strip("\"'") != "saved":
        old = cur.group(1).strip().strip("\"'") if cur else "0"
        st["grub_default"] = cur.group(1).strip() if cur else "0"
        text = re.sub(r"^GRUB_DEFAULT=.*$", "GRUB_DEFAULT=saved", text, flags=re.M) if cur else text + "\nGRUB_DEFAULT=saved\n"
        open(dflt, "w").write(text)
        sh(f"{pre}-set-default", old)
    sh(f"{pre}-mkconfig", "-o", grub_cfg)
    os.chmod(grub_cfg, 0o600)
    if "RustROS test" not in open(grub_cfg).read():
        die("the test entry did not make it into GRUB's configuration")
    sh(f"{pre}-reboot", "RustROS test")
    st["tested"] = True
    json.dump(st, open(STATE, "w"))
    say(f"the next boot runs RustROS {m['version']} once, for {TEST_SECS // 60} minutes, without touching the disk;")
    say(f"it should answer ping at {(ip or net['ip']).split('/')[0]}; the console (VNC) shows what it found.")
    say(f"Then it restarts into Linux. If it worked: python3 {DIR}/install.py --write")
    if a.yes or ask("Reboot now for the test? [y/N]").lower() == "y":
        subprocess.run(["systemctl", "reboot"]) if have("systemctl") else subprocess.run(["reboot"])
    else:
        say("reboot when you are ready (the test entry is set for the next boot only)")


# ------------------------------------------------------------------ step 2

EFIVARS = "/sys/firmware/efi/efivars"
GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def efi_var(name):
    with open(f"{EFIVARS}/{name}-{GLOBAL}", "rb") as f:
        return f.read()


def efi_generic(opt):
    """A boot option of the firmware's own for a disk: a device path with no
    file in it (it boots \\EFI\\BOOT\\BOOTX64.EFI), no network, no firmware app."""
    plen = struct.unpack_from("<H", opt, 8)[0]
    at = 10
    while at + 1 < len(opt) and struct.unpack_from("<H", opt, at)[0] != 0:
        at += 2
    path, kinds = opt[at + 2:at + 2 + plen], set()
    o = 0
    while o + 4 <= len(path):
        t, st, ln = path[o], path[o + 1], struct.unpack_from("<H", path, o + 2)[0]
        if ln < 4 or t == 0x7F:
            break
        kinds.add((t, st))
        o += ln
    has_disk = (1, 1) in kinds or (4, 1) in kinds   # PCI device, or a partition
    has_file = (4, 4) in kinds or (4, 6) in kinds   # a file, or a firmware volume file (apps)
    network = any(t == 3 and st in (11, 12, 24) for t, st in kinds)  # MAC, IPv4, URI
    return has_disk and not has_file and not network


def efi_boot_order():
    """The firmware's own disk entries first in BootOrder (through efivarfs)."""
    try:
        raw = efi_var("BootOrder")
    except OSError:
        return "no BootOrder variable: if the machine does not boot, choose the disk in the firmware's boot menu"
    attrs, order = raw[:4], [struct.unpack_from("<H", raw, 4 + 2 * i)[0] for i in range((len(raw) - 4) // 2)]
    generic = []
    for n in order:
        try:
            if efi_generic(efi_var(f"Boot{n:04X}")[4:]):
                generic.append(n)
        except (OSError, struct.error):
            pass
    if not generic:
        return "no firmware disk entry in the boot order: if the machine does not boot, choose the disk in the firmware's boot menu"
    new = generic + [n for n in order if n not in generic]
    path = f"{EFIVARS}/BootOrder-{GLOBAL}"
    subprocess.run(["chattr", "-i", path], capture_output=True)  # efivarfs files are immutable
    with open(path, "wb") as f:
        f.write(attrs + b"".join(struct.pack("<H", n) for n in new))
    return "UEFI boot order: " + ",".join(f"{n:04X}" for n in new) + " (the disk's own entries first)"


def clean(a):
    """Undo the test boot's changes (when not installing after all)."""
    pre, grub_cfg = grub_cmds()
    for f in ("/etc/grub.d/45_rustros_test", "/boot/rustros-test.elf"):
        if os.path.exists(f):
            os.remove(f)
    st = json.load(open(STATE)) if os.path.exists(STATE) else {}
    if st.get("grub_default") is not None:
        text = open("/etc/default/grub").read()
        text = re.sub(r"^GRUB_DEFAULT=saved$", f"GRUB_DEFAULT={st['grub_default']}", text, flags=re.M)
        open("/etc/default/grub", "w").write(text)
    sh(f"{pre}-mkconfig", "-o", grub_cfg)
    shutil.rmtree(DIR, ignore_errors=True)
    say("the test entry and RustROS's files are gone; Linux is as it was")


def write(a):
    if not os.path.exists(STATE):
        die(f"nothing prepared: run the installer first")
    st = json.load(open(STATE))
    img = open(f"{DIR}/rustros.img", "rb").read()
    if hashlib.sha256(img).hexdigest() != st["image_sha256"]:
        die("the prepared image has changed: prepare it again")
    disk, size = boot_disk()
    if disk != st["disk"]:
        die(f"the system disk is now {disk}, it was {st['disk']}: prepare again")
    key = open(f"{DIR}/update.key").read().strip()
    say(f"RustROS {st['version']} goes onto {disk} ({size >> 30} GiB). EVERYTHING ON {disk} IS LOST.")
    say(f"network {st['ip']}" + (f" gw {st['gw']}" if st["gw"] else "") + f", apps {', '.join(st['apps']) or 'none'}")
    say(f"update key: {key}  (it is on {disk} too, but nowhere else: keep it)")
    if not st["tested"]:
        say("this machine has not had a test boot")
    if not a.yes and ask(f"Type 'yes' to overwrite {disk}:") != "yes":
        die("nothing written")
    if st["uefi"]:
        say(efi_boot_order())
    # from here only what is in memory runs: the disk under Linux is going away
    subprocess.run(["swapoff", "-a"], capture_output=True)
    os.sync()
    with open("/proc/sys/kernel/sysrq", "w") as f:
        f.write("1")
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("u")  # every file system read-only: nothing writes into what is overwritten
    time.sleep(2)
    fd = os.open(disk, os.O_RDWR | os.O_SYNC)
    try:
        os.write(fd, img)
        # what was at RustROS's partitions and the old backup GPT must not look like anything
        zero = bytes(1 << 20)
        for off in (64 << 20, 512 << 20, 1 << 30):
            if off + len(zero) <= size:
                os.pwrite(fd, zero, off)
        os.pwrite(fd, bytes(33 * 512), size - 33 * 512)
        os.fsync(fd)
        back = os.pread(fd, len(img), 0)
    finally:
        os.close(fd)
    if back != img:
        say("WARNING: the disk does not read back as written; the machine may not boot")
    print("rustros: written. Restarting into RustROS.", flush=True)
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("b")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="write the prepared image over the system disk")
    ap.add_argument("--clean", action="store_true", help="not installing after all: remove the test entry and the downloads")
    ap.add_argument("--apps", default="ext4,shell", help="apps installed at first boot, comma separated (default: ext4,shell)")
    ap.add_argument("--ip", default="", help="a static address A.B.C.D/N")
    ap.add_argument("--gw", default="", help="its gateway")
    ap.add_argument("--dhcp", action="store_true", help="use DHCP")
    ap.add_argument("--panel", default="", help="the management panel to connect to (URL)")
    ap.add_argument("--key", default="", help="the update key (default: a new one)")
    ap.add_argument("--no-test", action="store_true", help="no test boot")
    ap.add_argument("--yes", action="store_true", help="do not ask")
    a = ap.parse_args()
    if os.geteuid() != 0:
        die("run this as root")
    clean(a) if a.clean else write(a) if a.write else prepare(a)


if __name__ == "__main__":
    main()
PYTHON
chmod 700 /root/rustros/install.py
exec python3 /root/rustros/install.py "$@"
