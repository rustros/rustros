#!/usr/bin/env python3
"""Third-party notices for what a release ships.

  notices.py [OUT]     (default build/THIRD-PARTY-NOTICES.txt)

RustROS itself is proprietary (LICENSE). The release's files contain other
people's code under permissive licences, which ask for their copyright
notices and licence texts to go along: the Rust crates linked into the
kernel and the modules (cargo metadata, normal dependencies for the target
the binaries are built for; build scripts and proc macros run only at build
time and are left out), Rust's own core and alloc, and GRUB (GPLv3, a
separate program: the boot loader in the disk images), whose source is
published next to the releases (grub_sources()).
"""
import json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACES = [(".", "x86_64-unknown-none"), ("modules", "x86_64-unknown-none"), ("wasm", "wasm32-unknown-unknown")]
LICENSE_FILES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
GRUB_PACKAGES = ("grub-pc-bin", "grub-efi-amd64-bin")
DEBIAN_POOL = "https://deb.debian.org/debian/pool/main/g/grub2"


def linked(ws, target):
    """The third-party packages the workspace's binaries link."""
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--filter-platform", target],
                                     cwd=os.path.join(ROOT, ws), capture_output=True, check=True).stdout)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, todo = set(), list(meta["workspace_members"])
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] is None for k in d["dep_kinds"]):
                p = pkgs[d["pkg"]]
                if not any("proc-macro" in t["kind"] for t in p["targets"]):
                    todo.append(d["pkg"])
    return [pkgs[i] for i in seen if pkgs[i]["source"] is not None]


def grub_version():
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Version}\n", *GRUB_PACKAGES], capture_output=True, text=True, check=True).stdout.split()
    if len(set(out)) != 1:
        raise SystemExit(f"GRUB packages at different versions: {out}")
    return out[0]


def grub_sources():
    """GRUB's source package (as Debian ships it) for the GRUB in the images: [(file name, url)]."""
    v = grub_version()
    upstream = v.split("-")[0]
    return [(f, f"{DEBIAN_POOL}/{f}") for f in (f"grub2_{v}.dsc", f"grub2_{upstream}.orig.tar.xz", f"grub2_{v}.debian.tar.xz")]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else f"{ROOT}/build/THIRD-PARTY-NOTICES.txt"
    crates = {}
    for ws, target in WORKSPACES:
        for p in linked(ws, target):
            crates[(p["name"], p["version"])] = p
    texts = {}  # licence text -> the crates that carry it
    bare = []  # crates without a licence file: MIT or Apache-2.0, the standard texts
    for (name, version), p in sorted(crates.items()):
        d = os.path.dirname(p["manifest_path"])
        files = sorted(f for f in os.listdir(d) if f.upper().startswith(LICENSE_FILES) and os.path.isfile(os.path.join(d, f)))
        if not files:
            # no file in the package: used under MIT or Apache-2.0 (standard texts, the ones Rust's are under)
            if not {"MIT", "Apache-2.0"} & set(p["license"].replace("/", " OR ").split(" OR ")):
                raise SystemExit(f"{name} {version}: no licence file in {d}")
            bare.append(f"{name} {version} ({p.get('repository') or 'crates.io'})")
        for f in files:
            texts.setdefault(open(os.path.join(d, f), errors="replace").read().strip(), []).append(f"{name} {version}")
    rust = os.path.expanduser("~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/share/doc/rust/licenses")
    gv = grub_version()
    w = []
    w.append("RustROS third-party notices\n===========================\n")
    w.append("RustROS is proprietary software (see LICENSE.txt). The kernel, the modules and the disk images\n"
             "contain the third-party software below, used under the licences reproduced here.\n")
    w.append(f"GRUB {gv.split('-')[0]} (Debian package {gv})\n----\n"
             "The disk images carry GRUB, the boot loader (BIOS boot sector and core image, BOOTX64.EFI for UEFI).\n"
             "GRUB is a separate program, licensed under the GNU General Public License version 3 or later.\n"
             "Its complete corresponding source, as built, is available from the same place as the releases:\n")
    for f, _ in grub_sources():
        w.append(f"  https://rustros.com/releases/sources/{f}")
    w.append("The licence text is at the end of this file.\n")
    w.append("Rust core and alloc libraries\n----\nCopyright the Rust Project Developers. MIT or Apache-2.0 (texts below).\n")
    w.append(f"Rust crates\n----\n" + "\n".join(f"  {n} {v}: {crates[(n, v)]['license']}" for n, v in sorted(crates)) + "\n")
    for text, users in texts.items():
        w.append("=" * 72 + "\n" + ", ".join(users) + "\n" + "=" * 72 + "\n" + text + "\n")
    for f in ("MIT.txt", "Apache-2.0.txt"):
        w.append("=" * 72 + f"\nRust core and alloc, and {', '.join(bare)}: {f[:-4]}\n" + "=" * 72 + "\n" + open(os.path.join(rust, f)).read().strip() + "\n")
    w.append("=" * 72 + "\nGRUB: GNU General Public License version 3\n" + "=" * 72 + "\n" + open("/usr/share/common-licenses/GPL-3").read().strip() + "\n")
    open(out, "w").write("\n".join(w))
    print(f"{out}: {len(crates)} crates, {len(texts)} licence texts, GRUB {gv}")


if __name__ == "__main__":
    main()
