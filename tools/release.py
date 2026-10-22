#!/usr/bin/env python3
"""Publish a RustROS release (and the website) on a machine running the
sites app.

  release.py --host <origin address> [--version 2026.10.22.1] [--no-build]
             [--site rustros.com] [--key build/release.key] [--token-file build/sites.token]

It builds the kernel and the modules with RUSTROS_BUILD=<version> (unless
--no-build: then it checks the built files carry that version), writes
releases/<version>/ with the kernel and every app, the manifest
releases/latest.json signed with the release key (Ed25519, by openssl:
releases/latest.json.sig, base64url) and the public key releases/key.pub,
and uploads them and site/ over HTTPS (PUT /_sites/files/...).

The manifest is what the panel and `pkg` read:
  {"format":1, "version", "date",
   "kernel":{"version", "x86_64":{"url","sha256","size"}},
   "modules":{"<name>":{"version","kind","description","requires",
                        "native":{"x86_64":{"url","sha256","size"}}}}}
"""
import argparse, base64, datetime, hashlib, http.client, json, os, socket, ssl, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# What each app is (published ones; test modules stay out).
APPS = {
    "nat": "NAT: masquerading, static mappings, port forwards",
    "router": "forwarding between interfaces",
    "cake": "CAKE traffic shaping",
    "l2tp": "L2TP VPN servers (per address) and dial-out clients",
    "wireguard": "WireGuard servers and clients (WARP too)",
    "proxy": "SOCKS5 and HTTP proxies",
    "anytls": "AnyTLS proxy server",
    "webadmin": "web administration",
    "shell": "the console shell (curl, warp, ping, cfg ...)",
    "wasm": "the WebAssembly runtime for wasm apps",
    "panel": "connects the machine to a management panel",
    "sites": "websites: static files, reverse proxy, Let's Encrypt",
}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def put(host, site, token, path, data, ctx):
    """One upload; raises on failure."""
    c = http.client.HTTPSConnection(host, 443, timeout=120, context=ctx)
    # connect by address, but speak to the site by name (SNI and Host)
    c.sock = ctx.wrap_socket(socket.create_connection((host, 443), timeout=120), server_hostname=site)
    c.request("PUT", "/_sites/files/" + path, body=data, headers={"Host": site, "Authorization": "Bearer " + token, "Content-Length": str(len(data))})
    r = c.getresponse()
    body = r.read()
    if r.status != 201:
        raise SystemExit(f"upload {path}: {r.status} {body.decode(errors='replace').strip()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="the machine running the site (address)")
    ap.add_argument("--site", default="rustros.com")
    ap.add_argument("--root", default="rustros.com", help="the site's files directory on that machine")
    ap.add_argument("--version", default="")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--key", default=f"{ROOT}/build/release.key")
    ap.add_argument("--token-file", default=f"{ROOT}/build/sites.token")
    ap.add_argument("--dry-run", action="store_true", help="build and sign, upload nothing")
    a = ap.parse_args()

    version = a.version or datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d") + ".1"
    if not a.no_build:
        env = dict(os.environ, RUSTROS_BUILD=version)
        subprocess.run(["touch", f"{ROOT}/api/src/lib.rs"], check=True)
        subprocess.run(["make", "-C", ROOT, "all", "modules"], env=env, check=True, stdout=subprocess.DEVNULL)
    kernel = open(f"{ROOT}/build/rustros.elf", "rb").read()
    files = {}  # published path (under releases/<version>/) -> bytes
    files["rustros-x86_64.elf"] = kernel
    mods = {}
    for name, desc in APPS.items():
        data = open(f"{ROOT}/build/modules/{name}.mod", "rb").read()
        if version.encode() not in data:
            raise SystemExit(f"{name}.mod was not built as {version} (build it, or drop --no-build)")
        files[f"{name}-x86_64.mod"] = data
        mods[name] = {"version": version, "kind": "app", "description": desc, "requires": [],
                      "native": {"x86_64": {"url": f"https://{a.site}/releases/{version}/{name}-x86_64.mod", "sha256": sha256(data), "size": len(data)}}}
    manifest = {
        "format": 1,
        "version": version,
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kernel": {"version": version, "x86_64": {"url": f"https://{a.site}/releases/{version}/rustros-x86_64.elf", "sha256": sha256(kernel), "size": len(kernel)}},
        "modules": mods,
    }
    body = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
    tmp = f"{ROOT}/build/latest.json"
    open(tmp, "wb").write(body)
    sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", a.key, "-in", tmp], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "pkey", "-in", a.key, "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout[-32:]
    # checked with the public key before anything goes out
    open(f"{ROOT}/build/latest.json.sig.bin", "wb").write(sig)
    pubpem = subprocess.run(["openssl", "pkey", "-in", a.key, "-pubout"], capture_output=True, check=True).stdout
    open(f"{ROOT}/build/release.pub.pem", "wb").write(pubpem)
    v = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", f"{ROOT}/build/release.pub.pem", "-in", tmp, "-sigfile", f"{ROOT}/build/latest.json.sig.bin"], capture_output=True, text=True)
    if "Successfully" not in v.stdout + v.stderr:
        raise SystemExit("the manifest's signature does not verify")
    print(f"release {version}: kernel {len(kernel)} bytes, {len(mods)} apps, manifest signed by {base64.b64encode(pub).decode()}")
    if a.dry_run:
        return
    token = open(a.token_file).read().strip()
    ctx = ssl.create_default_context()
    up = lambda p, d: put(a.host, a.site, token, f"{a.root}/{p}", d, ctx)
    for name, data in files.items():
        up(f"releases/{version}/{name}", data)
        print(f"  releases/{version}/{name} ({len(data)} bytes)")
    for d, _, fs in os.walk(f"{ROOT}/site"):
        for f in fs:
            p = os.path.join(d, f)
            up(os.path.relpath(p, f"{ROOT}/site"), open(p, "rb").read())
            print(f"  {os.path.relpath(p, f'{ROOT}/site')}")
    up("releases/key.pub", (base64.b64encode(pub).decode() + "\n").encode())
    # the manifest last: what it names is there before it is announced
    up("releases/latest.json.sig", b64u(sig).encode())
    up("releases/latest.json", body)
    print(f"  releases/latest.json (+ .sig, key.pub)\nhttps://{a.site}/releases/latest.json")


if __name__ == "__main__":
    main()
