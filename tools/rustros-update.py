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
        while cmd in (b"I", b"E", b"N", b"L") or not reply.endswith(b"\n"):
            chunk = s.recv(256)
            if not chunk:
                break
            reply += chunk
    finally:
        s.close()
    return reply.decode(errors="replace").strip(), slot, trial


# The EFI partition, as tools/mkimg.py lays it out.
ESP_FIRST, ESP_LAST = 576, 4096 - 34
ESP_CHUNK = 128


def esp_read(a, key, lba, n):
    reply, _, _ = command(a.host, a.port, key, b"D", struct.pack("<QH", lba, n), encrypt=True)
    if not reply.startswith("OK "):
        sys.exit(f"esp read at {lba}: {reply}")
    return keystream_xor(key, command.nonce + b"R", bytes.fromhex(reply[3:]))


def esp_get(a, key):
    data = b""
    for lba in range(ESP_FIRST, ESP_LAST + 1, ESP_CHUNK):
        data += esp_read(a, key, lba, min(ESP_CHUNK, ESP_LAST + 1 - lba))
    return data


def esp(a, key):
    if a.action == "esp-get":
        data = esp_get(a, key)
        fd = os.open(a.image, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # it holds the key
        os.write(fd, data)
        os.close(fd)
        print(f"{len(data)} bytes ({len(data) // 512} sectors from {ESP_FIRST})")
        return 0
    new = open(a.image, "rb").read()
    old = esp_get(a, key)
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
    for first, end in runs:
        reply, _, _ = command(a.host, a.port, key, b"B", struct.pack("<Q", ESP_FIRST + first) + new[first * 512:end * 512], encrypt=True)
        if reply != "OK":
            sys.exit(f"esp write at {ESP_FIRST + first}: {reply}")
    if esp_get(a, key) != new:
        sys.exit("verify failed: the EFI partition does not match the file")
    print(f"{len(changed)} sectors written in {len(runs)} runs, verified")
    return 0


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
                                       "module-install", "module-remove", "module-switch", "module-config",
                                       "wasm-install", "wasm-remove", "esp-get", "esp-put"])
    ap.add_argument("image", nargs="?", help="kernel image, or the module name for module-*")
    ap.add_argument("module", nargs="?", help="module file (module-install), native|wasm, or the setting's key (module-config)")
    ap.add_argument("value", nargs="*", help="module-config: the value ('-' removes the setting)")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--key")
    ap.add_argument("--key-file", default="build/update.key")
    ap.add_argument("--wait", action="store_true", help="after upload, wait for the new kernel and confirm it")
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

    if a.action in ("module-install", "wasm-install"):
        if not a.image or not a.module:
            sys.exit(f"{a.action} needs NAME and a module file")
        module = open(a.module, "rb").read()
        if module[:4] not in (b"\0asm", b"\x7fELF"):
            sys.exit(f"{a.module} is neither a WebAssembly module nor a native module")
        name = a.image.encode()
        reply, _, _ = command(a.host, a.port, key, b"W", bytes([len(name)]) + name + module)
        print(reply)
        sys.exit(0 if reply == "OK" else 1)
    if a.action in ("esp-get", "esp-put"):
        if not a.image:
            sys.exit(f"{a.action} needs a FILE")
        sys.exit(esp(a, key))
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
    if a.action in ("module-remove", "wasm-remove", "module-switch"):
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
