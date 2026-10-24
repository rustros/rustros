# slots-grow: the kernel slots of a 2 MiB image with 256 KiB slots (the
# deployed boxes' layout) grow inside the EFI partition as it is, to 448 KiB.
# A power cut after every single write: the tool runs with --stop-after 1,
# QEMU is killed (the writes it acknowledged are on the disk, as after a
# power cut), the machine must boot with storage and updates working, and
# the next run goes one write further, until it is done. Then kernels that
# need the bigger slots go into both slots, and a broken one rolls back.
# Each boot is left to become stable (rustros.stable=5 in this image) before
# the next cut, or the boot-loop protection would rightly roll back.
# BIOS starts on slot a; UEFI first updates once, so it starts on slot b.
import sys, time, subprocess, os, re, socket, threading
S = os.path.dirname(os.path.abspath(__file__))
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(f"{S}/test.py").read()
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
up = ["python3", f"{ROOT}/tools/rustros-update.py", "127.0.0.1"]
kf = ["--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
def u(*args, t=300):
    r = subprocess.run(up + list(args) + kf, capture_output=True, text=True, timeout=t)
    return r.returncode, r.stdout + r.stderr
def power_cut_and_boot():
    """Kill QEMU and start it again on the same disk (and UEFI variables)."""
    global q, con, log
    q.kill(); q.wait()
    if os.path.exists(sock): os.unlink(sock)
    q = subprocess.Popen(cmd); time.sleep(1)
    con = socket.socket(socket.AF_UNIX); con.connect(sock); con.settimeout(0.2)
    log = b""
    threading.Thread(target=_reader, daemon=True).start()
def slots_line():
    m = re.findall(r"rustros\.slots=(\d+),(\d+),(\d+)", clean(log))
    return m[-1] if m else None
def kernel(kib, broken=False):
    """build/rustros.elf padded to `kib` KiB (GRUB loads only its segments), or
    an ELF header with garbage behind it."""
    path = f"{S}/k{kib}{'-broken' if broken else ''}-{mode}.elf"
    body = open(f"{ROOT}/build/rustros.elf", "rb").read()
    if broken:
        body = body[:64] + os.urandom(len(body) - 64)
    open(path, "wb").write(body + bytes(kib * 1024 - len(body)))
    return path

check("boot", wait_for("rescue> ", 120))
check("256 KiB slots to begin with", slots_line() is not None and slots_line()[2] == "512")
rc, out = u("module-config", "keep", "x", "survives-slots-grow"); check("kv value stored", rc == 0)
if mode == "uefi":
    rc, out = u("upload", f"{ROOT}/build/rustros.elf", "--wait")
    rc2, st = u("status"); check("first on slot b", rc == 0 and "slot b" in st and "trial" not in st)
    wait_for("rescue> ", 60)
before = slots_line()
time.sleep(7)  # the boot so far becomes stable before the first cut
writes = 0
while True:
    rc, out = u("slots-grow", "--stop-after", "1", t=600)
    if rc not in (0, 3):
        print(out); check("slots-grow ran", False)
    if rc == 3:
        writes += 1
    else:
        time.sleep(8)  # done: it rebooted the machine itself; that boot becomes stable first
    power_cut_and_boot()
    ok = wait_for("rescue> ", 120)
    t0 = time.time()
    c = clean(log)
    rc_s, st = u("status")
    check(f"power cut after write {writes}: boots (first try), storage and updates on",
          ok and "rustros.boots=x " in c and "storage disabled" not in c and rc_s == 0 and "trial" not in st)
    time.sleep(max(0, 7 - (time.time() - t0)))  # stable: the boot count is cleared
    if rc == 0:
        break
print(f"{writes} writes, a power cut after each")
check("the slots grew in the running kernel's command line", slots_line() is not None and slots_line()[2] == "896")
check("slot A did not move", slots_line()[0] == before[0])
rc, out = u("esp-get", f"{S}/sg-{mode}.esp")
cfg = subprocess.run(["mtype", "-i", f"{S}/sg-{mode}.esp", "::/boot/grub/grub.cfg"], capture_output=True, text=True).stdout
entries = re.findall(r"rustros\.slots=(\d+),(\d+),(\d+)", cfg)
check("every grub.cfg entry (the fallback too) has the new slots", len(entries) == 2 and all(e == tuple(slots_line()) for e in entries))
rc, out = u("slots-grow"); print(out.strip().splitlines()[-1])
check("run again: nothing to do", rc == 0 and "nothing to do" in out)
rc, out = u("module-config", "keep"); check("kv survived", "survives-slots-grow" in out)
rc, st = u("status"); start = "a" if "slot a" in st else "b"
other = "b" if start == "a" else "a"
rc, out = u("upload", kernel(400), "--wait")
rc2, st = u("status"); check(f"a 400 KiB kernel into slot {other} + confirm", rc == 0 and f"slot {other}" in st and "trial" not in st)
wait_for("rescue> ", 60)
rc, out = u("upload", kernel(440), "--wait")
rc2, st = u("status"); check(f"a 440 KiB kernel into slot {start} + confirm", rc == 0 and f"slot {start}" in st and "trial" not in st)
wait_for("rescue> ", 60)
rc, out = u("upload", kernel(449), "--wait")
check("a kernel bigger than the slot is refused", rc != 0)
rc, out = u("upload", kernel(300, broken=True), "--wait"); print(out.strip().splitlines()[-1:])
rc2, st = u("status")
check("a broken kernel: back on the previous slot", rc != 0 and f"slot {start}" in st and "trial" not in st)
q.kill(); print("ALL OK")
