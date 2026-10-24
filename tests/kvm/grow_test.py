# esp-grow: a 2 MiB image's EFI partition grows to 8 MiB (slots 1 MiB) online.
# First an interrupted grow (client killed mid-write): nothing may change.
import sys, time, subprocess, os, re
S = os.path.dirname(os.path.abspath(__file__))
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(f"{S}/test.py").read()
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
check("boot", wait_for("rescue> ", 120))
up = ["python3", f"{ROOT}/tools/rustros-update.py", "127.0.0.1"]
kf = ["--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
def u(*args, t=300):
    r = subprocess.run(up + list(args) + kf, capture_output=True, text=True, timeout=t)
    return r.returncode, r.stdout + r.stderr
rc, out = u("module-config", "keep", "x", "survives-grow"); check("kv value stored", rc == 0)
rc, before = u("info"); print([l for l in before.splitlines() if "slot" in l.lower()][:2])
def booted(m, t=150):
    """A new boot reached the prompt (only output after position `m` counts:
    take it before the command that reboots; the console is read all the time)."""
    end = time.time() + t
    while time.time() < end:
        pump(0.5)
        if b"RustROS 0.1" in log[m:] and b"rescue> " in log[log.rfind(b"RustROS 0.1"):]:
            return clean(log[m:])
    return None
# interrupted: kill the client while it writes the new partition
p = subprocess.Popen(["python3", "-u"] + up[1:] + ["esp-grow", "8"] + kf, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
seen = b""
while b"written" not in seen:
    c = p.stdout.read(1)
    if not c: break
    seen += c
time.sleep(1); p.kill(); print("killed while:", seen[-120:])
check("killed during the write", b"written" in seen)
m = len(log); rc, out = u("reboot")
b1 = booted(m)
check("boots after the interrupted grow", b1 is not None and "rustros.slots=2117,2629,512" in b1)
rc, out = u("esp-get", f"{S}/g-{mode}.bin")
check("still the 2 MiB partition at 576", rc == 0 and "from 576" in out and os.path.getsize(f"{S}/g-{mode}.bin") < 2 << 20)
# the real thing
m = len(log); rc, out = u("esp-grow", "8", "1024", t=900); print(out[-600:])
check("esp-grow", rc == 0 and "up again" in out)
b2 = booted(m)
check("rebooted into it", b2 is not None)
rc, out = u("esp-get", f"{S}/g-{mode}.bin"); print(out.strip())
check("8 MiB EFI partition at 4096", rc == 0 and "from 4096" in out and os.path.getsize(f"{S}/g-{mode}.bin") > 7 << 20)
rc, out = u("module-config", "keep"); check("kv survived", "survives-grow" in out)
m = re.findall(r"rustros\.slots=(\d+),(\d+),(\d+)", b2 or "")
print("cmdline slots:", m[-1:] if m else None)
check("the kernel runs with the new slots (1 MiB)", bool(m) and m[-1][2] == "2048")
r = subprocess.run(up + ["upload", f"{ROOT}/build/rustros.elf", "--wait"] + kf, capture_output=True, text=True, timeout=300)
check("update into the new slot + confirm", r.returncode == 0)
rc, out = u("status"); check("on slot b", "slot b" in out and "trial" not in out)
q.kill(); print("ALL OK")
