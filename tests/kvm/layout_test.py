# The 8 MiB image: boots, online update into the 1 MiB slots, rollback, esp-get.
import sys, time, subprocess, os
S = os.path.dirname(os.path.abspath(__file__))
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(f"{S}/test.py").read()
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
check("boot", wait_for("rescue> ", 120))
up = ["python3", f"{ROOT}/tools/rustros-update.py", "127.0.0.1"]
kf = ["--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
r = subprocess.run(up + ["upload", f"{ROOT}/build/rustros.elf", "--wait"] + kf, capture_output=True, text=True, timeout=300)
print(r.stdout[-300:], r.stderr[-300:])
check("upload + trial boot + confirm", r.returncode == 0)
r = subprocess.run(up + ["status"] + kf, capture_output=True, text=True, timeout=60)
check("now on slot b", "slot b" in r.stdout and "trial" not in r.stdout)
r = subprocess.run(up + ["upload", f"{ROOT}/build/rustros.elf"] + kf, capture_output=True, text=True, timeout=300)
check("second upload (not confirmed)", r.returncode == 0)
def status_until(want, t=120):
    end = time.time() + t
    while time.time() < end:
        r = subprocess.run(up + ["status"] + kf, capture_output=True, text=True, timeout=60)
        if want(r.stdout):
            return r
        time.sleep(3)
    return r
r = status_until(lambda o: "slot a" in o and "trial" in o); print(r.stdout)
check("trial of slot a", "slot a" in r.stdout and "trial" in r.stdout)
subprocess.run(up + ["reboot"] + kf, capture_output=True, text=True, timeout=60)
time.sleep(5)
r = status_until(lambda o: "slot b" in o and "trial" not in o); print(r.stdout)
check("rolled back to slot b", "slot b" in r.stdout and "trial" not in r.stdout)
# past the stable-boot mark (it rewrites grubenv, inside the ESP), so the ESP
# stays the same between esp-get and esp-put
pump(22)
r = subprocess.run(up + ["esp-get", f"{S}/esp-{mode}.bin"] + kf, capture_output=True, text=True, timeout=120); print(r.stdout.strip())
check("esp-get: the whole ESP", r.returncode == 0 and 1 << 20 < os.path.getsize(f"{S}/esp-{mode}.bin") <= 64 << 20)
r = subprocess.run(up + ["esp-put", f"{S}/esp-{mode}.bin"] + kf, capture_output=True, text=True, timeout=120); print(r.stdout.strip())
check("esp-put of the same: nothing to write", r.returncode == 0 and r.stdout.startswith("0 sectors"))
q.kill(); print("ALL OK")
