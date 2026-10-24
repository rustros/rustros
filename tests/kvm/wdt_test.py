import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("wdt_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
def reboot_wait(t=180):
    global log
    mark = len(log)
    end = time.time() + t
    while time.time() < end and b"rustros> " not in log[mark:]: pump(0.5)
    return clean(log[mark:])
up = [sys.executable, f"{ROOT}/tools/rustros-update.py", "127.0.0.1", "--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
check("boot", wait_for("rustros> ", 120))
out = clean(log); print([l for l in out.splitlines() if l.startswith("watchdog")])
check("hw watchdog armed", "i6300esb armed" in out)
t0 = time.time(); mark = len(log); pump(70)
check("no false reset in 70 s", b"GNU GRUB" not in log[mark:] and b"SeaBIOS" not in log[mark:])
# 1. panic
mark = len(log); con.sendall(b"crash panic\r")
after = reboot_wait()
print([l for l in after.splitlines() if "panic" in l or "crash" in l or "rebooting" in l][:6])
check("panic recorded + reboot", "crash recorded" in after and "disk: last crash: up" in after and "test panic requested" in after)
r = subprocess.run(up[:3] + ["info"] + up[3:], capture_output=True, text=True); print(r.stdout.strip())
check("info shows crash", r.returncode == 0 and "test panic requested" in r.stdout)
out = run_cmd("crash clear", "rustros> "); check("clear", "cleared" in out)
pump(25)  # a stable boot first, or boot-loop protection steps in
# 2. software watchdog
t0 = time.time(); con.sendall(b"crash hang\r")
after = reboot_wait()
print([l for l in after.splitlines() if "watchdog" in l], f"{time.time()-t0:.0f}s")
check("software watchdog", "main loop stuck" in after and "rustros> " in after)
pump(25)  # a stable boot first, or boot-loop protection steps in
# 3. hardware watchdog
t0 = time.time(); con.sendall(b"crash freeze\r")
after = reboot_wait(240)
dt = time.time() - t0
print(f"hw reset after {dt:.0f}s")
check("hardware watchdog", "freezing" in after and "RustROS 0.1.0" in after and 50 < dt < 150)
pump(25)  # a stable boot first, or boot-loop protection steps in
# 4. a trial kernel that panics rolls back
r = subprocess.run(up[:3] + ["upload", f"{ROOT}/build/rustros.elf"] + up[3:], capture_output=True, text=True, timeout=300)
check("upload", r.returncode == 0)
after = reboot_wait()
check("trial boot", "(trial boot)" in after)
con.sendall(b"crash panic\r")
after = reboot_wait()
out = run_cmd("slot", "rustros> "); print(out.strip())
check("trial panic rolled back", "running slot a" in out and "trial" not in out)
q.kill(); print("ALL OK")
