import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("module_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("module_test.py", "wasm_test.py")).read()
_w = src2.index("W = f")
exec(src2[_w:src2.index('check("boot"', _w)])   # upd(), line(), wait_line(), http_ok()
M = f"{ROOT}/build/modules"
def reboot_wait(t=180):
    mark = len(log)
    end = time.time() + t
    while time.time() < end and b"rustros> " not in log[mark:]: pump(0.5)
    return clean(log[mark:])
def echo_ok(n=100000):
    s = socket.create_connection(("127.0.0.1", 17777), timeout=10)
    blob = os.urandom(n); s.sendall(blob); got = b""
    while len(got) < n: got += s.recv(65536)
    s.close(); return got == blob

check("boot", wait_for("rustros> ", 120))
check("install wasm runtime", upd("module-install", "wasm", f"{ROOT}/build/modules/wasm.mod") == "OK"); pump(2)
r = upd("module-install", "echo", f"{M}/echo.mod"); print(r); check("install native echo", r == "OK")
pump(1)
check("native echo tcp", echo_ok())
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3); u.sendto(b"udp-native", ("127.0.0.1", 17777))
check("native echo udp", u.recvfrom(100)[0] == b"udp-native")
check("add wasm form of echo", upd("module-install", "echo", f"{W}/echo_wasm.wasm") == "OK"); pump(1)
out = upd("info"); print([l for l in out.splitlines() if "echo" in l])
check("now running wasm", "echo: wasm running" in out and "native " in out and "wasm " in out)
check("wasm echo works", echo_ok())
check("switch to native", upd("module-switch", "echo", "native") == "OK"); pump(1)
check("native again", "echo: native running" in upd("info") and echo_ok())
# crashy in both forms, native preferred
check("install crashy wasm", upd("module-install", "crashy", f"{W}/crashy_wasm.wasm") == "OK")
check("install crashy native", upd("module-install", "crashy", f"{M}/crashy.mod") == "OK"); pump(1)
out = wait_line(17001, "hello", "start #"); print(out); check("crashy native up", "start #" in out)
check("native has no probe", "no probe" in line(17001, "bad"))
# a native panic reboots the machine and falls back to wasm
con.sendall(b"")
try: line(17001, "panic", 3)
except Exception: pass
after = reboot_wait()
print([l for l in after.splitlines() if "crash" in l or l.startswith("modules:")])
check("panic attributed + switched off", "native crashy crashed the last boot" in after and "modules: crashy started (wasm" in after)
check("echo still native after reboot", "modules: echo started (native" in after and echo_ok())
out = wait_line(17001, "hello", "start #"); check("crashy runs as wasm", "start #" in out)
check("wasm probe works", "host said -21" in line(17001, "bad"))
out = run_cmd("mod", "rustros> "); print(out.strip())
check("list shows native off", "native switched off after a crash" in out)
check("switch crashy back to native", upd("module-switch", "crashy", "native") == "OK"); pump(1)
check("native crashy again", "no probe" in wait_line(17001, "bad", "probe"))
# a native endless loop: software watchdog, pinned on the module
pump(25)  # a stable boot first, or boot-loop protection steps in
t0 = time.time()
try: line(17001, "loop", 2)
except Exception: pass
after = reboot_wait(240)
print([l for l in after.splitlines() if "watchdog" in l or "crash" in l][:4], f"{time.time()-t0:.0f}s")
check("hang attributed + fallback", "stuck in native app crashy" in clean(log) and "modules: crashy started (wasm" in after)
# rejections
r = upd("module-install", "kern", f"{ROOT}/target/x86_64-unknown-none/release/rustros"); print(r)
check("reject non-module ELF", "ERR not a RustROS module" in r)
r = upd("module-install", "shell", f"{M}/echo.mod"); print(r); check("reject built-in name", "built-in" in r)
# removal
check("remove native crashy", upd("module-remove", "crashy", "native") == "OK"); pump(1)
check("crashy still up as wasm", "start #" in wait_line(17001, "hello", "start #"))
check("remove crashy", upd("module-remove", "crashy") == "OK"); pump(1)
out = run_cmd("modules", "rustros> "); check("crashy gone", "crashy" not in out and "echo" in out)
q.kill(); print("ALL OK")
