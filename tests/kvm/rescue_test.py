import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("rescue_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("rescue_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
M = f"{ROOT}/build/modules"
def send(b):
    con.sendall(b)
check("boot to rescue", wait_for("rescue> ", 120))
out = clean(log); check("console announced", "[console: rescue; Ctrl-] switches]" in out)
out = run_cmd("modules", "rescue> "); print(out.strip().splitlines()[-2:])
check("built in: rescue, dhcp, updater only", "rescue, dhcp, updater" in out)
out = run_cmd("ip", "rescue> "); check("rescue ip", "10.0.2.15/24" in out)
for name in ["shell", "echo", "httpd"]:
    r = upd("module-install", name, f"{M}/{name}.mod"); check(f"install {name}", r == "OK")
pump(2)
check("console moves to shell", wait_for("[console: shell]", 20) and wait_for("rustros> ", 10))
out = run_cmd("ping 10.0.2.2 2", "received"); check("shell ping (module)", "bytes from 10.0.2.2" in out)
check("httpd module", http_ok())
s = socket.create_connection(("127.0.0.1", 17777), timeout=5); s.sendall(b"mod-echo"); check("echo module", s.recv(100) == b"mod-echo"); s.close()
mark = len(log); send(b"\x1d")
check("Ctrl-] -> rescue", wait_for("[console: rescue", 10) and b"rescue> " in log[mark:] or wait_for("rescue> ", 5))
out = run_cmd("mod", "rescue> "); print(out.strip()); check("rescue lists modules", "shell" in out and "echo" in out and "httpd" in out)
mark = len(log); send(b"\x1d")
check("Ctrl-] -> shell again", wait_for("[console: shell]", 10))
send(b"\r"); pump(1)
out = run_cmd("uptime", "rustros> "); check("shell answers again", "up 0d" in out)
r = upd("module-remove", "shell"); check("remove shell", r == "OK")
check("console back to rescue", wait_for("rescue> ", 20))
r = upd("module-install", "shell", f"{M}/shell.mod"); check("reinstall shell", r == "OK")
mark = len(log); send(b"\x1d"); pump(1); send(b"\x1d")   # toggle twice: still shell
mark = len(log); con.sendall(b"reboot\r")
end = time.time() + 120
while time.time() < end and b"[console: shell]" not in log[mark:]: pump(0.5)
after = clean(log[mark:]); print([l for l in after.splitlines() if l.startswith(("modules:", "[console"))])
check("after reboot modules back, console to shell", "modules: shell started (native" in after and "[console: shell]" in after)
q.kill(); print("ALL OK")
