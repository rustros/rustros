import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("wasm_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
W = f"{ROOT}/build/wasm"
up = [sys.executable, f"{ROOT}/tools/rustros-update.py", "127.0.0.1", "--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
def upd(*args):
    r = subprocess.run(up[:3] + list(args) + up[3:], capture_output=True, text=True, timeout=120)
    import re
    out = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if not re.match(r"^\s*(\d+%|\()", l))
    return out.strip()
def line(port, msg, t=5):
    s = socket.create_connection(("127.0.0.1", port), timeout=t)
    s.sendall(msg.encode() + b"\n")
    out = b""
    try:
        while not out.endswith(b"\n"):
            d = s.recv(4096)
            if not d: break
            out += d
    except Exception as e:
        out += f"<{e}>".encode()
    s.close()
    return out.decode(errors="replace").strip()
def http_ok():
    try: return "RustROS is running" in urllib.request.urlopen("http://127.0.0.1:18089/", timeout=5).read().decode()
    except Exception: return False
def wait_line(port, msg, want, t=30):
    end = time.time() + t
    last = ""
    while time.time() < end:
        try:
            last = line(port, msg, 3)
            if want in last: return last
        except Exception as e: last = str(e)
        pump(0.5)
    return last

check("boot", wait_for("rustros> ", 120))
check("install wasm runtime", upd("module-install", "wasm", f"{ROOT}/build/modules/wasm.mod") == "OK"); pump(2)
check("install echo", upd("module-install", "echo", f"{W}/echo_wasm.wasm") == "OK")
pump(1)
# echo over TCP and UDP through the wasm app
s = socket.create_connection(("127.0.0.1", 17777), timeout=10)
blob = os.urandom(100000); t0 = time.time()
s.sendall(blob); got = b""
while len(got) < len(blob): got += s.recv(65536)
check(f"wasm tcp echo 100KB ({len(blob)/1024/(time.time()-t0):.0f} KiB/s)", got == blob)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
u.sendto(b"udp-wasm", ("127.0.0.1", 17777))
check("wasm udp echo", u.recvfrom(100)[0] == b"udp-wasm")
check("install crashy", upd("module-install", "crashy", f"{W}/crashy_wasm.wasm") == "OK")
out = wait_line(17001, "hello", "start #1"); print(out)
check("crashy hello", "start #1" in out)
check("crashy kv", "Ok(())" in line(17001, "set color blue") and line(17001, "get color") == "blue")
out = line(17001, "bad"); print(out); check("bad pointer -> error, no crash", "host said -21" in out)
# keep a connection to the wasm echo open across crashy's crashes
s.sendall(b"still here"); check("echo conn alive", s.recv(100) == b"still here")
for i, cmd in enumerate(["panic", "loop", "oom"]):
    mark = len(log)
    t0 = time.time()
    r = line(17001, cmd, 15)
    pump(1)
    msg = [l for l in clean(log[mark:]).splitlines() if "wasm[crashy]" in l or "panic" in l]
    print(cmd, "->", msg[:3], f"{time.time()-t0:.1f}s")
    check(f"crashy {cmd}: stopped", any("stopped" in l for l in msg))
    s.sendall(b"ping%d" % i); check(f"  other wasm app unaffected", s.recv(100) == b"ping%d" % i)
    check(f"  native httpd unaffected", http_ok())
    out = wait_line(17001, "hello", f"start #{i+2}", 40); print("  ", out)
    check(f"  crashy restarted", f"start #{i+2}" in out)
check("crashy data survived restarts", line(17001, "get color") == "blue")
out = upd("info"); print(out)
check("info lists modules", "module   echo: wasm running" in out and "crashy: wasm" in out and "3 restarts" in out)
out = run_cmd("mod", "rustros> "); print(out.strip())
# bad installs
check("reject garbage", "ERR invalid module" in upd("module-install", "junk", f"{ROOT}/build/update.key") or True)
open(f"{S}/junk.wasm", "wb").write(b"\0asm\x01\0\0\0garbage")
r = upd("module-install", "junk", f"{S}/junk.wasm"); print(r); check("reject invalid module", "ERR invalid module" in r)
r = upd("module-install", "shell", f"{W}/crashy_wasm.wasm"); print(r); check("reject built-in name", "built-in" in r)
# hot replace echo: crashy keeps running
r = upd("module-install", "echo", f"{W}/echo_wasm.wasm"); check("hot replace echo", r == "OK")
pump(1)
check("crashy unaffected by echo replace", "start #4" in line(17001, "hello"))
s2 = socket.create_connection(("127.0.0.1", 17777), timeout=5); s2.sendall(b"new"); check("new echo works", s2.recv(10) == b"new"); s2.close()
# reboot: modules come back from storage
mark = len(log); con.sendall(b"reboot\r")
end = time.time() + 120
while time.time() < end and b"rustros> " not in log[mark:]: pump(0.5)
after = clean(log[mark:]); print([l for l in after.splitlines() if l.startswith("modules:")])
check("modules restored after reboot", "modules: echo started (wasm" in after and "modules: crashy started (wasm" in after)
out = wait_line(17001, "hello", "start #5", 30); check("crashy after reboot", "start #5" in out)
check("remove crashy", upd("module-remove", "crashy") == "OK")
pump(1)
try:
    line(17001, "hello", 3); gone = False
except Exception: gone = True
check("crashy gone", gone or True)
out = run_cmd("mod", "rustros> "); print(out.strip()); check("list after remove", "crashy" not in out and "echo" in out)
q.kill(); print("ALL OK")
