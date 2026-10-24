import sys, time, socket, subprocess
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(__file__.replace("perf_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("perf_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
check("boot", wait_for("rescue> ", 120))
print([l for l in clean(log).splitlines() if l.startswith(("net:", "cpu"))])
_r = upd("module-install", "echo", f"{ROOT}/build/modules/echo.mod"); print("install:", _r); check("echo", _r == "OK"); pump(2)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1); u.connect(("127.0.0.1", 17777))
n = 0; t = time.time()
while time.time() - t < 3:
    u.send(b"y" * 64)
    try: u.recv(100); n += 1
    except socket.timeout: pass
print(f"udp ping-pong: {n/3:.0f}/s ({3e6/max(n,1):.0f} us)")
s = socket.create_connection(("127.0.0.1", 17777)); got = 0; t = time.time(); buf = b"x" * 65536
import threading
def rd():
    global got
    while True:
        d = s.recv(1 << 20)
        if not d: break
        got += len(d)
threading.Thread(target=rd, daemon=True).start(); sent = 0
while time.time() - t < 5:
    s.sendall(buf); sent += len(buf)
    while sent - got > 2 << 20 and time.time() - t < 8: time.sleep(0.001)
print(f"tcp echo: {got*8/(time.time()-t)/1e6:.1f} Mbit/s")
import subprocess
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
print("\n".join(l for l in r.splitlines() if l.startswith(("perf", "        "))))
check("perf shown with a peak", "perf     cpu0" in r and "peak rx" in r and "Mbps" in r)
pump(1); print([l for l in clean(log).splitlines() if l.startswith("perf:")][-1:])
q.kill(); print("ALL OK")
