# User-mode processes (milestone M1): ring 3, one address space each, the
# Linux system-call module, demand paging and copy-on-write, and the data
# plane keeping priority over a process stuck in a loop.
import sys, time, socket, os
S = __file__.rsplit("/", 1)[0]
mode = sys.argv[1]; sys.argv = ["test.py"] + sys.argv[1:]
__file__ = f"{S}/test.py"
exec(open(f"{S}/test.py").read().split('check("boot"')[0])
src2 = open(f"{S}/wasm_test.py").read(); _w = src2.index("W = f"); exec(src2[_w:src2.index("def line", _w)])
U = f"{ROOT}/build/user"

def run(prog, *args):
    up = [sys.executable, f"{ROOT}/tools/rustros-update.py", "127.0.0.1", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "run", f"{U}/{prog}", *args]
    import subprocess
    return subprocess.run(up, capture_output=True, text=True, timeout=60).stdout.strip()

def wait_log(mark, token, t=30):
    end = time.time() + t
    while time.time() < end:
        if token.encode() in log[mark:]: return True
        pump(0.3)
    return False

def echo_mbit(n=8 << 20):
    """TCP echo throughput to RustROS's echo app, in Mbit/s (None if wrong)."""
    s = socket.create_connection(("127.0.0.1", 17777), timeout=30)
    blob = os.urandom(n); t0 = time.time(); s.sendall(blob); got = b""
    while len(got) < n:
        d = s.recv(1 << 20)
        if not d: break
        got += d
    s.close()
    return n * 8 / (time.time() - t0) / 1e6 if got == blob else None

def echo_ok(n=100000):
    s = socket.create_connection(("127.0.0.1", 17777), timeout=10)
    blob = os.urandom(n); s.sendall(blob); got = b""
    while len(got) < n:
        d = s.recv(65536)
        if not d: break
        got += d
    s.close(); return got == blob

check("boot", wait_for("rescue> ", 120))
# a process before the layer is installed: refused, machine fine
mark = len(log)
print(run("hello"))
check("no syscall layer yet", "no system call layer" in clean(log[mark:]))
M = f"{ROOT}/build/modules"
check("echo installed", upd("module-install", "echo", f"{M}/echo.mod") == "OK"); pump(1)
check("echo works", echo_ok())
check("linux module installed", upd("module-install", "linux", f"{ROOT}/build/modules/linux.mod") == "OK"); pump(1)

# hello: ring 3, args, uname
mark = len(log)
r = run("hello", "one", "two"); print(r)
wait_log(mark, '"two"]')
out = clean(log[mark:])
check("hello ran in ring 3", "hello from ring 3" in out and "Linux" in out)
check("args and pid", 'args ["one", "two"]' in out and "pid " in out)

# fork, wait, copy-on-write, mmap, brk
mark = len(log)
r = run("forktest"); print(r)
wait_log(mark, "none left", 40)
out = clean(log[mark:]); print(out)
check("fork + wait + COW", "copy-on-write" in out and "status 0x700" in out)
check("many children", "50 children done" in out and "none left: -10" in out)

# a bad pointer: the process dies, nothing else
mark = len(log)
r = run("badptr"); print(r)
wait_log(mark, "bad memory access", 15)
out = clean(log[mark:]); print(out)
check("bad pointer as a syscall arg → EFAULT", "bad pointer: -14" in out)
check("touching kernel memory kills only it", "bad memory access" in out and "still alive" not in out)
check("system still up after the fault", echo_ok())

# a process stuck in an endless loop must not stop forwarding or the shell;
# throughput is compared with the same measurement without it, in this run
# (other test VMs may share the host's CPUs)
base = max(echo_mbit() or 0, echo_mbit() or 0); print(f"tcp echo without spinner: {base:.0f} Mbit/s")
check("spin started", run("spin").startswith("OK")); pump(1)
check("spin is running", "spin" in upd("ps"))
check("data plane alive under the spinner", echo_ok(400000))
t0 = time.time(); out = run_cmd("mod", "rescue> "); dt = time.time() - t0
check("console responsive under the spinner", "linux" in out and dt < 10)
mbit = max(echo_mbit() or 0, echo_mbit() or 0); print(f"tcp echo under spinner: {mbit:.0f} Mbit/s ({mbit / base:.0%} of without)")
check("throughput under the spinner at least 80% of without", base > 0 and mbit >= 0.8 * base)

# kill it
pid = [l for l in upd("ps").splitlines() if l.strip().endswith("spin")][0].split()[0]
check("kill", upd("kill", pid) == "OK"); pump(1)
check("gone from ps", "spin" not in upd("ps"))
check("memory freed: another process runs", run("hello").startswith("OK"))

# the layer can be replaced while a process loops (hot update)
check("spin again", run("spin").startswith("OK")); pump(1)
mark = len(log)
check("reinstall linux while a process runs", upd("module-install", "linux", f"{ROOT}/build/modules/linux.mod") == "OK"); pump(1)
check("process survives the layer swap", "spin" in upd("ps") and echo_ok())
q.kill()
print("ALL OK")
