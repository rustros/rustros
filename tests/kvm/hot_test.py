# Hot replacement of the services (milestone H), on the default image (the
# boot image's services, the full-speed network stack carried on the disk):
#  - at boot the installed stack replaces the boot image's bootstrap one;
#  - replacing the stack while traffic runs: an HTTPS download (sites) and a
#    bulk TCP echo stream with full buffers finish intact, an idle
#    connection stays usable, UDP goes on;
#  - storage, the module manager and the virtio drivers replaced while the
#    system runs (a bulk stream across the NIC reset), and removed again
#    (the boot image's come back);
#  - removing the stack: the boot image's comes back at the next boot; an
#    installed one cannot take over from it while running (no state
#    handover) and does at the next boot.
import sys, time, socket, ssl, os, threading, hashlib
S = __file__.rsplit("/", 1)[0]
mode = sys.argv[1]; sys.argv = ["test.py"] + sys.argv[1:]
src = open(f"{S}/test.py").read().replace("hostfwd=tcp:127.0.0.1:17777-:7,", "hostfwd=tcp:127.0.0.1:17777-:7,hostfwd=tcp:127.0.0.1:18490-:443,")
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
src2 = open(f"{S}/wasm_test.py").read(); _w = src2.index("W = f"); exec(src2[_w:src2.index("def line", _w)])
M = f"{ROOT}/build/modules"
P = f"{S}/panelmock"

def http_ok():
    try: return "RustROS is running" in urllib.request.urlopen("http://127.0.0.1:18089/", timeout=5).read().decode()
    except Exception: return False

def since(mark):
    return clean(log[mark:])

def wait_since(mark, s, t=60):
    end = time.time() + t
    while time.time() < end:
        if s.encode() in log[mark:]: return True
        pump(0.3)
    return False

def echo_ok(n=100000):
    s = socket.create_connection(("127.0.0.1", 17777), timeout=10)
    blob = os.urandom(n); s.sendall(blob); got = b""
    while len(got) < n:
        d = s.recv(65536)
        if not d: break
        got += d
    s.close(); return got == blob

class Stream(threading.Thread):
    """A bulk echo stream: `total` bytes out, the same back, read slowly
    while `slow` is set (the buffers on both sides stay full)."""
    def __init__(self, total):
        super().__init__(daemon=True)
        self.total, self.slow, self.err = total, threading.Event(), None
        self.slow.set()
        self.sent, self.got = hashlib.sha256(), hashlib.sha256()
        self.n_got = 0
        self.s = socket.create_connection(("127.0.0.1", 17777), timeout=60)
    def run(self):
        try:
            w = threading.Thread(target=self.write, daemon=True); w.start()
            while self.n_got < self.total:
                d = self.s.recv(4096 if self.slow.is_set() else 1 << 20)
                if not d: raise IOError("closed after %d bytes" % self.n_got)
                self.got.update(d); self.n_got += len(d)
                if self.slow.is_set(): time.sleep(0.02)
            w.join()
        except Exception as e:
            self.err = e
    def write(self):
        left = self.total
        while left:
            b = os.urandom(min(left, 65536)); self.sent.update(b); self.s.sendall(b); left -= len(b)
    def ok(self):
        self.join(120)
        print(f"  stream: {self.n_got} of {self.total} bytes back, error {self.err}")
        return self.err is None and self.n_got == self.total and self.sent.digest() == self.got.digest()

check("boot", wait_for("rescue> ", 120))
out = clean(log)
print("\n".join(l for l in out.splitlines() if l.startswith(("services:", "modules:"))))
check("installed stack from the image's disk", "installed netstack from the boot image" in out)
check("it replaced the bootstrap stack at boot", "services: network stack replaced by netstack" in out)
check("info lists it", "netstack" in upd("info"))

# ---------------------------------------------------------------- the stack, with traffic
check("echo installed", upd("module-install", "echo", f"{M}/echo.mod") == "OK"); pump(1)
check("echo works", echo_ok())
check("ext4 driver installed", upd("module-install", "ext4", f"{M}/ext4.mod") == "OK")
check("files partition mounted", wait_for("journaled", 30))
check("sites installed", upd("module-install", "sites", f"{M}/sites.mod") == "OK")
cfg = lambda k, v: upd("module-config", "sites", k, v)
one = lambda f: open(f"{P}/{f}").read().replace("\n", " ")
TOKEN = "tok-0123456789abcdef"
cfg("site.main.hosts", "site.test"); cfg("site.main.cert", one("site.pem")); cfg("site.main.key", one("site.key")); cfg("token", TOKEN)
time.sleep(3)
ctx = ssl.create_default_context(cafile=f"{P}/ca.pem")
def https(method, path, body=b"", headers=None, t=60):
    s = socket.create_connection(("127.0.0.1", 18490), timeout=t)
    s = ctx.wrap_socket(s, server_hostname="site.test")
    h = {"Host": "site.test", "Content-Length": str(len(body)), "Connection": "close"}; h.update(headers or {})
    s.sendall((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body)
    return s
BIG = os.urandom(12 << 20)
s = https("PUT", "/_sites/files/main/big.bin", BIG, {"Authorization": "Bearer " + TOKEN}, t=400)
r = b""
while True:
    d = s.recv(65536)
    if not d: break
    r += d
check("12 MB file uploaded", r.startswith(b"HTTP/1.1 201"))

class Download(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.slow, self.err, self.body = threading.Event(), None, b""
        self.slow.set()
        self.s = https("GET", "/big.bin")
    def run(self):
        try:
            d = b""
            while True:
                c = self.s.recv(16384 if self.slow.is_set() else 1 << 20)
                if not c: break
                d += c
                if self.slow.is_set(): time.sleep(0.02)
            self.body = d
        except Exception as e:
            self.err = e
    def ok(self):
        self.join(180)
        head, _, b = self.body.partition(b"\r\n\r\n")
        print(f"  download: {len(b)} bytes, error {self.err}")
        return self.err is None and head.startswith(b"HTTP/1.1 200") and b == BIG

idle = socket.create_connection(("127.0.0.1", 17777), timeout=10)
idle.sendall(b"before"); check("idle connection echoes", idle.recv(100) == b"before")
dl = Download(); dl.start()
st = Stream(16 << 20); st.start()
time.sleep(3)
check("download under way", 0 < len(dl.body) or dl.is_alive())
mark = len(log)
check("stack replaced while running (module-install)", upd("module-install", "netstack", f"{M}/netstack.mod") == "OK")
check("handover logged", wait_since(mark, "services: network stack replaced by netstack", 20))
print("\n".join(l for l in since(mark).splitlines() if "services:" in l or "modules:" in l))
time.sleep(2)
dl.slow.clear(); st.slow.clear()
check("HTTPS download finished intact across the replacement", dl.ok())
check("bulk echo stream intact across the replacement", st.ok())
idle.sendall(b"after"); check("idle connection still echoes", idle.recv(100) == b"after")
idle.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3); u.sendto(b"udp-after", ("127.0.0.1", 17777))
check("udp echo after", u.recvfrom(100)[0] == b"udp-after")
check("no resets in the log", "reset" not in since(mark).lower())
out = [l for l in upd("info").splitlines() if "netstack" in l]; print(out)
check("info lists the stack as a running service", any("service" in l for l in out))

# ---------------------------------------------------------------- storage
out = run_cmd("log", "rescue> "); print(out.strip()[-300:])
mark = len(log)
check("storage replaced", upd("module-install", "storage", f"{M}/storage.mod") == "OK")
check("storage handover logged", wait_since(mark, "services: storage replaced by storage", 20))
check("no second boot log", "log: this is boot" not in since(mark))
check("the store works after (a module installed)", upd("module-install", "httpd", f"{M}/httpd.mod") == "OK"); pump(1)
cfg("hot", "after-storage"); check("a setting written and read back", "after-storage" in upd("module-config", "sites"))
r = upd("status"); print(r); check("slots readable", "slot a" in r)
out2 = run_cmd("log", "rescue> "); print(out2.strip()[-300:])
check("this boot's log goes on", out2.strip()[-300:] != out.strip()[-300:])

# ---------------------------------------------------------------- the module manager
mark = len(log)
check("module manager replaced", upd("module-install", "modman", f"{M}/modman.mod") == "OK")
check("manager handover logged", wait_since(mark, "services: module manager replaced by modman", 20))
check("installing after it works", upd("module-install", "echo", f"{M}/echo.mod") == "OK"); pump(1)
check("echo again", echo_ok())

# ---------------------------------------------------------------- the drivers, with traffic
st = Stream(8 << 20); st.slow.clear(); st.start()
time.sleep(0.5)
mark = len(log)
check("drivers replaced", upd("module-install", "virtio", f"{M}/virtio.mod") == "OK")
check("both drivers replaced", wait_since(mark, "services: driver replaced by virtio", 20))
time.sleep(1)
print("\n".join(l for l in since(mark).splitlines() if l.strip()))
check("bulk stream intact across the NIC reset", st.ok())
check("the disk works after (a module installed)", upd("module-install", "echo", f"{M}/echo.mod") == "OK"); pump(1)
check("echo after the drivers", echo_ok())

# ---------------------------------------------------------------- back to the boot image's
for name, what in (("virtio", "driver"), ("modman", "module manager"), ("storage", "storage")):
    mark = len(log)
    check(f"{name} removed", upd("module-remove", name) == "OK")
    check(f"boot image's {what} back", wait_since(mark, f"services: {what} replaced by boot", 20))
    check(f"works after removing {name}", echo_ok() and upd("module-install", "httpd", f"{M}/httpd.mod") == "OK")
mark = len(log)
check("netstack removed", upd("module-remove", "netstack") == "OK")
check("the boot image's stack comes back at the next boot", wait_since(mark, "comes back at the next boot", 20))
check("echo still on the installed stack", echo_ok())
mark = len(log)
upd("reboot")
check("rebooted", wait_since(mark, "rescue> ", 120))
pump(3)
check("bootstrap stack now (nothing replaced it)", "network stack replaced" not in since(mark))
check("echo on the bootstrap stack", echo_ok())
mark = len(log)
check("netstack installed again", upd("module-install", "netstack", f"{M}/netstack.mod") == "OK")
check("refused while running (the bootstrap has no handover)", wait_since(mark, "it takes over at the next boot", 20))
check("still works", echo_ok())
mark = len(log)
upd("reboot")
check("rebooted", wait_since(mark, "rescue> ", 120))
check("the installed stack took over at boot", "services: network stack replaced by netstack" in since(mark))
check("echo on it", echo_ok())
q.kill()
print("ALL OK")
