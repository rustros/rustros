import os, re, socket, subprocess, sys, time
S = os.path.dirname(os.path.abspath(__file__)); ROOT = os.environ.get("ROOT", "/root/github.com/firadio/ros")
mode = sys.argv[1]
def clean(b): return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", b.decode(errors="replace"))
class VM:
    def __init__(self, name, upd_port, mac):
        self.name, self.port = name, upd_port
        self.img = f"{S}/mn-{name}-{mode}.img"
        subprocess.run(["cp", f"{ROOT}/build/rustros.img", self.img], check=True)
        subprocess.run(["truncate", "-s", "1200M", self.img], check=True)
        self.ser = f"{S}/mn-{name}.ser"; self.mac = mac; self.log = b""
        if mode == "uefi":
            subprocess.run(["cp", "/usr/share/OVMF/OVMF_VARS_4M.fd", f"{S}/mn-{name}-vars.fd"], check=True)
        self.boot()
    def boot(self):
        if os.path.exists(self.ser): os.unlink(self.ser)
        cmd = ["qemu-system-x86_64", "-accel", "kvm", "-m", "256", "-display", "none", "-monitor", "none",
               "-chardev", f"socket,id=s0,path={self.ser},server=on,wait=off", "-serial", "chardev:s0",
               "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:9000" + (f",hostfwd=tcp:127.0.0.1:{self.port + 100}-10.0.2.100:9000,hostfwd=tcp:127.0.0.1:{self.port + 200}-:28820" if self.name == "a" else ""), "-device", "virtio-net-pci,netdev=n0",
               "-netdev", "socket,id=n1,mcast=230.0.0.1:%d" % (23400 + (mode == "uefi")), "-device", f"virtio-net-pci,netdev=n1,mac={self.mac}",
               "-drive", f"file={self.img},format=raw,if=virtio"]
        if mode == "uefi":
            cmd += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={S}/mn-{self.name}-vars.fd"]
        self.q = subprocess.Popen(cmd); time.sleep(1)
        self.c = socket.socket(socket.AF_UNIX); self.c.connect(self.ser); self.c.settimeout(0.2)
    def pump(self, t):
        end = time.time() + t
        while time.time() < end:
            try:
                d = self.c.recv(65536)
                if d: self.log += d
            except (socket.timeout, OSError): pass
    def wait(self, s, t=60, since=0):
        end = time.time() + t
        while time.time() < end:
            if s.encode() in self.log[since:]: return True
            self.pump(0.3)
        return False
    def cmd(self, c, until, t=20):
        mark = len(self.log); self.c.sendall(c.encode() + b"\r"); self.wait(until, t, mark)
        return clean(self.log[mark:])
    def upd(self, *a):
        return subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(self.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", *a], capture_output=True, text=True).stdout.strip().splitlines()[-1:]
vms = []
def check(n, ok, out=""):
    print(("PASS " if ok else "FAIL ") + n, flush=True)
    if not ok:
        print(out[-2500:])
        for v in vms: v.q.kill()
        sys.exit(1)
import importlib.util
spec = importlib.util.spec_from_file_location("hu", f"{ROOT}/tools/rustros-update.py"); hu = importlib.util.module_from_spec(spec); spec.loader.exec_module(hu)
KEY = open(f"{ROOT}/build/update.key").read().strip().encode()
def raw(v, text): return hu.command("127.0.0.1", v.port, KEY, b"N", text.encode())[0]
off = 10 * (mode == "uefi")
a = VM("a", 19201 + off, "52:54:00:aa:00:01"); vms.append(a)
b = VM("b", 19202 + off, "52:54:00:bb:00:01"); vms.append(b)
c = VM("c", 19203 + off, "52:54:00:cc:00:01"); vms.append(c)
for v in vms:
    check(f"{v.name} boots", v.wait("rescue> ", 120))
for v in (b, c):
    check(f"{v.name} shell", v.upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod") == ["OK"] and v.wait("rustros> ", 20))
def cfg(*kv):
    return subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "module-config", "nat", *kv], capture_output=True, text=True).stdout
def banner(port, t=5):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=t); s.settimeout(t)
        d = s.recv(64); s.close(); return d
    except OSError as e:
        return repr(e).encode()
# A: WAN 2 = nic0 (slirp, 10.0.2.15 gw 10.0.2.2, plus 10.0.2.100 for the published host);
# WAN 1 = nic1 192.168.50.1/24 towards b, the main default route via b;
# LAN = VLAN 2240, c = 198.51.100.1
for t in ["cand ip nic0 add 10.0.2.100", "cand ip nic1 192.168.50.1/24", "cand ip vlan add nic1 2240", "cand ip nic1.2240 198.51.100.254/24",
          "cand ip route add 0.0.0.0/0 192.168.50.2", "apply 0"]:
    raw(a, t)
out = raw(a, "ip"); print(out)
check("main default via WAN 1", "route 0.0.0.0/0 via 192.168.50.2" in out, out)
check("a still managed over WAN 2 (replies leave by their own WAN)", a.upd("status") != [] and "running slot" in " ".join(a.upd("status")))
b.cmd("ip none", "rustros> "); b.cmd("ip nic1 192.168.50.2/24", "rustros> ")
b.cmd("ip route add 203.0.113.240/32 192.168.50.1", "rustros> ")
c.cmd("ip none", "rustros> "); c.cmd("ip vlan add nic1 2240", "rustros> "); c.cmd("ip nic1.2240 198.51.100.1/24 198.51.100.254", "rustros> ")
for m in ("router", "nat"):
    check(f"{m} installed", a.upd("module-install", m, f"{ROOT}/build/modules/{m}.mod") == ["OK"])
a.pump(3)
check("nothing published yet", b"RRS1" not in banner(a.port + 100, 3))
# c is published on both WANs, and goes out as WAN 2's 10.0.2.100
check("srcnat", "OK" in cfg("srcnat.198.51.100.1", "10.0.2.100"))
check("dstnat WAN 1", "OK" in cfg("dstnat.203.0.113.240", "198.51.100.1"))
check("dstnat WAN 2", "OK" in cfg("dstnat.10.0.2.100", "198.51.100.1"))
check("rules reported", a.wait("nat: dstnat 203.0.113.240 -> 198.51.100.1", 10))
a.pump(2)
d = banner(a.port + 100); print(d)
check("WAN 2 -> 10.0.2.100:9000 reaches c, answered back out of WAN 2", d.startswith(b"RRS1"), clean(a.log)[-2000:])
out = b.cmd("ping 203.0.113.240 3", "received", 20); check("WAN 1 -> 203.0.113.240 reaches c, answered from it", "bytes from 203.0.113.240" in out, out)
out = b.cmd("http 203.0.113.240 9000", "rustros> ", 20); check("TCP over WAN 1 to c", "RRS1" in out or "connected" in out or "bytes" in out, out)
b.cmd("ip route add 198.51.100.0/24 192.168.50.1", "rustros> ")
out = b.cmd("ping 198.51.100.1 3", "received", 20); print(out.strip()[-200:])
check("b pings c at its own address: answered from it (srcnat leaves replies alone)", "bytes from 198.51.100.1" in out, out)
out = c.cmd("ping 10.0.2.2 3", "received", 20); check("c -> outside as 10.0.2.100, out of WAN 2 (not the main default)", "bytes from 10.0.2.2" in out, out)
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
print([l for l in r.splitlines() if "nat:" in l or "router:" in l])
check("status counts", "static 1 srcnat 2 dstnat" in r and "connections" in r)
# a source route sends c's plain (un-NATed) traffic out of a chosen WAN
cfg("srcnat.198.51.100.1", "-"); a.pump(3)
out = raw(a, "ip route add 0.0.0.0/0 10.0.2.2 from 198.51.100.1"); check("source route added", "from 198.51.100.1/32" in out, out)
out = raw(a, "ip"); print([l for l in out.splitlines() if "route" in l])
cfg("dstnat.203.0.113.240", "-"); cfg("dstnat.10.0.2.100", "-"); a.pump(4)
check("rules removed: no longer published", b"RRS1" not in banner(a.port + 100, 3))
# a port forward on A's own WAN 2 address: only TCP 28820, to c's port 9000
check("port forward", "OK" in cfg("dstnat.tcp.10.0.2.15:28820", "198.51.100.1:9000"))
check("forward reported", a.wait("nat: forward tcp 10.0.2.15:28820 -> 198.51.100.1:9000", 10))
d = banner(a.port + 200); print(d)
check("10.0.2.15:28820 reaches c's 9000", d.startswith(b"RRS1"))
check("A's own 9000 on that address untouched", "running slot" in " ".join(a.upd("status")))
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
print([l for l in r.splitlines() if "nat:" in l])
for _ in range(5):
    if "1 forwards" in r: break
    time.sleep(1); r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
check("forward counted", "1 forwards" in r)
# a connection in progress keeps its translation when the rules change
# (RustROS nat until 2026.10.24: any rule change dropped every tracked
# connection): hold one through the forward, remove the forward, then finish
# an info request on it
import struct, hmac, hashlib
held, nonce, _, _ = hu.hello("127.0.0.1", a.port + 200)
cfg("dstnat.tcp.10.0.2.15:28820", "-"); a.pump(4)
check("forward removed: new connections are not forwarded", b"RRS1" not in banner(a.port + 200, 3))
head = b"I" + struct.pack(">I", 0)
held.sendall(head + hmac.new(KEY, nonce + b"H" + head, hashlib.sha256).digest() + hmac.new(KEY, nonce + head, hashlib.sha256).digest())
held.settimeout(15); reply = b""
try:
    while True:
        chunk = held.recv(4096)
        if not chunk: break
        reply += chunk
except OSError as e:
    reply += repr(e).encode()
held.close()
print(reply[:120])
check("the connection made before the removal still works both ways", b"slot" in reply, reply.decode(errors="replace"))
raw(a, "save")
check("reboot", a.upd("reboot") == ["OK"]); mark = len(a.log)
check("a back", a.wait("rescue> ", 120, mark))
boot = clean(a.log[mark:]); print([l for l in boot.splitlines() if "route" in l])
check("source route restored", "net: route 0.0.0.0/0 via 10.0.2.2 from 198.51.100.1/32" in boot)
check("managed over WAN 2 after reboot", "running slot" in " ".join(a.upd("status")))
for v in vms: v.q.kill()
print("ALL OK")
