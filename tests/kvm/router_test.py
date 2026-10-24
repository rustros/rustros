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
               "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:9000", "-device", "virtio-net-pci,netdev=n0",
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
# A: LAN on nic1 untagged, VLAN 2240 on nic1, both via candidate + apply 0 + save
for t in ["cand ip nic1 192.168.50.1/24", "cand ip vlan add nic1 2240", "cand ip nic1.2240 198.51.100.254/24", "apply 0", "save"]:
    raw(a, t)
out = raw(a, "ip"); check("a: nic1 and nic1.2240 up", "nic1.2240 mac 52:54:00:aa:00:01  ip 198.51.100.254/24" in out and "ip 192.168.50.1/24" in out)
# B untagged on nic1, C on VLAN 2240; nic0 off so the only way is through A
b.cmd("ip none", "rustros> "); b.cmd("ip nic1 192.168.50.2/24 192.168.50.1", "rustros> ")
c.cmd("ip none", "rustros> "); c.cmd("ip vlan add nic1 2240", "rustros> "); c.cmd("ip nic1.2240 198.51.100.10/24 198.51.100.254", "rustros> ")
out = b.cmd("ping 198.51.100.10 1", "received", 15); check("no router module: no forwarding", "bytes from" not in out)
check("router installed", a.upd("module-install", "router", f"{ROOT}/build/modules/router.mod") == ["OK"]); a.pump(3)
out = b.cmd("ping 198.51.100.10 3", "received", 20); check("b -> c through the router (untagged -> VLAN 2240)", "bytes from 198.51.100.10" in out, out)
out = c.cmd("ping 192.168.50.2 2", "received", 20); check("c -> b back the other way", "bytes from 192.168.50.2" in out, out)
out = c.cmd("http 192.168.50.2 9000", "rustros> ", 20); check("TCP through the router", "RRS1" in out or "connected" in out or "HTTP" in out or "bytes" in out, out)
out = b.cmd("ping 198.51.100.254 1", "received", 15); check("b -> a's VLAN address (not forwarded, answered)", "bytes from 198.51.100.254" in out, out)
# static route: 10.99.0.0/16 lives behind b
b.cmd("ip nic1 add 10.99.1.1", "rustros> ")
out = raw(a, "ip route add 10.99.0.0/16 192.168.50.2"); check("route added", "route 10.99.0.0/16 via 192.168.50.2" in out, out)
out = c.cmd("ping 10.99.1.1 2", "received", 20); check("static route used", "bytes from 10.99.1.1" in out, out)
raw(a, "ip route del 10.99.0.0/16")
out = c.cmd("ping 10.99.1.1 1", "received", 15); check("route gone: network unreachable", "bytes from 10.99.1.1" not in out, out)
# NAT for the VLAN alongside: c reaches the outside through NAT, b still routed plainly
check("nat installed", a.upd("module-install", "nat", f"{ROOT}/build/modules/nat.mod") == ["OK"])
check("nat inside nic1.2240", "OK" in subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "module-config", "nat", "inside", "nic1.2240"], capture_output=True, text=True).stdout)
a.pump(3)
out = c.cmd("ping 10.0.2.2 3", "received", 20); check("c -> outside through NAT", "bytes from 10.0.2.2" in out, out)
out = b.cmd("ping 198.51.100.10 2", "received", 20); check("b -> c still routed", "bytes from 198.51.100.10" in out, out)
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
print([l for l in r.splitlines() if "router" in l or "nat:" in l])
check("router counts", "forwarded" in r)
# routes survive a reboot
raw(a, "ip route add 10.99.0.0/16 192.168.50.2"); raw(a, "save")
check("reboot", a.upd("reboot") == ["OK"]); mark = len(a.log)
check("a back", a.wait("rescue> ", 120, mark))
check("route restored", "net: route 10.99.0.0/16 via 192.168.50.2" in clean(a.log[mark:]))
a.pump(3)
out = c.cmd("ping 10.99.1.1 2", "received", 20); check("static route after reboot", "bytes from 10.99.1.1" in out, out)
for v in vms: v.q.kill()
print("ALL OK")
