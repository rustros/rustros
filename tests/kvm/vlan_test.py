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

def net(v, *w):
    r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(v.port), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "net", *w], capture_output=True, text=True)
    return r.stdout
a = VM("a", 19201 + 10 * (mode == "uefi"), "52:54:00:aa:00:01"); vms.append(a)
b = VM("b", 19202 + 10 * (mode == "uefi"), "52:54:00:bb:00:01"); vms.append(b)
for v in vms:
    check(f"{v.name} boots", v.wait("rescue> ", 120))
check("b shell", b.upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod") == ["OK"] and b.wait("rustros> ", 20))
out = net(a, "ip", "vlan", "add", "nic1", "109"); check("remote: vlan nic1.109 created", "nic1.109 mac 52:54:00:aa:00:01  ip none" in out, out)
check("duplicate vlan refused", net(a, "ip", "vlan", "add", "nic1", "109").startswith("ERR"))
check("bad id refused", net(a, "ip", "vlan", "add", "nic1", "5000").startswith("ERR"))
out = net(a, "ip", "nic1.109", "192.168.109.1/24"); check("vlan address", "nic1.109 mac 52:54:00:aa:00:01  ip 192.168.109.1/24" in out, out)
out = net(a, "ip", "nic1.109", "add", "192.168.109.2-252"); check("251 extra addresses on the vlan", "extra (251) 192.168.109.2-192.168.109.252" in out, out)
net(a, "ip", "nic1", "192.168.50.1/24")
b.cmd("ip vlan add nic1 109", "rustros> ")
out = b.cmd("ip nic1.109 192.168.109.254/24", "rustros> "); check("b: vlan set", "nic1.109" in out and "192.168.109.254/24" in out, out)
b.cmd("ip nic1 192.168.50.2/24", "rustros> ")
for addr in ["1", "2", "100", "252"]:
    out = b.cmd(f"ping 192.168.109.{addr} 1", "received", 15)
    check(f"tagged: 192.168.109.{addr} answers", f"bytes from 192.168.109.{addr}" in out, out)
out = b.cmd("ping 192.168.50.1 1", "received", 15); check("untagged nic1 still works alongside", "bytes from 192.168.50.1" in out, out)
# isolation: B without the VLAN cannot reach A's VLAN addresses
b.cmd("ip vlan del nic1.109", "rustros> ")
b.cmd("ip nic1 192.168.109.200/24", "rustros> ")
out = b.cmd("ping 192.168.109.1 1", "received", 15); check("untagged cannot reach the VLAN", "bytes from" not in out, out)
check("remote save", "saved" in net(a, "save"))
check("remote reboot", a.upd("reboot") == ["OK"])
mark = len(a.log)
check("a back", a.wait("rescue> ", 120, mark))
after = clean(a.log[mark:])
check("vlan restored", "net: nic2 is VLAN 109 on nic1" in after and "net: nic2 251 extra addresses 192.168.109.2-192.168.109.252" in after, after)
b.cmd("ip vlan add nic1 109", "rustros> "); b.cmd("ip nic1.109 192.168.109.254/24", "rustros> ")
out = b.cmd("ping 192.168.109.200 2", "received"); check("range answers on the vlan after reboot", "bytes from 192.168.109.200" in out, out)
out = net(a, "ip", "vlan", "del", "nic1.109"); check("vlan removed", "nic1.109" not in out, out)
for v in vms: v.q.kill()
print("ALL OK")
