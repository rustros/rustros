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
import importlib.util
spec = importlib.util.spec_from_file_location("hu", f"{ROOT}/tools/rustros-update.py"); hu = importlib.util.module_from_spec(spec); spec.loader.exec_module(hu)
KEY = open(f"{ROOT}/build/update.key").read().strip().encode()
def raw(v, text):
    try: return hu.command("127.0.0.1", v.port, KEY, b"N", text.encode())[0]
    except OSError as e: return f"unreachable {e}"
a = VM("a", 19201 + 10 * (mode == "uefi"), "52:54:00:aa:00:01"); vms.append(a)
b = VM("b", 19202 + 10 * (mode == "uefi"), "52:54:00:bb:00:01"); vms.append(b)
for v in vms:
    check(f"{v.name} boots", v.wait("rescue> ", 120))
check("b shell", b.upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod") == ["OK"] and b.wait("rustros> ", 20))
b.cmd("ip vlan add nic1 109", "rustros> "); b.cmd("ip nic1.109 192.168.109.254/24", "rustros> ")
def reach(addr="192.168.109.1"):
    return f"bytes from {addr}" in b.cmd(f"ping {addr} 1", "received", 15)
# candidate
raw(a, "cand ip vlan add nic1 109"); raw(a, "cand ip nic1.109 192.168.109.1/24")
out = raw(a, "cand ip nic1.109 add 192.168.109.2-252")
check("cand: changes listed", "+ nic1.109 ip 192.168.109.1/24" in out and "+ nic1.109 extra (251)" in out)
check("cand: not in effect", "not in effect" in raw(a, "cand") and not reach())
check("nothing stored", "net_vlans" not in raw(a, "boot"))
# apply / revert back and forth, the candidate stays
out = raw(a, "apply 0"); check("apply (no timer)", "nic1.109 mac" in out and "NOT CONFIRMED" not in out)
check("applied: reachable", reach() and reach("192.168.109.200"))
check("cand says in effect", "in effect (revert" in raw(a, "cand"))
check("revert", "nic1.109" not in raw(a, "revert") and not reach())
check("candidate kept after revert", "not in effect" in raw(a, "cand"))
check("apply again", "nic1.109 mac" in raw(a, "apply 0") and reach())
check("revert again", "nic1.109" not in raw(a, "revert") and not reach())
# timeout reverts, candidate kept
out = raw(a, "apply 5"); check("apply 5 s", "NOT CONFIRMED" in out and reach())
mark = len(a.log)
check("reverted by itself", a.wait("previous configuration restored (the candidate is kept)", 30, mark) and not reach())
check("candidate kept after timeout", "not in effect" in raw(a, "cand"))
# lockout: drop the management address; it comes back by itself
raw(a, "cand ip none")
import threading
threading.Thread(target=lambda: raw(a, "apply 20"), daemon=True).start(); time.sleep(2)
def probe():
    try:
        s, *_ = hu.hello("127.0.0.1", a.port, timeout=2); s.close(); return True
    except OSError: return False
check("locked out after a bad apply", not probe())
mark = len(a.log)
check("management back after the timeout", a.wait("previous configuration restored", 40, mark) and probe() and "nic0 mac" in raw(a, "ip"))
raw(a, "cand ip 10.0.2.15/24 10.0.2.2")  # undo the bad edit in the candidate
# the client's iptables-apply flow: apply, new connection, keep
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(a.port), "--key-file", f"{ROOT}/build/update.key", "--yes", "127.0.0.1", "net", "apply", "10"], capture_output=True, text=True)
print(r.stdout.strip().splitlines()[-3:])
check("client apply: new connection works, kept", r.returncode == 0 and "confirmed" in r.stdout)
time.sleep(12)
check("kept past the timeout", reach())
check("save", "saved" in raw(a, "save") and "no candidate" in raw(a, "cand"))
check("stored", "net_vlans = 1.109" in raw(a, "boot"))
# discard after an apply reverts and drops the candidate
raw(a, "cand ip nic1.109 del 192.168.109.200"); raw(a, "apply 0")
check("applied the deletion", not reach("192.168.109.200"))
raw(a, "discard")
check("discard reverts and drops", reach("192.168.109.200") and "no candidate" in raw(a, "cand"))
# reboot: the saved configuration
check("remote reboot", a.upd("reboot") == ["OK"])
mark = len(a.log)
check("a back", a.wait("rescue> ", 120, mark) and reach("192.168.109.150"))
# console flow on b: apply asks first, then whether to keep
b.cmd("cand ip nic1 192.168.50.99/24", "rustros> ")
out = b.cmd("apply", "apply these changes? [y/N]"); check("console: changes shown, asks", "+ nic1 ip 192.168.50.99/24" in out)
out = b.cmd("y", "keep these changes? [y/N]"); check("console: applied, asks to keep", "keep these changes" in out)
out = b.cmd("y", "rustros> "); check("console: kept", "kept" in out)
check("console: in effect", "ip 192.168.50.99/24" in b.cmd("ip", "rustros> "))
b.cmd("cand ip nic1 192.168.50.98/24", "rustros> "); b.cmd("apply", "[y/N]"); b.cmd("y", "keep these")
out = b.cmd("n", "rustros> "); check("console: n reverts to before the round", "reverted" in out and "nic1 mac 52:54:00:bb:00:01  ip none" in b.cmd("ip", "rustros> "))
out = b.cmd("apply", "[y/N]"); out = b.cmd("n", "rustros> "); check("console: n before apply", "not applied" in out)
# the question comes back with the time left; no answer reverts and says so
b.cmd("cand ip nic1 192.168.50.97/24", "rustros> ")
b.cmd("apply 8", "[y/N]")
mark = len(b.log); b.c.sendall(b"y\r")
check("console: question repeated with time left", b.wait("s left)", 10, mark))
check("console: no answer reverts, said so", b.wait("no answer: the previous configuration is back", 15, mark) and b.wait("rustros> ", 5, mark))
check("console: reverted", "ip none" in b.cmd("ip", "rustros> ").split("nic1 mac")[1][:60])
for v in vms: v.q.kill()
print("ALL OK")
