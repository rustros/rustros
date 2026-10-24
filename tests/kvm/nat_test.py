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

import threading, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("hello from outside, you are " + self.client_address[0]).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
HP = 28123 + (mode == "uefi")
srv = http.server.HTTPServer(("127.0.0.1", HP), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
a = VM("a", 19201 + 10 * (mode == "uefi"), "52:54:00:aa:00:01"); vms.append(a)
b = VM("b", 19202 + 10 * (mode == "uefi"), "52:54:00:bb:00:01"); vms.append(b)
for v in vms:
    check(f"{v.name} boots", v.wait("rescue> ", 120))
    check(f"{v.name} shell", v.upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod") == ["OK"] and v.wait("rustros> ", 20))
check("a: nat installed", a.upd("module-install", "nat", f"{ROOT}/build/modules/nat.mod") == ["OK"])
check("nat idle until configured", a.wait("modules: nat started", 10))
a.cmd("ip nic1 192.168.50.1/24", "rustros> ")
out = a.cmd("cfg nat inside nic1", "rustros> "); check("cfg set", "ok" in out, out)
check("nat picks up the setting", a.wait("nat: inside nic1, egress 10.0.2.15", 10))
b.cmd("ip none", "rustros> ")
out = b.cmd("ip nic1 192.168.50.2/24 192.168.50.1", "rustros> ")
check("b: only reachable through a", "ip 192.168.50.2/24  gw 192.168.50.1" in out, out)
out = b.cmd("ping 192.168.50.1 1", "received"); check("b -> gateway itself (not NATed)", "bytes from 192.168.50.1" in out, out)
out = b.cmd("ping 10.0.2.2 3", "received", 30); check("b -> outside ping through NAT", "bytes from 10.0.2.2" in out, out)
out = b.cmd(f"http 10.0.2.2 {HP} /", "rustros> ", 30); check("b -> outside TCP/HTTP through NAT", "hello from outside" in out, out)
out = a.cmd("mod", "rustros> "); print([l for l in out.splitlines() if "nat" in l])
check("a: sessions shown", "sessions" in out and " 0 sessions" not in out, out)
# a ttl-limited packet: ping with ttl 1 is not supported by the shell; check that the gateway still answers itself
out = b.cmd("ping 10.0.2.15 1", "received"); check("b -> a's outside address (routed to the gateway itself)", "bytes from 10.0.2.15" in out, out)
# removing the module stops forwarding
check("remove nat", a.upd("module-remove", "nat") == ["OK"]); a.pump(2)
out = b.cmd("ping 10.0.2.2 1", "received", 15); check("no NAT, no way out", "bytes from 10.0.2.2" not in out, out)
for v in vms: v.q.kill()
print("ALL OK")
