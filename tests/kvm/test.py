import os, socket, subprocess, sys, time, urllib.request
S = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("ROOT", "/root/github.com/firadio/ros")
mode = sys.argv[1]           # bios | uefi
extra = sys.argv[2:]         # e.g. legacy
img = f"{S}/{mode}.img"
subprocess.run(["cp", f"{ROOT}/build/" + os.environ.get("IMG", "rustros.img"), img], check=True)
if os.environ.get("DISK_MB"):
    subprocess.run(["truncate", "-s", os.environ["DISK_MB"] + "M", img], check=True)
sock = f"{S}/{mode}.sock"
if os.path.exists(sock): os.unlink(sock)
nic = "virtio-net-pci" + (",disable-modern=on" if "legacy" in extra else "")
cmd = ["qemu-system-x86_64", "-accel", "kvm", "-m", "256", "-display", "none", "-monitor", "none",
       "-chardev", f"socket,id=s0,path={sock},server=on,wait=off", "-serial", "chardev:s0",
       "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:17001-:7001,hostfwd=tcp:127.0.0.1:18089-:80,hostfwd=tcp:127.0.0.1:19000-:9000,hostfwd=tcp:127.0.0.1:17777-:7,hostfwd=udp:127.0.0.1:17777-:7",
       "-device", f"{nic},netdev=n0"]
# a legacy virtio disk only under UEFI: SeaBIOS cannot boot from one ("fail
# to find vq"); BIOS runs keep the legacy NIC and a modern disk
if "legacy" in extra and mode == "uefi":
    cmd += ["-drive", f"file={img},format=raw,if=none,id=d0", "-device", "virtio-blk-pci,drive=d0,disable-modern=on,queue-size=128"]
else:
    cmd += ["-drive", f"file={img},format=raw,if=virtio"]
if mode == "uefi":
    subprocess.run(["cp", "/usr/share/OVMF/OVMF_VARS_4M.fd", f"{S}/vars.fd"], check=True)
    cmd += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", f"if=pflash,format=raw,file={S}/vars.fd"]
if os.environ.get("WDT"):
    cmd += ["-device", "i6300esb"]
cmd += os.environ.get("QEMU_EXTRA", "").split()
q = subprocess.Popen(cmd)
import atexit
atexit.register(lambda: q.kill())
time.sleep(1)
con = socket.socket(socket.AF_UNIX); con.connect(sock); con.settimeout(0.2)
log = b""
# The console is read all the time, not only while a test waits for it: a
# serial line nobody reads backs up into QEMU, and GRUB (UEFI) then stalls on
# its output (fast on KVM: the menu's redraws fill the buffer).
def _reader():
    global log
    while True:
        try:
            d = con.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return
        if not d:
            return
        log += d
import threading
threading.Thread(target=_reader, daemon=True).start()
def pump(t):
    time.sleep(t)
def wait_for(s, t=60):
    end = time.time() + t
    while time.time() < end:
        if s.encode() in log: return True
        pump(0.3)
    return False
def clean(b): 
    import re
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", b.decode(errors="replace"))
def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name, flush=True)
    if not ok:
        print(clean(log)[-3000:]); q.kill(); sys.exit(1)
def run_cmd(c, until, t=20):
    global log
    mark = len(log)
    con.sendall(c.encode() + b"\r")
    end = time.time() + t
    while time.time() < end and until.encode() not in log[mark:]:
        pump(0.3)
    return clean(log[mark:])

check("boot", wait_for("rustros> ", 120))
out = clean(log); print("\n".join(l for l in out.splitlines() if l.startswith(("RustROS ", "cpu", "cmdline", "net:", "disk:"))))
check("key not printed", "key=***" in out)
page = urllib.request.urlopen("http://127.0.0.1:18089/", timeout=5).read().decode()
check("http", "RustROS is running" in page)
s = socket.create_connection(("127.0.0.1", 17777), timeout=5)
blob = os.urandom(200000)
s.sendall(blob); got = b""
while len(got) < len(blob): got += s.recv(65536)
s.close()
check("tcp echo 200KB", got == blob)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
u.sendto(b"udp-hello", ("127.0.0.1", 17777))
check("udp echo", u.recvfrom(100)[0] == b"udp-hello")
out = run_cmd("ping 10.0.2.2 3", "received")
check("ping gateway", "bytes from 10.0.2.2" in out)
print("\n".join(l for l in out.splitlines() if "from" in l or "received" in l))
s2 = socket.create_connection(("127.0.0.1", 17777), timeout=5)
time.sleep(1)
out = run_cmd("conns", "rustros> ")
print(out.strip())
check("conns shows owner app", "echo" in out)
out = run_cmd("modules", "rustros> ")
check("modules lists all", all(a in out for a in ("shell", "echo", "httpd", "updater")))
s2.close()
if "update" in extra:
    up = [sys.executable, f"{ROOT}/tools/rustros-update.py", "127.0.0.1", "--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
    r = subprocess.run(up[:2] + ["127.0.0.1", "upload", f"{ROOT}/build/rustros.elf", "--wait"] + up[3:], capture_output=True, text=True, timeout=300)
    print(r.stdout, r.stderr)
    if r.returncode != 0:
        print("---- serial log tail ----"); print(clean(log)[-4000:])
    check("upload + trial boot + confirm", r.returncode == 0)
    r = subprocess.run(up[:3] + ["status"] + up[3:], capture_output=True, text=True); print(r.stdout.strip())
    check("now on slot b", "slot b" in r.stdout and "trial" not in r.stdout)
    # bad key must be rejected
    r = subprocess.run(up[:3] + ["reboot", "--key", "wrong"] + up[3:5], capture_output=True, text=True); print(r.stdout.strip())
    check("bad key rejected", "ERR auth" in r.stdout)
    # rollback: upload again but never confirm, then force a reboot
    r = subprocess.run(up[:2] + ["127.0.0.1", "upload", f"{ROOT}/build/rustros.elf"] + up[3:], capture_output=True, text=True, timeout=300)
    check("second upload", r.returncode == 0)
    for _ in range(90):
        r = subprocess.run(up[:3] + ["status"] + up[3:], capture_output=True, text=True)
        if "slot a (trial" in r.stdout: break
        time.sleep(1)
    print(r.stdout.strip())
    check("trial boot of slot a", "slot a (trial" in r.stdout)
    r = subprocess.run(up[:3] + ["reboot"] + up[3:], capture_output=True, text=True); print(r.stdout.strip())
    time.sleep(3)
    for _ in range(90):
        r = subprocess.run(up[:3] + ["status"] + up[3:], capture_output=True, text=True)
        if r.stdout.strip(): break
        time.sleep(1)
    print(r.stdout.strip())
    check("rolled back to slot b", "slot b" in r.stdout and "trial" not in r.stdout)
q.kill()
print("ALL OK")
