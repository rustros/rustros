import sys, time, socket, subprocess, struct, os
mode = sys.argv[1]; sys.argv = ["test.py", mode]
TAP = "hmq0"
subprocess.run(["ip", "tuntap", "del", "dev", TAP, "mode", "tap", "multi_queue"], capture_output=True)
subprocess.run(["ip", "tuntap", "add", "dev", TAP, "mode", "tap", "multi_queue"], check=True)
subprocess.run(["ip", "addr", "add", "10.77.0.1/24", "dev", TAP], check=True)
subprocess.run(["ip", "link", "set", TAP, "up"], check=True)
src = open(__file__.replace("mq_test.py", "test.py")).read()
src = src.replace('"-device", f"{nic},netdev=n0"]', f'"-device", f"{{nic}},netdev=n0", "-netdev", "tap,id=n1,ifname={TAP},script=no,downscript=no,queues=4,vhost=off", "-device", "virtio-net-pci,netdev=n1,mq=on,vectors=10,mac=52:54:00:77:00:02"]')
exec(src.split('check("boot"')[0])
import atexit; atexit.register(lambda: subprocess.run(["ip", "tuntap", "del", "dev", TAP, "mode", "tap", "multi_queue"], capture_output=True))
src2 = open(__file__.replace("mq_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
check("boot", wait_for("rescue> ", 120))
boot = clean(log); print([l for l in boot.splitlines() if "queue pair" in l])
check("nic1: 4 queue pairs, host MAC filter on", "net: 4 queue pairs (rings rx 512 tx 256), host MAC filter on" in boot or "net: 4 queue pairs (rings rx 512 tx 512), host MAC filter on" in boot)
check("nic0 (slirp): one pair", "net: 1 queue pair" in boot)
run_cmd("ip nic1 10.77.0.2/24", "rescue> ")
check("echo", upd("module-install", "echo", f"{ROOT}/build/modules/echo.mod") == "OK"); pump(2)
r = subprocess.run(["ping", "-c", "3", "-W", "2", "10.77.0.2"], capture_output=True, text=True).stdout
check("host pings the guest over the multiqueue NIC", " 0% packet loss" in r)
# many flows: every one answered, in order
socks = []
for i in range(64):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.bind(("10.77.0.1", 0)); socks.append(s)
ok = 0
for rnd in range(5):
    for i, s in enumerate(socks):
        s.sendto(b"flow %d seq %d" % (i, rnd), ("10.77.0.2", 7))
    for i, s in enumerate(socks):
        try:
            d, _ = s.recvfrom(100)
            ok += d == b"flow %d seq %d" % (i, rnd)
        except socket.timeout: pass
check(f"64 flows x 5 rounds echoed ({ok}/320)", ok == 320)
# frames for other MACs: the host-side filter should drop them before the guest
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); raw.bind((TAP, 0))
for i in range(2000):
    raw.send(bytes([0x02, 0, 0, 0, 0x99, i & 0xFF]) + bytes.fromhex("fe0000000001") + b"\x08\x00" + bytes(46))
time.sleep(2)
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "net", "stats"], capture_output=True, text=True).stdout
print(r.strip())
check("foreign frames filtered by the host", "nic1" not in r or "not for us" not in r.split("nic1")[1].split("\n")[0])
q.kill(); print("ALL OK")
