import sys, time, socket, subprocess, struct, os
mode = sys.argv[1]; sys.argv = ["test.py", mode]
TAP = "hmq0"
subprocess.run(["ip", "tuntap", "del", "dev", TAP, "mode", "tap", "multi_queue"], capture_output=True)
subprocess.run(["ip", "tuntap", "add", "dev", TAP, "mode", "tap", "multi_queue"], check=True)
subprocess.run(["ip", "addr", "add", "10.77.0.1/24", "dev", TAP], check=True)
subprocess.run(["ip", "link", "set", TAP, "up"], check=True)
src = open(__file__.replace("cake_test.py", "test.py")).read()
src = src.replace('"-device", f"{nic},netdev=n0"]', f'"-device", f"{{nic}},netdev=n0", "-netdev", "tap,id=n1,ifname={TAP},script=no,downscript=no,queues=4,vhost=off", "-device", "virtio-net-pci,netdev=n1,mq=on,vectors=10,mac=52:54:00:77:00:02"]')
exec(src.split('check("boot"')[0])
import atexit; atexit.register(lambda: subprocess.run(["ip", "tuntap", "del", "dev", TAP, "mode", "tap", "multi_queue"], capture_output=True))
src2 = open(__file__.replace("cake_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
check("boot", wait_for("rescue> ", 120))
boot = clean(log); print([l for l in boot.splitlines() if "queue pair" in l])
#check("nic1: 4 queue pairs, host MAC filter on", "net: 4 queue pairs (rings rx 512 tx 256), host MAC filter on" in boot or "net: 4 queue pairs (rings rx 512 tx 512), host MAC filter on" in boot)
#check("nic0 (slirp): one pair", "net: 1 queue pair" in boot)
run_cmd("ip nic1 10.77.0.2/24", "rescue> ")
for m in ["echo", "cake"]:
    check(m, upd("module-install", m, f"{ROOT}/build/modules/{m}.mod") == "OK")
def cfg(*a): return subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "module-config", "cake", *a], capture_output=True, text=True).stdout
import threading
def flood_and_measure(secs=4):
    """UDP echo at a high rate from 8 ports; returns (Mbit/s echoed back, ping avg ms)"""
    socks = []
    for i in range(8):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False); s.bind(("10.77.0.1", 0)); socks.append(s)
    got = [0]; stop = [False]
    def rx():
        while not stop[0]:
            for s in socks:
                try:
                    while True: got[0] += len(s.recv(2000))
                except BlockingIOError: pass
            time.sleep(0.0005)
    th = threading.Thread(target=rx, daemon=True); th.start()
    data = b"x" * 1000; t0 = time.time(); sent = 0
    pings = []
    def pinger():
        r = subprocess.run(["ping", "-c", "6", "-i", "0.5", "-W", "2", "10.77.0.2"], capture_output=True, text=True).stdout
        pings.append(r)
    pt = threading.Thread(target=pinger); pt.start()
    first = [None]
    while time.time() - t0 < secs:
        if first[0] is None and time.time() - t0 >= 1: first[0] = got[0]
        for s in socks:
            try: s.sendto(data, ("10.77.0.2", 7)); sent += 1
            except BlockingIOError: pass
        time.sleep(0.0003)
    in_window = got[0]
    time.sleep(1); stop[0] = True; pt.join()
    # what arrived while sending, after the first second (the queue fills first)
    mbit = (in_window - first[0]) * 8 / (secs - 1) / 1e6
    import re
    m = re.search(r"= [\d.]+/([\d.]+)/", pings[0] or "")
    return mbit, float(m.group(1)) if m else None
base, p0 = flood_and_measure(); print(f"no shaping: {base:.1f} Mbit/s echoed, ping {p0} ms")
cfg("egress.nic1", "5mbit"); pump(3)
check("cake configured", wait_for("cake: nic1 egress 5Mbit", 10))
eg, p1 = flood_and_measure(); print(f"egress 5 Mbit: {eg:.1f} Mbit/s echoed, ping {p1} ms")
check("egress shaped to ~5 Mbit", 3.8 < eg < 5.6 and base > eg * 1.5)
check("ping stays quick under the flood", p1 is not None and p1 < 20)
cfg("egress.nic1", "-"); cfg("ingress.nic1", "3mbit"); pump(3)
ig, p2 = flood_and_measure(); print(f"ingress 3 Mbit: {ig:.1f} Mbit/s echoed, ping {p2} ms")
check("ingress shaped to ~3 Mbit", 2.2 < ig < 3.4)
r = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "info"], capture_output=True, text=True).stdout
print([l for l in r.splitlines() if "cake" in l])
check("status", "nic1 in 3Mbit" in r)
print([l.strip() for l in r.splitlines() if "by module" in l])
check("CPU by module, cake among them", any("by module" in l and "cake " in l for l in r.splitlines()))
cfg("ingress.nic1", "-"); pump(3)
free, _ = flood_and_measure(2); print(f"removed: {free:.1f} Mbit/s")
check("unshaped again", free > 2 * ig)
q.kill(); print("ALL OK")
