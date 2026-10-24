"""Forwarding through a router VM on the KVM test box: RustROS (its router
module) or, as references, Linux in the same VM configuration.

Topology: network namespace fa (10.10.1.2) - tap - [nic1 10.10.1.1 | router |
nic2 10.10.2.1] - tap - namespace fb (10.10.2.2). The router VM has 1 vCPU,
512 MB and two virtio-net NICs on taps with vhost (plus nic0 on QEMU's user
network for RustROS's updater).

  fwd_bench.py [bios|uefi]

  ROUTER   rustros (default) | linux-fwd (Linux kernel forwarding) |
           linux-nft (with a stateful nftables forward chain) |
           linux-xdp (an XDP program redirecting between the NICs);
           the Linux guests need linux-router/build.sh run first
  GEN      suite (default, the regression suite's: tcp1 and tcp4 with
           iperf3, 64-byte UDP with pktgen in 1 and 16 flows) |
           iperf (tcp1, tcp4) | pktgen (64-byte UDP, FLOWS flows) |
           tcpflows (TCP with 1, 2, 4 and 8 streams)
  FLOWS    pktgen: UDP source ports (flows), default 1
  THREADS  pktgen: sending threads into the tap, default 1
  MQ       queue pairs per NIC (taps and virtio-net), default 1
  SPIN=1   a RustROS user-mode process loops for ever during the measurements
  RUNS, SECS  runs per measurement (default 3) of SECS seconds (default 10)

Prints one line per measurement: "fwd <router> mq=<n> <test> <median> <unit>
(runs: ...)". 64-byte UDP uses the kernel's packet generator (pktgen) in fa
and counts the packets arriving on fb's tap: iperf3 cannot send small packets
faster than about 215 kpps, below what the routers forward. With a router
that is RustROS, each measurement also prints RustROS's own view (CPU, NIC
counters, and the stage counters of a measurement build) and how busy the
host's QEMU, vhost and pktgen threads were.
"""
import json, os, socket, statistics, subprocess, sys, time

S = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("ROOT", "/root/github.com/firadio/ros")
mode = sys.argv[1] if len(sys.argv) > 1 else "bios"
RUNS = int(os.environ.get("RUNS", "3"))
SECS = int(os.environ.get("SECS", "10"))
ROUTER = os.environ.get("ROUTER", "rustros")
GEN = os.environ.get("GEN", "suite")
FLOWS = int(os.environ.get("FLOWS", "1"))
THREADS = int(os.environ.get("THREADS", "1"))
MQ = int(os.environ.get("MQ", "1"))
SPIN = os.environ.get("SPIN") == "1"
LINUX_K = os.environ.get("LINUX_KERNEL", f"/boot/vmlinuz-{os.uname().release}")
LINUX_I = os.environ.get("LINUX_INITRD", f"{S}/linux-router.cpio.gz")
PORT = 19301
NS = {"fa": ("fwa", "10.10.1.2", "10.10.1.1", "52:54:00:f0:00:01"), "fb": ("fwb", "10.10.2.2", "10.10.2.1", "52:54:00:f0:00:02")}
UPDATE = ["python3", f"{ROOT}/tools/rustros-update.py", "--port", str(PORT), "--key-file", f"{ROOT}/build/update.key", "127.0.0.1"]

# one test run at a time on the box
if not os.environ.get("RUSTROS_LOCKED"):
    import fcntl
    _lock = open(f"{S}/run.lock", "w")
    try:
        fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another test run is active, stopping")
    subprocess.run(["bash", f"{S}/kvm_check.sh"], check=True)


def sh(*a, check=True):
    return subprocess.run(a, capture_output=True, text=True, check=check)


def upd(*a):
    return subprocess.run(UPDATE + list(a), capture_output=True, text=True).stdout


q = None


def cleanup():
    for ns, (tap, *_r) in NS.items():
        sh("ip", "netns", "del", ns, check=False)
        sh("ip", "link", "del", tap, check=False)


def check(n, ok, out=""):
    print(("PASS " if ok else "FAIL ") + n, flush=True)
    if not ok:
        print(out[-2500:])
        if q:
            q.kill()
        cleanup()
        sys.exit(1)


def report(test, vals, unit, extra=""):
    nums = ", ".join(f"{v:.2f}" for v in vals)
    print(f"fwd {ROUTER} mq={MQ} {test} {statistics.median(vals):.2f} {unit} (runs: {nums}{extra})", flush=True)


# ---------------------------------------------------------------- the router VM
cleanup()
for ns, (tap, *_r) in NS.items():
    sh("ip", "tuntap", "add", "dev", tap, "mode", "tap", *(["multi_queue"] if MQ > 1 else []))
img = f"{S}/fwd-{mode}.img"
subprocess.run(["cp", f"{ROOT}/build/rustros.img", img], check=True)
subprocess.run(["truncate", "-s", "1200M", img], check=True)
ser = f"{S}/fwd.ser"
if os.path.exists(ser):
    os.unlink(ser)
cmd = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-m", "512", "-display", "none", "-monitor", "none",
       "-chardev", f"socket,id=s0,path={ser},server=on,wait=off", "-serial", "chardev:s0",
       "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{PORT}-:9000", "-device", "virtio-net-pci,netdev=n0"]
for i, (ns, (tap, _ip, _gw, mac)) in enumerate(NS.items(), 1):
    q_opt = f",queues={MQ}" if MQ > 1 else ""
    d_opt = f",mq=on,vectors={2 * MQ + 2}" if MQ > 1 else ""
    cmd += ["-netdev", f"tap,id=n{i},ifname={tap},script=no,downscript=no,vhost=on{q_opt}", "-device", f"virtio-net-pci,netdev=n{i},mac={mac}{d_opt}"]
cmd += ["-drive", f"file={img},format=raw,if=virtio"]
if ROUTER.startswith("linux-"):
    # the same VM, booting the Linux reference router instead of RustROS
    cmd += ["-kernel", LINUX_K, "-initrd", LINUX_I, "-append", f"console=ttyS0 router={ROUTER[6:]} quiet"]
if mode == "uefi":
    subprocess.run(["cp", "/usr/share/OVMF/OVMF_VARS_4M.fd", f"{S}/fwd-vars.fd"], check=True)
    cmd += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd", "-drive", f"if=pflash,format=raw,file={S}/fwd-vars.fd"]
q = subprocess.Popen(cmd)
time.sleep(1)
con = socket.socket(socket.AF_UNIX)
con.connect(ser)
con.settimeout(0.3)
log = b""
end = time.time() + 120
READY = b"LINUX ROUTER READY" if ROUTER.startswith("linux-") else b"rescue> "
while time.time() < end and READY not in log:
    try:
        log += con.recv(65536)
    except (socket.timeout, OSError):
        pass
check("boots", READY in log, log.decode(errors="replace"))
if ROUTER.startswith("linux-"):
    print([l for l in log.decode(errors="replace").splitlines() if "READY" in l or "xdp" in l.lower() or "rror" in l][:5], flush=True)

if ROUTER == "rustros":
    import importlib.util
    spec = importlib.util.spec_from_file_location("hu", f"{ROOT}/tools/rustros-update.py")
    hu = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hu)
    KEY = open(f"{ROOT}/build/update.key").read().strip().encode()
    for t in ["cand ip nic1 10.10.1.1/24", "cand ip nic2 10.10.2.1/24", "apply 0"]:
        hu.command("127.0.0.1", PORT, KEY, b"N", t.encode())
    out = hu.command("127.0.0.1", PORT, KEY, b"N", b"ip")[0]
    check("nic1 and nic2 configured", "10.10.1.1/24" in out and "10.10.2.1/24" in out, out)
    check("router installed", upd("module-install", "router", f"{ROOT}/build/modules/router.mod").strip().endswith("OK"))
for ns, (tap, ip, gw, _mac) in NS.items():
    sh("ip", "netns", "add", ns)
    sh("ip", "link", "set", tap, "netns", ns)
    sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", tap)
    sh("ip", "-n", ns, "link", "set", tap, "up")
    sh("ip", "-n", ns, "link", "set", "lo", "up")
    sh("ip", "-n", ns, "route", "add", "default", "via", gw)
time.sleep(2)
p = sh("ip", "netns", "exec", "fa", "ping", "-c", "3", "-W", "2", NS["fb"][1], check=False)
check("fa reaches fb through the router", " 0% packet loss" in p.stdout or "3 received" in p.stdout, p.stdout + p.stderr)

if SPIN:
    check("linux installed", upd("module-install", "linux", f"{ROOT}/build/modules/linux.mod").strip().endswith("OK"))
    time.sleep(1)
    r = upd("run", f"{ROOT}/build/user/spin")
    check("spin started", r.startswith("OK"), r)
    time.sleep(1)
    before = upd("ps")
    print(before.strip(), flush=True)
    check("spin running", "spin" in before, before)


# ---------------------------------------------------------------- what is seen while traffic runs
def counter(ns, side, what="packets"):
    out = sh("ip", "-n", ns, "-s", "-j", "link", "show", NS[ns][0]).stdout
    return json.loads(out)[0]["stats64"][side][what]


def rustros_load():
    """RustROS's own view: CPU busy (halted time counts as idle), the NICs'
    rates and ring-full counts, and the stage counters of a measurement
    build (from `info`)."""
    if ROUTER != "rustros":
        return ""
    keep = [l.strip() for l in upd("info").splitlines() if l.strip().startswith(("cpu0", "by module", "nic1 now", "nic2 now", "stages"))]
    return " | ".join(keep)


def threads_cpu():
    """CPU time (ticks) of QEMU's threads and of the vhost and pktgen threads."""
    t = {}
    for tid in os.listdir(f"/proc/{q.pid}/task"):
        try:
            st = open(f"/proc/{q.pid}/task/{tid}/stat").read()
        except OSError:
            continue
        f = st[st.rindex(")") + 2:].split()
        t[f"{st[st.index('(') + 1:st.rindex(')')]}#{tid}"] = int(f[11]) + int(f[12])
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            st = open(f"/proc/{pid}/stat").read()
        except OSError:
            continue
        comm = st[st.index("(") + 1:st.rindex(")")]
        if comm.startswith(("kpktgend", "vhost")):
            f = st[st.rindex(")") + 2:].split()
            t[f"{comm}#{pid}"] = int(f[11]) + int(f[12])
    return t


def busy(a, b, secs):
    hz = os.sysconf("SC_CLK_TCK")
    out = sorted(((k.split("#")[0], (b[k] - a.get(k, 0)) / hz / secs * 100) for k in b), key=lambda x: -x[1])
    return ", ".join(f"{n} {pct:.0f}%" for n, pct in out if pct >= 3)


# ---------------------------------------------------------------- 64-byte UDP with pktgen
def pktgen(flows):
    sh("modprobe", "pktgen")
    dev = NS["fa"][0]
    fa_mac = json.loads(sh("ip", "-n", "fa", "-j", "link", "show", dev).stdout)[0]["address"]

    def pg(path, c):
        r = sh("ip", "netns", "exec", "fa", "sh", "-c", f"echo '{c}' > /proc/net/pktgen/{path}", check=False)
        if r.returncode:
            check(f"pktgen {path}: {c}", False, r.stderr)

    vals, offered = [], []
    for _ in range(RUNS):
        for t in range(8):
            pg(f"kpktgend_{t}", "rem_device_all")
        devs = [dev if t == 0 else f"{dev}@{t}" for t in range(THREADS)]
        for t, d in enumerate(devs):
            pg(f"kpktgend_{t}", f"add_device {d}")
            for c in ["count 0", "pkt_size 60", "delay 0", "clone_skb 0", "dst 10.10.2.2", "src_min 10.10.1.2", "src_max 10.10.1.2",
                      f"dst_mac {NS['fa'][3]}", f"src_mac {fa_mac}", "udp_dst_min 9", "udp_dst_max 9",
                      "udp_src_min 10000", f"udp_src_max {10000 + flows - 1}"] + (["flag UDPSRC_RND"] if flows > 1 else []):
                pg(d, c)
        p = subprocess.Popen(["ip", "netns", "exec", "fa", "sh", "-c", "echo start > /proc/net/pktgen/pgctrl"])
        time.sleep(2)  # warm up (ARP, queues)
        r0, t0, w0, c0 = counter("fb", "rx"), counter("fa", "tx"), time.time(), threads_cpu()
        time.sleep(SECS / 2)
        load = rustros_load()
        time.sleep(SECS / 2)
        r1, t1, w1, c1 = counter("fb", "rx"), counter("fa", "tx"), time.time(), threads_cpu()
        if load:
            print(f"  RustROS: {load}", flush=True)
        print(f"  host threads busy: {busy(c0, c1, w1 - w0)}", flush=True)
        sh("ip", "netns", "exec", "fa", "sh", "-c", "echo stop > /proc/net/pktgen/pgctrl", check=False)
        p.wait(timeout=30)
        vals.append((r1 - r0) / (w1 - w0) / 1000)
        offered.append((t1 - t0) / (w1 - w0) / 1000)
    report(f"pktgen64 flows={flows} threads={THREADS}", vals, "kpps forwarded", f"; offered {', '.join(f'{v:.0f}' for v in offered)} kpps")


# ---------------------------------------------------------------- TCP with iperf3
srv = None


def iperf(*a):
    p0, b0, c0, w0 = counter("fb", "rx"), counter("fb", "rx", "bytes"), threads_cpu(), time.time()
    pr = subprocess.Popen(["ip", "netns", "exec", "fa", "iperf3", "-c", NS["fb"][1], "-t", str(SECS), "-J", *a], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(SECS / 2)
    load = rustros_load()
    out, err = pr.communicate(timeout=SECS + 60)
    p1, b1, c1, w1 = counter("fb", "rx"), counter("fb", "rx", "bytes"), threads_cpu(), time.time()
    pk = p1 - p0
    print(f"  {' '.join(a) or 'tcp1'}: {pk / (w1 - w0) / 1000:.1f} kpps on the fb tap, {(b1 - b0) / max(pk, 1):.0f} bytes per packet; host threads busy: {busy(c0, c1, w1 - w0)}", flush=True)
    if load:
        print(f"  RustROS: {load}", flush=True)
    try:
        j = json.loads(out)
    except ValueError:
        j = {"error": out + err}
    if "error" in j:
        check(f"iperf3 {' '.join(a)}", False, str(j["error"]))
    return j["end"]["sum_received"]["bits_per_second"] / 1e9


def tcp(streams):
    report(f"tcp{streams}", [iperf(*(["-P", str(streams)] if streams > 1 else [])) for _ in range(RUNS)], "Gbit/s")


if GEN in ("suite", "iperf", "tcpflows"):
    srv = subprocess.Popen(["ip", "netns", "exec", "fb", "iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
if GEN in ("suite", "iperf"):
    tcp(1)
    tcp(4)
elif GEN == "tcpflows":
    for n in (1, 2, 4, 8):
        tcp(n)
if GEN == "suite":
    pktgen(1)
    pktgen(16)
elif GEN == "pktgen":
    pktgen(FLOWS)
elif GEN not in ("iperf", "tcpflows"):
    check(f"GEN={GEN} is one of suite, iperf, pktgen, tcpflows", False)

if SPIN:
    after = upd("ps")
    print(after.strip(), flush=True)
    check("spin still running after the measurements", "spin" in after and "running" in after, after)
if srv:
    srv.kill()
q.kill()
cleanup()
print("ALL OK")
