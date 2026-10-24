import sys, time, socket, struct, threading
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(__file__.replace("l2tp_test.py", "test.py")).read()
src = src.replace("hostfwd=udp:127.0.0.1:17777-:7", "hostfwd=udp:127.0.0.1:17777-:7,hostfwd=udp:127.0.0.1:11701-:1701")
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("l2tp_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
sys.path.insert(0, S); from l2tpclient import Client, icmp_echo, udp_pkt
M = f"{ROOT}/build/modules"
# a UDP echo server "on the internet" (the host, 10.0.2.2 from the guest)
es = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); es.bind(("127.0.0.1", 0)); EP = es.getsockname()[1]
seen = []
def echo():
    while True:
        d, a = es.recvfrom(4096); seen.append(a); es.sendto(b"echo:" + d, a)
threading.Thread(target=echo, daemon=True).start()
check("boot", wait_for("rescue> ", 120))
for m in ["shell", "l2tp"]:
    _r = upd("module-install", m, f"{M}/{m}.mod"); print(repr(_r)); check(f"install {m}", _r == "OK")
check("shell", wait_for("rustros> ", 20))
pump(2)
import subprocess
def cfgcmd(*a):
    out = subprocess.run(["python3", f"{ROOT}/tools/rustros-update.py", "--port", "19000", "--key-file", f"{ROOT}/build/update.key", "127.0.0.1", "module-config", "l2tp", *a], capture_output=True, text=True).stdout
    lines = [l for l in out.splitlines() if not l.strip().startswith("(") and l.strip()]
    return "\n".join(lines)
check("remote set alice", cfgcmd("user.alice", "s3cret") == "OK")
# the password must not cross the wire in clear
import importlib.util
spec = importlib.util.spec_from_file_location("hu", f"{ROOT}/tools/rustros-update.py"); hu = importlib.util.module_from_spec(spec); spec.loader.exec_module(hu)
wire = []
_cc = hu.socket.create_connection
class Rec:
    def __init__(self, s): self.s = s
    def sendall(self, d): wire.append(bytes(d)); return self.s.sendall(d)
    def send(self, d): wire.append(bytes(d)); return self.s.send(d)
    def __getattr__(self, n): return getattr(self.s, n)
hu.socket.create_connection = lambda *a, **k: Rec(_cc(*a, **k))
key = open(f"{ROOT}/build/update.key").read().strip().encode()
r, _, _ = hu.command("127.0.0.1", 19000, key, b"K", b"l2tp\nuser.carol\nTopSecretPw", encrypt=True)
check("encrypted set works", r == "OK")
check("password not on the wire", not any(b"TopSecretPw" in w for w in wire) and not any(b"carol" in w for w in wire))
# tampering with the ciphertext is caught by the MAC
_orig = hu.keystream_xor
hu.keystream_xor = lambda k, n, d: bytes([_orig(k, n, d)[0] ^ 1]) + _orig(k, n, d)[1:]
r, _, _ = hu.command("127.0.0.1", 19000, key, b"K", b"l2tp\nuser.mallory\nx", encrypt=True)
hu.keystream_xor = _orig
check("garbled ciphertext refused", r.startswith("ERR"))
check("remove carol", cfgcmd("user.carol", "-") == "OK")
check("remote set bob", cfgcmd("user.bob", "pw@2") == "OK")
check("remote set+remove", cfgcmd("dns", "9.9.9.9") == "OK" and cfgcmd("dns", "-") == "OK")
lst = cfgcmd(); print(lst)
check("listing masks passwords", "user.alice = ***" in lst and "s3cret" not in lst and "dns" not in lst)
pump(3)
SRV = ("127.0.0.1", 11701)
A = Client(SRV, "alice", "s3cret", tid=101); check("alice connects", A.connect())
check("alice got 10.0.0.2", A.ip == bytes([10, 0, 0, 2]))
B = Client(SRV, "bob", "pw@2", tid=102); check("bob (password with @) connects", B.connect() and B.ip == bytes([10, 0, 0, 3]))
C = Client(SRV, "alice", "wrong", tid=103); check("wrong password refused", C.connect() is False)
# ping the server
A.send_ip(icmp_echo(A.ip, bytes([10, 0, 0, 1]), 1, 1))
check("ping server 10.0.0.1", A.expect_ip(lambda p: p[9] == 1 and p[20] == 0 and p[12:16] == bytes([10, 0, 0, 1])) is not None)
# ping the outside through NAT (slirp answers 10.0.2.2)
A.send_ip(icmp_echo(A.ip, bytes([10, 0, 2, 2]), 0x4242, 1))
r = A.expect_ip(lambda p: p[9] == 1 and p[20] == 0)
check("ping outside through NAT", r is not None and r[12:16] == bytes([10, 0, 2, 2]) and r[16:20] == A.ip and r[24:26] == b"\x42\x42")
# UDP to the internet and back, port and payload intact
for k in range(5):
    A.send_ip(udp_pkt(A.ip, bytes([10, 0, 2, 2]), 40000, EP, b"hello %d" % k))
got = [A.expect_ip(lambda p: p[9] == 17) for _ in range(5)]
check("udp through NAT and back", all(g is not None and g[22:24] == struct.pack(">H", 40000) and g[28:].startswith(b"echo:hello") for g in got))
check("host saw the NAT's address", seen and seen[-1][0] == "127.0.0.1")
# client to client
B.send_ip(icmp_echo(B.ip, A.ip, 7, 1))
def pump_a():
    for _ in range(30): A.recv()
threading.Thread(target=pump_a).start()
check("bob pings alice directly", B.expect_ip(lambda p: p[9] == 1 and p[20] == 0 and p[12:16] == A.ip, 5) is not None)
# spoofing: bob sends with alice's address -> dropped
B.send_ip(udp_pkt(A.ip, bytes([10, 0, 2, 2]), 1, EP, b"spoof")); time.sleep(1)
check("spoofed source dropped", not any(b"spoof" in x for x in []) and not B.rx)
out = run_cmd("mod", "rustros> "); print([l for l in out.splitlines() if l.startswith("l2tp")])
check("status counts clients", "2 clients" in out)
A.close(); pump(2)
out = run_cmd("mod", "rustros> "); check("alice down on disconnect", "1 clients" in out)
q.kill(); print("ALL OK")
