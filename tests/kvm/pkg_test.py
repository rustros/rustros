import sys, time, os, json, hashlib, base64, threading, http.server, subprocess
S = __file__.rsplit("/", 1)[0]
mode = sys.argv[1]
src = open(f"{S}/webadmin_test.py").read()
__file__ = f"{S}/webadmin_test.py"
exec(src.split("cfg = lambda")[0])
_r = upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod"); pump(2)
check("shell", _r == "OK")
def run(c, until=b"rustros> ", t=60):
    m = len(log); con.sendall(c.encode() + b"\r"); end = time.time() + t
    while time.time() < end:
        pump(0.3)
        if log[m:].count(until) >= 1 and len(log) - m > len(c) + 12: break
    pump(0.5); return clean(log[m:])
# the real repository
out = run("pkg list"); check("list before update", "no manifest yet" in out)
out = run("pkg update"); print(out)
check("update from rustros.com", "signature checked" in out)
out = run("pkg list"); print(out)
check("list", "cake" in out and "sites" in out and "kernel" in out)
out = run("pkg info cake"); print(out); check("info", "sha256" in out)
out = run("pkg install cake"); print(out)
check("install cake", "cake installed (native" in out)
out = run("mod"); check("cake listed", "cake" in out)
out = run("pkg remove cake"); check("remove", "cake removed" in out)
out = run("pkg install nosuch"); check("unknown app", "no app nosuch" in out)
# a mock repository with its own key
M = f"{S}/pkgrepo"; os.makedirs(M, exist_ok=True)
key = f"{M}/k.pem"
if not os.path.exists(key): subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key], check=True)
pub = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout[-32:]
kern = open(f"{ROOT}/build/rustros.elf", "rb").read()
cake = open(f"{ROOT}/build/modules/cake.mod", "rb").read()
def manifest(sha, ver="2099.1.1.1", kv="0.0.1"):
    m = {"format": 1, "version": "2099.1.1.1", "kernel": {"version": kv, "x86_64": {"url": "http://10.0.2.2:18766/k", "sha256": hashlib.sha256(kern).hexdigest(), "size": len(kern)}},
         "modules": {"cake": {"version": ver, "native": {"x86_64": {"url": "http://10.0.2.2:18766/cake.mod", "sha256": sha, "size": len(cake)}}}}}
    b = json.dumps(m).encode(); open(f"{M}/latest.json", "wb").write(b)
    sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", f"{M}/latest.json"], capture_output=True, check=True).stdout
    open(f"{M}/latest.json.sig", "w").write(base64.urlsafe_b64encode(sig).rstrip(b"=").decode())
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=M, **k)
    def log_message(self, *a): pass
open(f"{M}/cake.mod", "wb").write(cake); open(f"{M}/k", "wb").write(kern)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18766), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
manifest("ab" * 32)
run("cfg shell repo http://10.0.2.2:18766/latest.json")
out = run("pkg update"); print(out); check("pinned key refuses another signer", "does not check out" in out)
run("cfg shell repo_key " + base64.b64encode(pub).decode())
manifest("ab" * 32)
out = run("pkg install cake"); print(out); check("bad sha256 refused", "does not match" in out)
out = run("mod"); check("not installed", "cake" not in out)
manifest(hashlib.sha256(cake).hexdigest())
out = run("pkg install cake"); print(out); check("good one installs", "cake installed" in out)
out = run("pkg upgrade"); print(out); check("upgrade: newer one taken", "cake 0.1.0 -> 2099.1.1.1" in out and "cake installed" in out)
manifest(hashlib.sha256(cake).hexdigest(), "0.1.0")
out = run("pkg upgrade"); print(out); check("upgrade: up to date", "up to date" in out)
out = run("pkg upgrade kernel"); print(out); check("older kernel not taken", "kernel is up to date" in out)
manifest(hashlib.sha256(cake).hexdigest(), "0.1.0", "2099.1.1.1")
out = run("pkg upgrade kernel"); print(out); check("newer kernel into the spare slot", "spare slot" in out)
out = run("slot"); print(out)
# tampered manifest, old signature
open(f"{M}/latest.json", "ab").write(b" ")
out = run("pkg update"); check("tampered manifest refused", "does not check out" in out)
q.kill(); print("ALL OK")
