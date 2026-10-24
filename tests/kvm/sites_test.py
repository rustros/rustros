import sys, time, socket, ssl, os, threading, http.server, hashlib, json
S = __file__.rsplit("/", 1)[0]
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(f"{S}/test.py").read().replace("hostfwd=tcp:127.0.0.1:17777-:7,", "hostfwd=tcp:127.0.0.1:17777-:7,hostfwd=tcp:127.0.0.1:18490-:443,")
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
src2 = open(f"{S}/wasm_test.py").read(); _w = src2.index("W = f"); exec(src2[_w:src2.index("def line", _w)])
check("boot", wait_for("rescue> ", 120))
P = f"{S}/panelmock"
class B(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        b = f"backend saw {self.path} host={self.headers.get('Host')} xff={self.headers.get('X-Forwarded-For')} proto={self.headers.get('X-Forwarded-Proto')}".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
srv = http.server.ThreadingHTTPServer(("0.0.0.0", 18557), B); threading.Thread(target=srv.serve_forever, daemon=True).start()
ctx = ssl.create_default_context(cafile=f"{P}/ca.pem")
def req(method, host, path, body=b"", headers=None, secure=True, t=30):
    s = socket.create_connection(("127.0.0.1", 18490 if secure else 18089), timeout=t)
    if secure: s = ctx.wrap_socket(s, server_hostname=host)
    h = {"Host": host, "Content-Length": str(len(body)), "Connection": "close"}; h.update(headers or {})
    s.sendall((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body)
    d = b""
    while True:
        c = s.recv(1 << 20)
        if not c: break
        d += c
    head, _, b = d.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n"); code = int(lines[0].split()[1])
    hd = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    return code, hd, b
cfg = lambda k, v: upd("module-config", "sites", k, v)
one = lambda f: open(f"{P}/{f}").read().replace("\n", " ")
check("ext4 driver installed", upd("module-install", "ext4", f"{ROOT}/build/modules/ext4.mod") == "OK")
check("files partition mounted by it", wait_for("storage: files partition", 30) and wait_for("journaled", 30))
check("installed", upd("module-install", "sites", f"{ROOT}/build/modules/sites.mod") == "OK")
TOKEN = "tok-0123456789abcdef"
cfg("site.main.hosts", "site.test,www.site.test"); cfg("site.main.cert", one("site.pem")); cfg("site.main.key", one("site.key"))
cfg("site.api.hosts", "api.test"); cfg("site.api.proxy", "10.0.2.2:18557"); cfg("token", TOKEN)
time.sleep(4); print([l for l in upd("info").splitlines() if "sites" in l])
A = {"Authorization": "Bearer " + TOKEN}
code, _, _ = req("PUT", "site.test", "/_sites/files/main/index.html", b"x", A, secure=False); check("no uploads over plain HTTP", code == 403)
code, _, _ = req("PUT", "site.test", "/_sites/files/main/index.html", b"x", {"Authorization": "Bearer nope"}); check("wrong token", code == 401)
BIG = os.urandom(20 << 20)
files = {"main/index.html": b"<h1>RustROS</h1>\n", "main/docs/index.html": b"<h1>docs</h1>\n", "main/releases/latest.json": b'{"format":1}', "main/big.bin": BIG}
for k, v in files.items():
    code, _, b = req("PUT", "site.test", "/_sites/files/" + k, v, A, t=120); check(f"upload {k}", code == 201)
code, h, b = req("GET", "site.test", "/"); check("index", code == 200 and b == files["main/index.html"] and h["content-type"].startswith("text/html"))
code, h, b = req("HEAD", "site.test", "/releases/latest.json"); check("HEAD json", code == 200 and b == b"" and h["content-type"] == "application/json" and h["content-length"] == "12")
etag = h["etag"]
code, h, b = req("GET", "site.test", "/releases/latest.json", headers={"If-None-Match": etag}); check("ETag → 304", code == 304)
code, h, b = req("GET", "www.site.test", "/docs"); check("directory without slash → 301", code == 301 and h["location"] == "/docs/")
code, h, b = req("GET", "site.test", "/docs/"); check("directory index", code == 200 and b"docs" in b)
code, _, _ = req("GET", "site.test", "/nope.html"); check("404", code == 404)
code, _, _ = req("GET", "site.test", "/../../cfg"); check("traversal refused", code in (400, 404))
code, h, _ = req("GET", "site.test", "/x?y=1", secure=False); check("HTTP → HTTPS", code == 301 and h["location"] == "https://site.test:443/x?y=1" or h.get("location") == "https://site.test/x?y=1"); print(h.get("location"))
t0 = time.time(); code, h, b = req("GET", "site.test", "/big.bin", t=120); dt = time.time() - t0
check("20 MB intact", code == 200 and b == BIG); print(f"{len(b)/dt*8/1e6:.0f} Mbit/s")
code, h, b = req("GET", "api.test", "/hello?q=1"); check("proxied site", code == 200 and b.startswith(b"backend saw /hello?q=1 host=api.test xff=10.0.2.2 proto=https")); print(b)
code, h, b = req("GET", "site.test", "/_sites/files/?prefix=main/releases", headers=A); check("list", code == 200 and json.loads(b) == [{"name": "main/releases/latest.json", "size": 12}]); print(b)
code, _, _ = req("DELETE", "site.test", "/_sites/files/main/docs/index.html", headers=A); check("delete", code == 204)
code, _, _ = req("GET", "site.test", "/docs/"); check("gone", code == 404)
print([l for l in upd("info").splitlines() if "module   sites" in l])
q.kill(); print("ALL OK")
