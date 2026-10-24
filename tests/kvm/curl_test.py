# The shell's curl command (used daily as `curl ip.fm` to see the outbound
# address), against local test servers on the box only, no internet: HTTP
# (GET, -i, -I, -X POST -d, -H, --interface with an extra address or an
# interface, as in `curl --interface <extra address> ip.fm`) and HTTPS (a
# private CA is not trusted by default; `cfg shell ca` makes it trusted;
# removing it undoes that).
# The servers answer like ip.fm does with the client's address, and echo
# the request so the options can be checked.
import sys, threading, http.server, ssl, os
S = __file__.rsplit("/", 1)[0]
mode = sys.argv[1]; sys.argv = ["test.py"] + sys.argv[1:]
__file__ = f"{S}/test.py"
exec(open(f"{S}/test.py").read().split('check("boot"')[0])
src2 = open(f"{S}/wasm_test.py").read(); _w = src2.index("W = f"); exec(src2[_w:src2.index("def line", _w)])
P = f"{S}/panelmock"
HTTP, HTTPS = 18580, 18581


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, body=True):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n).decode(errors="replace") if n else ""
        b = f"rustros-curl {self.command} {self.path} from={self.client_address[0]} xtest={self.headers.get('X-Test')} body={data}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if body:
            self.wfile.write(b)

    def do_GET(self):
        self.reply()

    def do_POST(self):
        self.reply()

    def do_HEAD(self):
        self.reply(body=False)


plain = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP), Echo)
threading.Thread(target=plain.serve_forever, daemon=True).start()
secure = http.server.ThreadingHTTPServer(("127.0.0.1", HTTPS), Echo)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{P}/site.pem", f"{P}/site.key")
secure.socket = ctx.wrap_socket(secure.socket, server_side=True)
threading.Thread(target=secure.serve_forever, daemon=True).start()


def curl(args, t=30):
    return run_cmd(f"curl {args}", "rustros> ", t)


check("boot", wait_for("rescue> ", 120))
check("shell installed", upd("module-install", "shell", f"{ROOT}/build/modules/shell.mod") == "OK")
check("shell has the console", wait_for("rustros> ", 30))
base = f"http://10.0.2.2:{HTTP}"
out = curl(f"{base}/ip"); print(out.strip()[-200:])
check("HTTP GET", "rustros-curl GET /ip from=" in out)
out = curl(f"-i {base}/"); check("HTTP -i shows the status line and headers", "HTTP/1.1 200" in out and "Content-Type: text/plain" in out and "rustros-curl GET /" in out)
out = curl(f"-I {base}/h"); check("HTTP -I: HEAD, headers only", "HTTP/1.1 200" in out and "rustros-curl" not in out)
out = curl(f"-X POST -d hello {base}/p"); check("HTTP -X POST -d", "rustros-curl POST /p" in out and "body=hello" in out)
out = curl(f"-H X-Test:42 {base}/x"); check("HTTP -H", "xtest=42" in out)
# from an extra address: QEMU's user network shows every client to the host
# as 127.0.0.1, so the address is checked in curl's own -v output
run_cmd("cand ip nic0 add 10.0.2.100", "rustros> "); run_cmd("apply 0", "[y/N]"); run_cmd("y", "rustros> ")
check("extra address 10.0.2.100 on nic0", "10.0.2.100" in run_cmd("ip", "rustros> "))
out = curl(f"-v --interface 10.0.2.100 {base}/ip"); print(out.strip()[-300:])
check("--interface <extra address>", "from 10.0.2.100" in out and "rustros-curl GET /ip" in out)
out = curl(f"-v --interface nic0 {base}/ip")
check("--interface nic0", "from 10.0.2.15" in out and "rustros-curl GET /ip" in out)
out = curl(f"--interface 10.0.2.123 {base}/ip")
check("--interface with an address not ours is refused", "not one of our addresses" in out and "rustros-curl" not in out)
secure_url = f"https://10.0.2.2:{HTTPS}"
out = curl(f"{secure_url}/"); print(out.strip()[-200:])
check("HTTPS: a private CA is not trusted by default", "rustros-curl" not in out and "curl: (" in out)
pem = open(f"{P}/ca.pem").read().replace("\n", " ")
check("cfg shell ca set", upd("module-config", "shell", "ca", pem) == "OK")
out = curl(f"{secure_url}/ip"); print(out.strip()[-200:])
check("HTTPS GET with the CA trusted", "rustros-curl GET /ip from=" in out)
out = curl(f"-i {secure_url}/"); check("HTTPS -i", "HTTP/1.1 200" in out and "rustros-curl GET /" in out)
out = curl(f"-X POST -d secret {secure_url}/p"); check("HTTPS -X POST -d", "rustros-curl POST /p" in out and "body=secret" in out)
check("cfg shell ca removed", upd("module-config", "shell", "ca", "-") == "OK")
out = curl(f"{secure_url}/"); check("HTTPS: not trusted again", "rustros-curl" not in out)
q.kill()
print("ALL OK")
