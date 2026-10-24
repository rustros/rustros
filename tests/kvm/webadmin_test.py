import sys, time, socket, subprocess, json, hashlib, hmac, os, http.client, urllib.parse
mode = sys.argv[1]; sys.argv = ["test.py", mode]
src = open(__file__.replace("webadmin_test.py", "test.py")).read()
src = src.replace("hostfwd=tcp:127.0.0.1:17777-:7,", "hostfwd=tcp:127.0.0.1:17777-:7,hostfwd=tcp:127.0.0.1:18088-:8080,")
assert "18088" in src
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("webadmin_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index("def line", _w)])
check("boot", wait_for("rescue> ", 120))

class Web:
    def __init__(s): s.cookie = None
    def req(s, method, path, form=None, hull=True, t=10):
        c = http.client.HTTPConnection("127.0.0.1", 18088, timeout=t)
        h = {}
        if hull: h["X-RustROS"] = "1"
        if s.cookie: h["Cookie"] = "hs=" + s.cookie
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form); h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body=body, headers=h)
        r = c.getresponse(); d = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and sc.startswith("hs="): s.cookie = sc.split(";")[0][3:] or None
        try: d = json.loads(d)
        except Exception: d = d.decode(errors="replace")
        return r.status, d
    def login(s, pw):
        _, c = s.req("GET", "/api/challenge")
        key = hashlib.sha256(("rustros-web:" + pw).encode()).digest()
        proof = hmac.new(key, c["nonce"].encode(), hashlib.sha256).hexdigest()
        return s.req("POST", "/api/login", {"nonce": c["nonce"], "proof": proof})
w = Web()
cfg = lambda k, v: upd("module-config", "webadmin", k, v)
check("installed", upd("module-install", "webadmin", f"{ROOT}/build/modules/webadmin.mod") == "OK")
check("listening, nobody allowed (nic0 is a WAN)", wait_for("webadmin: open to nobody", 10) and wait_for("webadmin: http on port 8080", 5))
try:
    st, _ = w.req("GET", "/", t=3); refused = False
except Exception:
    refused = True
check("WAN side refused", refused)
cfg("allow", "10.0.2.0/24"); check("allow set", wait_for("webadmin: open to 10.0.2.0/24", 10))
st, page = w.req("GET", "/"); check("page served", st == 200 and "RustROS" in page and "sha256" in page)
st, d = w.req("GET", "/api/status"); check("status needs login", st == 401)
st, d = w.login("x"); check("no password yet: no logins", st == 403 and "no password" in d["error"])
mark = len(log)
cfg("password", "s3cret pass"); check("password stored hashed", wait_for("webadmin: password set", 10))
time.sleep(0.5)
out = upd("module-config", "webadmin"); print(out)
check("plain password gone from the settings", "s3cret" not in out and "pwhash" in out)
st, d = w.login("wrong"); check("wrong password", st == 403)
_, c = w.req("GET", "/api/challenge")
key = hashlib.sha256(b"rustros-web:s3cret pass").digest()
proof = hmac.new(key, c["nonce"].encode(), hashlib.sha256).hexdigest()
st, d = w.req("POST", "/api/login", {"nonce": c["nonce"], "proof": proof}, hull=False); check("login needs the custom header", st == 403)
st, d = w.req("POST", "/api/login", {"nonce": c["nonce"], "proof": proof}); check("login", st == 200 and w.cookie)
st, d = w.req("POST", "/api/login", {"nonce": c["nonce"], "proof": proof}); check("a challenge works once", st == 403)
st, d = w.req("GET", "/api/status"); check("status", st == 200 and d["ifaces"][0]["name"] == "nic0" and "cpu0" in d["perf"]); print(d["ifaces"][0], d["running"])
st, d = w.req("POST", "/api/system", {"action": "perf_reset"}, hull=False); check("changes need the custom header", st == 403)
# network: the candidate flow
st, d = w.req("POST", "/api/net", {"cmd": "ip nic0 add 10.0.2.77"}); check("no direct edits from the web", not d["ok"])
st, d = w.req("POST", "/api/net", {"cmd": "cand ip nic0 add 10.0.2.77"}); check("candidate edit", d["ok"] and "10.0.2.77" in d["out"])
st, d = w.req("GET", "/api/net"); check("candidate shown, not in effect", d["has_cand"] and not d["applied"] and "10.0.2.77" not in d["show"])
st, d = w.req("POST", "/api/net", {"cmd": "apply 20"}); check("apply", d["ok"])
st, d = w.req("GET", "/api/net"); check("pending revert, new connection works", d["pending"] is not None and "10.0.2.77" in d["show"]); print("pending", d["pending"])
st, d = w.req("POST", "/api/net", {"cmd": "confirm"}); check("confirm", d["ok"] and "confirmed" in d["out"])
time.sleep(1); st, d = w.req("GET", "/api/net"); check("kept", d["pending"] is None and d["applied"] and "10.0.2.77" in d["show"])
st, d = w.req("POST", "/api/net", {"cmd": "revert"}); st, d = w.req("GET", "/api/net"); check("revert", "10.0.2.77" not in d["show"])
st, d = w.req("POST", "/api/net", {"cmd": "discard"}); st, d = w.req("GET", "/api/net"); check("discard", not d["has_cand"])
# modules
check("router installed", upd("module-install", "router", f"{ROOT}/build/modules/router.mod") == "OK"); time.sleep(1)
st, d = w.req("GET", "/api/modules"); names = [m["name"] for m in d["modules"]]; print(names)
check("module list", "router" in names and "webadmin" in names)
wa = [m for m in d["modules"] if m["name"] == "webadmin"][0]; check("password hash hidden", ["pwhash", "(set)"] in wa["config"])
st, d = w.req("POST", "/api/module", {"name": "router", "action": "set", "key": "note", "value": "hello"}); check("module setting", d["ok"])
st, d = w.req("GET", "/api/modules"); r = [m for m in d["modules"] if m["name"] == "router"][0]; check("setting listed", ["note", "hello"] in r["config"])
st, d = w.req("POST", "/api/module", {"name": "router", "action": "del", "key": "note"}); check("setting removed", d["ok"])
# logs
st, d = w.req("GET", "/api/logs"); check("log list", isinstance(d["boots"], list))
if d["this"] is not None:
    st, t = w.req("GET", "/api/log"); check("this boot's log", "webadmin: login" in t)
# logout, lockout
st, d = w.req("POST", "/api/logout", {}); w.cookie = None
st, d = w.req("GET", "/api/status"); check("logged out", st == 401)
for i in range(5): w.login("nope")
st, d = w.login("s3cret pass"); check("locked out after failed logins", st == 429)
# reboot from the web
time.sleep(61); st, d = w.login("s3cret pass"); check("login again after the pause", st == 200)
mark = len(log)
st, d = w.req("POST", "/api/system", {"action": "reboot"}); check("reboot requested", d["ok"])
end = time.time() + 120
while time.time() < end and b"rescue> " not in log[mark:]: pump(0.5)
check("back after reboot", b"rescue> " in log[mark:])
end = time.time() + 20
while time.time() < end and b"webadmin: open to 10.0.2.0/24" not in log[mark:]: pump(0.5)
check("webadmin back with its settings", b"webadmin: open to 10.0.2.0/24" in log[mark:])
q.kill(); print("ALL OK")
