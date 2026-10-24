"""Userspace L2TPv2 + PPP (LCP/PAP/IPCP) client for tests."""
import socket, struct, time

def avp(t, v): return struct.pack(">HHH", 0x8000 | (6 + len(v)), 0, t) + v
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack(f">{len(b)//2}H", b)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def ip_hdr(src, dst, proto, plen, ttl=64):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + plen, 0, 0x4000, ttl, proto, 0, src, dst)
    return h[:10] + struct.pack(">H", csum(h)) + h[12:]
def icmp_echo(src, dst, ident, seq, data=b"rustros-ping"):
    m = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + data
    m = m[:2] + struct.pack(">H", csum(m)) + m[4:]
    return ip_hdr(src, dst, 1, len(m)) + m
def udp_pkt(src, dst, sp, dp, data):
    u = struct.pack(">HHHH", sp, dp, 8 + len(data), 0) + data
    ph = src + dst + struct.pack(">BBH", 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack(">H", c) + u[8:]
    return ip_hdr(src, dst, 17, len(u)) + u
def check_ip(p):
    assert csum(p[:20]) == 0, "IP checksum"
    ihl = (p[0] & 15) * 4; total = struct.unpack(">H", p[2:4])[0]; l4 = p[ihl:total]
    if p[9] == 1: assert csum(l4) == 0, "ICMP checksum"
    if p[9] == 17 and l4[6:8] != b"\0\0":
        assert csum(p[12:20] + struct.pack(">BBH", 0, 17, len(l4)) + l4) == 0, "UDP checksum"
    return p[:total]

class Client:
    def __init__(self, server, user=None, password=None, tid=100):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.s.settimeout(0.2)
        self.server = server; self.user, self.password = user, password
        self.tid, self.sid, self.ns, self.nr = tid, 7, 0, 0
        self.stid = self.ssid = 0; self.ip = None; self.rx = []; self.lcp_ok = False; self.auth = None
        self.log = []
    def send(self, p): self.s.sendto(p, self.server)
    def ctl(self, msg, avps=b"", session=0):
        a = avp(0, struct.pack(">H", msg)) + avps
        p = struct.pack(">HHHHHH", 0xC802, 12 + len(a), self.stid, session, self.ns, self.nr) + a
        self.ns += 1; self.send(p)
    def zlb(self):
        self.send(struct.pack(">HHHHHH", 0xC802, 12, self.stid, 0, self.ns, self.nr))
    def ppp(self, proto, payload):
        self.send(struct.pack(">HHHBBH", 0x0002, self.stid, self.ssid, 0xff, 0x03, proto) + payload)
    def cp(self, proto, code, ident, data=b""):
        self.ppp(proto, struct.pack(">BBH", code, ident, 4 + len(data)) + data)
    def recv(self, t=0.2):
        try: d, _ = self.s.recvfrom(4096)
        except socket.timeout: return None
        flags = struct.unpack(">H", d[:2])[0]; i = 2
        if flags & 0x4000: i += 2
        i += 4
        if flags & 0x0800: ns, nr = struct.unpack(">HH", d[i:i+4]); i += 4
        if flags & 0x0200: i += 2 + struct.unpack(">H", d[i:i+2])[0]
        if flags & 0x8000:
            avps = {}; p = d[i:]
            while len(p) >= 6:
                l = struct.unpack(">H", p[:2])[0] & 0x3ff; t = struct.unpack(">H", p[4:6])[0]; avps[t] = p[6:l]; p = p[l:]
            if 0 in avps: self.nr = (ns + 1) & 0xffff
            return ("ctl", avps)
        f = d[i:]
        if f[:2] == b"\xff\x03": f = f[2:]
        proto = struct.unpack(">H", f[:2])[0]; f = f[2:]
        if proto == 0x21:
            f = check_ip(f)
            if f[9] == 1 and f[20] == 8 and self.ip and f[16:20] == self.ip:   # answer pings to us
                m = b"\0\0\0\0" + f[24:]; m = m[:2] + struct.pack(">H", csum(m)) + m[4:]
                self.send_ip(ip_hdr(self.ip, f[12:16], 1, len(m)) + m); self.answered = getattr(self, "answered", 0) + 1
                return ("ping", f)
            self.rx.append(f); return ("ip", f)
        self.on_ppp(proto, f); return ("ppp", proto)
    def on_ppp(self, proto, f):
        code, ident, ln = struct.unpack(">BBH", f[:4]); data = f[4:ln]
        self.log.append((hex(proto), code))
        if proto == 0xc021 and code == 1: self.cp(0xc021, 2, ident, data)       # ack server's LCP (incl. PAP)
        elif proto == 0xc021 and code == 2: self.lcp_ok = True
        elif proto == 0xc021 and code == 9: self.cp(0xc021, 10, ident, b"\0\0\0\0" + data[4:])
        elif proto == 0xc023: self.auth = (code == 2)
        elif proto == 0x8021 and code == 1: self.cp(0x8021, 2, ident, data)   # server's IPCP request
        elif proto == 0x8021 and code == 3: self.ip_offer = data[2:6]; self.cp(0x8021, 1, 2, data)
        elif proto == 0x8021 and code == 2: self.ip = data[2:6] if len(data) >= 6 else self.ip_offer
    def wait(self, cond, t=5):
        end = time.time() + t
        while time.time() < end:
            if cond(): return True
            self.recv()
        return cond()
    def connect(self):
        self.ctl(1, avp(2, b"\1\0") + avp(7, b"pyclient") + avp(3, struct.pack(">I", 3)) + avp(9, struct.pack(">H", self.tid)))
        r = None
        end = time.time() + 5
        while time.time() < end and not r:
            x = self.recv()
            if x and x[0] == "ctl" and 0 in x[1] and struct.unpack(">H", x[1][0])[0] == 2: r = x[1]
        assert r, "no SCCRP"
        self.stid = struct.unpack(">H", r[9])[0]
        self.ctl(3)                                              # SCCCN
        self.ctl(10, avp(14, struct.pack(">H", self.sid)) + avp(15, struct.pack(">I", 1)))  # ICRQ
        r = None; end = time.time() + 5
        while time.time() < end and not r:
            x = self.recv()
            if x and x[0] == "ctl" and 0 in x[1] and struct.unpack(">H", x[1][0])[0] == 11: r = x[1]
        assert r, "no ICRP"
        self.ssid = struct.unpack(">H", r[14])[0]
        self.ctl(12, avp(24, struct.pack(">I", 10000000)), session=self.ssid)   # ICCN
        self.cp(0xc021, 1, 1, bytes([5, 6, 0x12, 0x34, 0x56, 0x78]))            # our LCP: magic only
        assert self.wait(lambda: self.lcp_ok, 5), "LCP"
        if self.user is not None:
            u, p = self.user.encode(), self.password.encode()
            self.cp(0xc023, 1, 1, bytes([len(u)]) + u + bytes([len(p)]) + p)
            assert self.wait(lambda: self.auth is not None, 5), "PAP answer"
            if not self.auth: return False
        self.cp(0x8021, 1, 1, bytes([3, 6, 0, 0, 0, 0]))
        assert self.wait(lambda: self.ip is not None, 5), "IPCP"
        return True
    def send_ip(self, pkt): self.ppp(0x21, pkt)
    def expect_ip(self, pred, t=5):
        end = time.time() + t
        while time.time() < end:
            for p in self.rx:
                if pred(p): self.rx.remove(p); return p
            x = self.recv()
            # answer pings addressed to us
            if x and x[0] == "ip" and x[1][9] == 1 and x[1][20] == 8 and x[1][16:20] == self.ip:
                p = self.rx.pop(); ihl = 20
                m = b"\0\0\0\0" + p[24:]; m = m[:2] + struct.pack(">H", csum(m)) + m[4:]
                self.send_ip(ip_hdr(self.ip, p[12:16], 1, len(m)) + m)
        return None
    def close(self):
        self.ctl(14, avp(1, b"\0\1"), session=self.ssid)   # CDN
        self.ctl(4, avp(9, struct.pack(">H", self.tid)))    # StopCCN
