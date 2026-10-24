import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("dhcp_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("dhcp_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
M = f"{ROOT}/build/modules"
check("boot", wait_for("rescue> ", 120))
check("dhcp lease", wait_for("dhcp: 10.0.2.15/24 gw 10.0.2.2 from 10.0.2.2", 30))
out = run_cmd("ip", "rescue> "); check("address applied", "10.0.2.15/24  gw 10.0.2.2" in out)
r = upd("info"); check("updater reachable over dhcp", "slot" in r)
check("install shell remotely", upd("module-install", "shell", f"{M}/shell.mod") == "OK")
check("shell up", wait_for("rustros> ", 20))
out = run_cmd("ping 10.0.2.2 2", "received"); check("ping gw", "bytes from 10.0.2.2" in out)
# manual address wins: dhcp steps aside
con.sendall(b"\x1d"); wait_for("rescue> ", 10)
out = run_cmd("ip 10.0.2.16/24 10.0.2.2", "rescue> ")
check("dhcp steps aside", wait_for("dhcp: address set by hand (10.0.2.16), stopping", 10))
out = run_cmd("ip 10.0.2.15/24 10.0.2.2", "rescue> ")
# saved static config: no dhcp on the next boot
out = run_cmd("save", "rescue> "); check("save", "saved" in out)
mark = len(log); con.sendall(b"reboot\r")
end = time.time() + 120
while time.time() < end and b"[console: shell]" not in log[mark:]: pump(0.5)
pump(5)
after = clean(log[mark:])
check("static after save: no dhcp", "dhcp:" not in after and "10.0.2.15" in after)
q.kill(); print("ALL OK")
