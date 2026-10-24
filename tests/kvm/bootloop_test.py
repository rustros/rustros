import sys
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("bootloop_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
src2 = open(__file__.replace("bootloop_test.py", "wasm_test.py")).read()
_w = src2.index("W = f"); exec(src2[_w:src2.index('check("boot"', _w)])
M = f"{ROOT}/build/modules"
def crash_and_wait(t=150):
    mark = len(log)
    con.sendall(b"crash panic\r")
    end = time.time() + t
    while time.time() < end and b"rustros> " not in log[mark:].split(b"rebooting in 2 s", 1)[-1]: pump(0.5)
    return clean(log[mark:])
check("boot", wait_for("rustros> ", 120))
check("install native echo", upd("module-install", "echo", f"{M}/echo.mod") == "OK"); pump(2)
a = crash_and_wait(); print([l for l in a.splitlines() if l.startswith(("boot:", "modules:"))])
check("2nd unstable boot: normal", "2 unstable boots in a row" in a and "SAFE MODE" not in a and "echo started" in a)
a = crash_and_wait(); print([l for l in a.splitlines() if l.startswith(("boot:", "modules:"))])
check("3rd: safe mode, modules not started", "boot: SAFE MODE" in a and "echo started" not in a)
r = upd("info"); print([l for l in r.splitlines() if l.startswith(("slot", "boot"))]); check("info shows safe mode", "SAFE MODE, 3 unstable boots" in r)
a = crash_and_wait(); print([l for l in a.splitlines() if l.startswith(("boot:", "modules:", "disk:"))])
check("4th: GRUB rolled back to slot b, normal again", "rolled back to slot b" in a and "disk: running slot b" in a and "echo started" in a and "SAFE MODE" not in a)
r = upd("info"); print([l for l in r.splitlines() if l.startswith(("slot", "boot", "crash"))]); check("rollback recorded", "rolled back to slot b" in r)
print("waiting for the stable mark..."); pump(25)
a = crash_and_wait(); print([l for l in a.splitlines() if l.startswith(("boot:", "modules:"))])
check("after a stable run one crash is just one", "unstable boots" not in a and "echo started" in a)
q.kill(); print("ALL OK")
