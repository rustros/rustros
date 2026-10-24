import sys, re
mode = sys.argv[1]
sys.argv = ["test.py", mode]
src = open(__file__.replace("store_test.py", "test.py")).read()
exec(src.split('check("boot"')[0])
check("boot", wait_for("rustros> ", 120))
out = clean(log); print([l for l in out.splitlines() if l.startswith("storage")])
check("partition created", "created data partition" in out and "storage: data partition" in out)
run_cmd("kv set l2tp/user/alice secret pass 1", "rustros> ")
run_cmd("kv set tmp gone soon", "rustros> ")
out = run_cmd("kv del tmp", "rustros> "); check("delete", "deleted" in out)
out = run_cmd("kv", "rustros> "); print(out.strip()); check("list", "l2tp/user/alice" in out and "tmp" not in out.split("\n",1)[1])
out = run_cmd("df", "rustros> "); print(out.strip())
mark = len(log); con.sendall(b"reboot\r")
end = time.time() + 120
while time.time() < end and b"rustros> " not in log[mark:]: pump(0.5)
after = clean(log[mark:]); print([l for l in after.splitlines() if l.startswith("storage")])
check("not recreated", "created data partition" not in after and "storage: data partition" in after)
out = run_cmd("kv get l2tp/user/alice", "rustros> "); check("survives reboot", "secret pass 1" in out)
up = [sys.executable, f"{ROOT}/tools/rustros-update.py", "127.0.0.1", "--port", "19000", "--key-file", f"{ROOT}/build/update.key"]
r = subprocess.run(up[:3] + ["upload", f"{ROOT}/build/rustros.elf", "--wait"] + up[3:], capture_output=True, text=True, timeout=300)
check("update + confirm", r.returncode == 0)
pump(2)
out = run_cmd("slot", "rustros> ") + run_cmd("kv get l2tp/user/alice", "rustros> "); print(out.strip())
check("survives update", "slot b" in out and "secret pass 1" in out)
q.kill()
import struct, zlib
g = open(img, "rb"); g.seek(512); hdr = g.read(512)
g.seek(1024); ents = g.read(128 * 128)
parts = [struct.unpack_from("<16s16sQQ", ents, i * 128) for i in range(128)]
data = [p for p in parts if p[0] == b"HullOS-data-v1\0\0"]
alt = struct.unpack_from("<Q", hdr, 32)[0]
crc_ok = zlib.crc32(hdr[:16] + b"\0" * 4 + hdr[20:92]) == struct.unpack_from("<I", hdr, 16)[0]
print("GPT data partition", [(p[2], p[3]) for p in data], "backup at", alt, "crc", crc_ok)
mbr = open(img, "rb").read(512)
t, start, size = mbr[446+4], int.from_bytes(mbr[446+16+8:446+16+12], "little"), int.from_bytes(mbr[446+16+12:446+16+16], "little")
print(f"MBR p2 type {t:#x} start {start} size {size} ({size//2048} MiB)")
disk_mb = int(os.environ.get("DISK_MB", "300"))
cache = [p for p in parts if p[0] == b"HullOS-cache-v1\0"]
want = 1048576 if disk_mb >= 600 else 131072
check(f"gpt: data at {want // 2048} MiB, backup at disk end", crc_ok and len(data) == 1 and data[0][2] == want and alt == disk_mb * 2048 - 1)
if disk_mb >= 600:
    check("gpt: cache partition 64-512 MiB", len(cache) == 1 and (cache[0][2], cache[0][3]) == (131072, 1048575))
print("ALL OK")
