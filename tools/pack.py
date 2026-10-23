#!/usr/bin/env python3
"""Pack the kernel into a self-extracting ELF, so a bigger kernel fits a slot.

  pack.py KERNEL.elf OUT.elf [--boot=NAME=FILE ...]

With --boot, the boot modules follow the ELF (4 KiB aligned) in OUT: the
kernel image a slot holds. A third segment has GRUB load them above the
stub, and their address and length go into the kernel (over the
"RRSBNDL1@ADDRESS" of kernel/src/bootmods.rs), so the kernel has its drivers
before it can read a disk.

The kernel's loadable image (code, read-only data, data) is LZ4-compressed
and put behind a 32-bit stub. GRUB loads two segments:

  - the kernel's whole range (image and .bss), empty: GRUB zeroes it and keeps
    the boot info and everything else out of it;
  - just above it, the kernel's multiboot2 header, the stub and the data.

GRUB enters the stub like the kernel (32-bit, paging off, EAX = magic,
EBX = boot info); it inflates the image into place and jumps to the kernel's
entry with EAX and EBX as they were. The kernel is linked and runs exactly as
before; the stub's memory is free once it is running.
"""

import os
import struct
import subprocess
import sys
import tempfile

MB2_MAGIC = 0xE85250D6

# The stub: a plain LZ4 block decoder. ESI walks the compressed data, EDI the
# output. No stack (GRUB sets none); EBP keeps the magic, the boot info
# pointer goes to memory.
STUB = """
bits 32
org {base}
mb2:
    incbin "{mb2}"
    align 16, db 0
start:
    cld
    mov ebp, eax
    mov [boot_info], ebx
    mov esi, data
    mov edi, {dest}
token:
    movzx ebx, byte [esi]
    inc esi
    mov eax, ebx
    shr eax, 4
    call length
    mov ecx, eax
    rep movsb
    cmp esi, data_end
    jae done
    movzx eax, word [esi]
    add esi, 2
    mov edx, eax
    mov eax, ebx
    and eax, 15
    call length
    lea ecx, [eax + 4]
    mov ebx, esi
    mov esi, edi
    sub esi, edx
    rep movsb               ; forward, a byte at a time: overlaps repeat
    mov esi, ebx
    jmp token
done:
    cmp edi, {dest_end}
    jne $                   ; corrupt: hang rather than run half a kernel
    mov eax, ebp
    mov ebx, [boot_info]
    mov ecx, {entry}
    jmp ecx
; EAX = a 4-bit length; 15 continues in the following bytes
length:
    cmp eax, 15
    jne .end
.more:
    movzx ecx, byte [esi]
    inc esi
    add eax, ecx
    cmp ecx, 255
    je .more
.end:
    ret
    align 4, db 0
boot_info:
    dd 0
data:
    incbin "{data}"
data_end:
"""
# `call` needs a stack: the stub sets one at its own end, see STACK below.


def lz4_compress(src: bytes) -> bytes:
    """LZ4 block format, hash chains with lazy matching (slow but small output)."""
    n = len(src)
    out = bytearray()
    MIN, WINDOW, DEPTH = 4, 65535, 512
    head = {}
    prev = [-1] * n

    def insert(i):
        if i + MIN <= n:
            k = src[i:i + MIN]
            prev[i] = head.get(k, -1)
            head[k] = i

    def best(i):
        # matches must end 5 bytes before the end and start 12 before it
        if i + 12 > n:
            return 0, 0
        limit = n - 5
        blen, boff = 0, 0
        j = head.get(src[i:i + MIN], -1)
        depth = DEPTH
        while j >= 0 and i - j <= WINDOW and depth:
            if i + blen < limit and src[j + blen] == src[i + blen]:
                l = 0
                while i + l < limit and src[j + l] == src[i + l]:
                    l += 1
                if l > blen:
                    blen, boff = l, i - j
            j = prev[j]
            depth -= 1
        return (blen, boff) if blen >= MIN else (0, 0)

    def ext(v):
        while v >= 255:
            out.append(255)
            v -= 255
        out.append(v)

    def emit(lit, mlen, off):
        ll = len(lit)
        tok = (min(ll, 15) << 4) | (min(mlen - 4, 15) if mlen else 0)
        out.append(tok)
        if ll >= 15:
            ext(ll - 15)
        out.extend(lit)
        if mlen:
            out.extend(struct.pack("<H", off))
            if mlen - 4 >= 15:
                ext(mlen - 4 - 15)

    i = anchor = 0
    while i < n:
        l, o = best(i)
        if l:
            # lazy: a longer match one byte later wins
            insert(i)
            l2, o2 = best(i + 1)
            if l2 > l + 1:
                i += 1
                l, o = l2, o2
            else:
                prev_i = i
                emit(src[anchor:i], l, o)
                for k in range(prev_i + 1, prev_i + l):
                    insert(k)
                i = anchor = prev_i + l
                continue
            emit(src[anchor:i], l, o)
            for k in range(i, i + l):
                insert(k)
            i = anchor = i + l
        else:
            insert(i)
            i += 1
    emit(src[anchor:], 0, 0)
    return bytes(out)


def lz4_decompress(src: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(src):
        tok = src[i]
        i += 1

        def length(v):
            nonlocal i
            if v == 15:
                while True:
                    b = src[i]
                    i += 1
                    v += b
                    if b != 255:
                        break
            return v

        ll = length(tok >> 4)
        out += src[i:i + ll]
        i += ll
        if i >= len(src):
            break
        off = src[i] | src[i + 1] << 8
        i += 2
        ml = length(tok & 15) + 4
        for _ in range(ml):
            out.append(out[-off])
    return bytes(out)


def segments(elf: bytes):
    assert elf[:4] == b"\x7fELF" and elf[4] == 2, "a 64-bit ELF"
    entry, phoff = struct.unpack_from("<QQ", elf, 0x18)
    phentsize, phnum = struct.unpack_from("<HH", elf, 0x36)
    loads = []
    for k in range(phnum):
        p_type, _flags, off, vaddr, paddr, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", elf, phoff + k * phentsize)
        if p_type == 1 and memsz:
            loads.append((paddr, off, filesz, memsz))
    return entry, sorted(loads)


def pack(kernel: bytes, bundle: bytes = b"") -> bytes:
    """The packed ELF (with `bundle`: then the bundle, 4 KiB aligned) and the ELF's size."""
    if kernel[:4] == b"\x7fELF" and b"RUSTPACK" in kernel[:512]:
        sys.exit("pack: already packed")
    entry, loads = segments(kernel)
    base = loads[0][0]
    # the image: every file-backed byte from the first segment on, gaps zeroed
    img_end = max(p + f for p, _, f, _ in loads)
    image = bytearray(img_end - base)
    for p, off, f, _ in loads:
        image[p - base:p - base + f] = kernel[off:off + f]
    end = max(p + m for p, _, _, m in loads)

    # the boot modules right above the kernel, where they stay; the stub
    # above them (its memory is free once the kernel runs)
    bundle_base = (end + 0xFFF) & ~0xFFF
    stub_base = (bundle_base + len(bundle) + 0xFFF) & ~0xFFF
    if bundle:
        if image.count(BUNDLE_AT) != 1:
            sys.exit("pack: the kernel has no (or more than one) boot module address field")
        at = image.index(BUNDLE_AT)
        image[at:at + 16] = struct.pack("<QQ", bundle_base, len(bundle))

    # the multiboot2 header, copied (it must be in the first 32 KiB of the file)
    mb2 = None
    for o in range(0, min(len(kernel), 32768), 8):
        if struct.unpack_from("<I", kernel, o)[0] == MB2_MAGIC:
            hlen = struct.unpack_from("<I", kernel, o + 8)[0]
            mb2 = kernel[o:o + hlen]
            break
    if mb2 is None:
        sys.exit("pack: no multiboot2 header in the kernel")

    data = lz4_compress(bytes(image))
    assert lz4_decompress(data) == bytes(image), "LZ4 round trip"

    with tempfile.TemporaryDirectory() as tmp:
        t = lambda n: os.path.join(tmp, n)
        open(t("mb2"), "wb").write(mb2)
        open(t("data"), "wb").write(data)
        src = STUB.format(base=stub_base, mb2=t("mb2"), data=t("data"), dest=base,
                          dest_end=img_end, entry=entry)
        # a small stack for `call`, after everything
        src = src.replace("start:\n    cld\n", "start:\n    cld\n    mov esp, stack_top\n")
        src += "    align 16, db 0\n    times 64 db 0\nstack_top:\n"
        open(t("stub.asm"), "w").write(src)
        subprocess.run(["nasm", "-f", "bin", "-o", t("stub.bin"), t("stub.asm")], check=True)
        stub = open(t("stub.bin"), "rb").read()
    start = stub_base + ((len(mb2) + 15) & ~15)

    # ELF64: header, program headers, a marker, the stub segment, then a
    # section header table with just the null entry (GRUB wants one); the
    # bundle after that, 4 KiB aligned
    PH = 56
    nph = 3 if bundle else 2
    seg_off = 0x100
    shoff = (seg_off + len(stub) + 7) & ~7
    elf_end = shoff + 64
    bundle_off = (elf_end + 0xFFF) & ~0xFFF
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, start, 64, shoff, 0, 64, PH, nph, 64, 1, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 6, seg_off, base, base, 0, end - base, 8)
    ph += struct.pack("<IIQQQQQQ", 1, 7, seg_off, stub_base, stub_base, len(stub), len(stub), 8)
    if bundle:
        ph += struct.pack("<IIQQQQQQ", 1, 4, bundle_off, bundle_base, bundle_base, len(bundle), len(bundle), 4096)
    head = ehdr + ph + b"RUSTPACK"
    assert len(head) <= seg_off
    head += bytes(seg_off - len(head))
    body = head + stub
    out = body + bytes(shoff - len(body)) + bytes(64)
    elf = len(out)
    if bundle:
        out += bytes(bundle_off - len(out)) + bundle
    return out, elf


# the kernel's field for the boot modules' address and length (kernel/src/bootmods.rs)
BUNDLE_AT = b"RRSBNDL1@ADDRESS"
BUNDLE_MAGIC = b"RRSBNDL1"
BUNDLE_HEAD = 4096   # magic, count, then 80-byte entries: name (32), offset in sectors (4), stored bytes (4),
                     # SHA-256 of the module (32), its bytes (4), flags (4: 1 = stored LZ4-compressed)
BUNDLE_ENTRY = 80


def boot_bundle(specs):
    """The boot modules, LZ4-compressed, after the kernel ELF (see kernel/src/bootmods.rs)."""
    import hashlib
    entries, blobs, at = [], [], BUNDLE_HEAD // 512
    for spec in specs:
        name, path = spec.split("=", 1)
        data = open(path, "rb").read()
        packed = lz4_compress(data)
        assert lz4_decompress(packed) == data, "LZ4 round trip"
        entries.append(name.encode().ljust(32, b"\0") + struct.pack("<II", at, len(packed)) + hashlib.sha256(data).digest() + struct.pack("<II", len(data), 1))
        padded = packed + bytes(-len(packed) % 512)
        blobs.append(padded)
        at += len(padded) // 512
    head = (BUNDLE_MAGIC + struct.pack("<II", len(entries), 0) + b"".join(entries)).ljust(BUNDLE_HEAD, b"\0")
    return head + b"".join(blobs)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--boot=")]
    boot = [a[len("--boot="):] for a in sys.argv[1:] if a.startswith("--boot=")]
    if len(args) != 2:
        sys.exit(__doc__)
    kernel = open(args[0], "rb").read()
    out, elf = pack(kernel, boot_bundle(boot) if boot else b"")
    open(args[1], "wb").write(out)
    print(f"pack: kernel {len(kernel)} -> {elf} bytes" + (f", with boot modules {len(out)} bytes ({', '.join(b.split('=')[0] for b in boot)})" if boot else ""))


if __name__ == "__main__":
    main()
