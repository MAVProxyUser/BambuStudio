import struct, sys
path, dylib = sys.argv[1], sys.argv[2]
d = bytearray(open(path,'rb').read())
assert struct.unpack_from('<I',d,0)[0]==0xFEEDFACF, "need thin MH_MAGIC_64"
ncmds, sizeofcmds = struct.unpack_from('<II', d, 16)
lc_end = 32 + sizeofcmds
name = dylib.encode()+b'\x00'
namelen = (len(name)+7)&~7
cmdsize = 24 + namelen
lc = struct.pack('<IIIIII', 0x0C, cmdsize, 24, 2, 0x10000, 0x10000) + name + b'\x00'*(namelen-len(name))
if any(d[lc_end:lc_end+cmdsize]):
    print("ERR: no zero padding after load commands (%d bytes needed)"%cmdsize); sys.exit(1)
d[lc_end:lc_end+cmdsize] = lc
struct.pack_into('<II', d, 16, ncmds+1, sizeofcmds+cmdsize)
open(path,'wb').write(d)
print("injected LC_LOAD_DYLIB ->", dylib)
