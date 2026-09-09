import sys, struct, mmap
f=open(sys.argv[1],'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
assert d[:4]==b'MDMP', "not a minidump"
nstreams=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]
streams={}
for i in range(nstreams):
    st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); streams.setdefault(st,(ds,rva))
ds,rva=streams[6]; b=d[rva:rva+ds]
tid=struct.unpack('<I',b[0:4])[0]
ecode=struct.unpack('<I',b[8:12])[0]
eflags=struct.unpack('<I',b[12:16])[0]
eaddr=struct.unpack('<Q',b[24:32])[0]
nparam=struct.unpack('<I',b[32:36])[0]
einfo=[struct.unpack('<Q',b[40+i*8:48+i*8])[0] for i in range(nparam)]
csz,crva=struct.unpack('<II', b[160:168])
c=d[crva:crva+csz]
def q(o): return struct.unpack('<Q',c[o:o+8])[0]
names=['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15']
offs=[0x78,0x80,0x88,0x90,0x98,0xa0,0xa8,0xb0,0xb8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0]
regs={n:q(o) for n,o in zip(names,offs)}
rip=q(0xf8)
print("thread=%d exception=0x%08x flags=0x%x eaddr=0x%x"%(tid,ecode,eflags,eaddr))
rw = "WRITE" if (nparam>=1 and einfo[0]==1) else ("READ" if nparam>=1 and einfo[0]==0 else "?")
fault = einfo[1] if nparam>=2 else None
print("access=%s fault=0x%x"%(rw, fault if fault is not None else 0))
print("rip=0x%x"%rip)
for n in names: print("  %s=0x%x"%(n,regs[n]))
rax,rcx=regs['rax'],regs['rcx']
print("--- CutInfo model check (rax=data(), rcx=volume_id) ---")
calc=(rax+rcx*8)&0xffffffffffffffff
print("rax+rcx*8=0x%x  fault=0x%x  match=%s"%(calc, fault or 0, calc==(fault or -1)))
d.close()
