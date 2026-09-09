# given a dump, print rip's module+RVA and rax/rcx and store/load classification
import sys, struct, mmap
f=open(sys.argv[1],'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
ns=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]; S={}
for i in range(ns):
    st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); S.setdefault(st,(ds,rva))
ds,rva=S[6]; b=d[rva:rva+ds]
ec=struct.unpack('<I',b[8:12])[0]; np=struct.unpack('<I',b[32:36])[0]
ei=[struct.unpack('<Q',b[40+i*8:48+i*8])[0] for i in range(np)]
csz,crva=struct.unpack('<II',b[160:168]); c=d[crva:crva+csz]
def q(o): return struct.unpack('<Q',c[o:o+8])[0]
rax,rcx,rip=q(0x78),q(0x80),q(0xf8)
rw="W" if (np>=1 and ei[0]==1) else ("R" if np>=1 and ei[0]==0 else "?"); fault=ei[1] if np>=2 else 0
# module list
ds,rva=S[4]; n=struct.unpack('<I',d[rva:rva+4])[0]; p=rva+4
def rstr(off):
    ln=struct.unpack('<I',d[off:off+4])[0]; return d[off+4:off+4+ln].decode('utf-16-le','replace')
own=None
for i in range(n):
    base=struct.unpack('<Q',d[p:p+8])[0]; sz=struct.unpack('<I',d[p+8:p+12])[0]
    nm=rstr(struct.unpack('<I',d[p+20:p+24])[0]).split('\\')[-1]
    if base<=rip<base+sz: own=(nm,base,rip-base)
    p+=108
print("ex=0x%x %s fault=0x%x rax=0x%x rcx=0x%x rip=0x%x"%(ec,rw,fault,rax,rcx,rip))
if own: print("rip in %s +0x%x (base 0x%x)"%(own[0],own[2],own[1]))
print("load_match(rax+rcx*8==fault)=%s"%(((rax+rcx*8)&0xffffffffffffffff)==fault))
d.close()
