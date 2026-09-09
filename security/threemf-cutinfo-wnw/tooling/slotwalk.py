# full-dump heap walker: read the CONTEXT, find data() (rax at load fault),
# then dump the qword at data()+k*8 for a range of k, classifying each region.
import sys, struct, mmap
f=open(sys.argv[1],'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
ns=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]; S={}
for i in range(ns):
    st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); S.setdefault(st,(ds,rva))
# context
ds,rva=S[6]; b=d[rva:rva+ds]
csz,crva=struct.unpack('<II',b[160:168]); c=d[crva:crva+csz]
rax=struct.unpack('<Q',c[0x78:0x80])[0]  # volumes.data() at load fault
rcx=struct.unpack('<Q',c[0x80:0x88])[0]
# modules
ds,rva=S[4]; nm_=struct.unpack('<I',d[rva:rva+4])[0]; p=rva+4; mods=[]
def rstr(off): ln=struct.unpack('<I',d[off:off+4])[0]; return d[off+4:off+4+ln].decode('utf-16-le','replace')
for i in range(nm_):
    base=struct.unpack('<Q',d[p:p+8])[0]; sz=struct.unpack('<I',d[p+8:p+12])[0]
    nm=rstr(struct.unpack('<I',d[p+20:p+24])[0]).split('\\')[-1]; mods.append((base,base+sz,nm)); p+=108
# memory64 ranges
mem=[]
if 9 in S:
    ds,rva=S[9]; n=struct.unpack('<Q',d[rva:rva+8])[0]; base=struct.unpack('<Q',d[rva+8:rva+16])[0]
    off=base; q=rva+16
    for i in range(n):
        va=struct.unpack('<Q',d[q:q+8])[0]; sz=struct.unpack('<Q',d[q+8:q+16])[0]; q+=16
        mem.append((va,off,sz)); off+=sz
def read(va,ln):
    for s,o,sz in mem:
        if s<=va<s+sz: return d[o+(va-s):o+(va-s)+min(ln,sz-(va-s))]
    return None
def classify(v):
    for lo,hi,nm in mods:
        if lo<=v<hi: return "MOD:%s+0x%x"%(nm,v-lo)
    for s,o,sz in mem:
        if s<=v<s+sz: return "heap"
    return "unmapped"
print("data()=0x%x (rax)  rcx(vid at faultrun)=0x%x"%(rax,rcx))
print("mem64 ranges:",len(mem))
print("--- slots data()+k*8 ---")
lo,hi=int(sys.argv[2]),int(sys.argv[3])
for k in range(lo,hi):
    va=rax+k*8
    r=read(va,8)
    if r is None:
        print("  k=%-7d @0x%x  <slot addr unmapped>"%(k,va)); continue
    val=struct.unpack('<Q',r)[0]
    # peek at what val+0x1e8 looks like (target of the write)
    cls=classify(val)
    tgt=classify((val+0x1e8)&0xffffffffffffffff) if val else "-"
    # is val attacker content? show ascii of the 8 bytes
    asc=''.join(chr(x) if 32<=x<127 else '.' for x in r)
    print("  k=%-7d slot@0x%x = 0x%016x [%s] tgt+0x1e8:[%s] |%s|"%(k,va,val,cls,tgt,asc))
d.close()
