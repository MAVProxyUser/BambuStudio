# scan slots data()+k*8 for k in [lo,hi); print slots whose value is a module ptr
# AND value+0x1e8 lands in a WRITABLE section (candidate grooming-free write target).
import sys, struct, mmap
f=open(sys.argv[1],'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
ns=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]; S={}
for i in range(ns):
    st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); S.setdefault(st,(ds,rva))
ds,rva=S[6]; b=d[rva:rva+ds]; csz,crva=struct.unpack('<II',b[160:168]); c=d[crva:crva+csz]
rax=struct.unpack('<Q',c[0x78:0x80])[0]
ds,rva=S[4]; nm_=struct.unpack('<I',d[rva:rva+4])[0]; p=rva+4; mods=[]
def rstr(off): ln=struct.unpack('<I',d[off:off+4])[0]; return d[off+4:off+4+ln].decode('utf-16-le','replace')
for i in range(nm_):
    base=struct.unpack('<Q',d[p:p+8])[0]; sz=struct.unpack('<I',d[p+8:p+12])[0]
    nm=rstr(struct.unpack('<I',d[p+20:p+24])[0]).split('\\')[-1]; mods.append((base,base+sz,nm)); p+=108
mem=[]; ds,rva=S[9]; n=struct.unpack('<Q',d[rva:rva+8])[0]; base=struct.unpack('<Q',d[rva+8:rva+16])[0]
off=base; q=rva+16
for i in range(n):
    va=struct.unpack('<Q',d[q:q+8])[0]; sz=struct.unpack('<Q',d[q+8:q+16])[0]; q+=16
    mem.append((va,off,sz)); off+=sz
mem.sort()
import bisect
starts=[m[0] for m in mem]
def read8(va):
    i=bisect.bisect_right(starts,va)-1
    if i>=0:
        s,o,sz=mem[i]
        if s<=va<s+sz-7: return struct.unpack('<Q',d[o+(va-s):o+(va-s)+8])[0]
    return None
# BambuStudio.dll writable RVA ranges
WR=[(0x62b5000,0x6554108),(0x6829000,0x682ccf0)]
def modinfo(v):
    for lo,hi,nm in mods:
        if lo<=v<hi: return nm,v-lo
    return None
bs=[m for m in mods if m[2].lower()=='bambustudio.dll'][0]
lo,hi=int(sys.argv[2]),int(sys.argv[3])
print("data()=0x%x scan k=%d..%d"%(rax,lo,hi))
hits=0; modptr=0
for k in range(lo,hi):
    v=read8(rax+k*8)
    if v is None: continue
    mi=modinfo(v)
    if not mi: continue
    modptr+=1
    tgt=v+0x1e8
    ti=modinfo(tgt)
    # is tgt writable in BambuStudio.dll?
    if ti and ti[0].lower()=='bambustudio.dll':
        rva=ti[1]
        if any(a<=rva<b for a,b in WR):
            print("  *** k=%-7d P=0x%x (%s+0x%x)  P+0x1e8 -> %s+0x%x  [WRITABLE .data]"%(k,v,mi[0],mi[1],ti[0],rva)); hits+=1
print("module-ptr slots=%d  writable-target hits=%d"%(modptr,hits))
d.close()
