import sys, struct, mmap
f=open(sys.argv[1],'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
ns=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]; S={}
for i in range(ns):
    st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); S.setdefault(st,(ds,rva))
ds,rva=S[6]; b=d[rva:rva+ds]; csz,crva=struct.unpack('<II',b[160:168]); c=d[crva:crva+csz]
data=struct.unpack('<Q',c[0x78:0x80])[0]
ds,rva=S[9]; n=struct.unpack('<Q',d[rva:rva+8])[0]; base=struct.unpack('<Q',d[rva+8:rva+16])[0]
off=base; q=rva+16; ranges=[]
for i in range(n):
    va=struct.unpack('<Q',d[q:q+8])[0]; sz=struct.unpack('<Q',d[q+8:q+16])[0]; q+=16
    ranges.append((va,off,sz)); off+=sz
MK=b'\x41'*8
import sys as _s
outp=open(sys.argv[2],'w')
cnt=0
for va,o,sz in ranges:
    chunk=d[o:o+sz]; idx=0
    while True:
        j=chunk.find(MK,idx)
        if j<0: break
        a=va+j
        if (a-data)%8==0:
            vid=(a-data)//8
            if -0x80000000<=vid<0x80000000: outp.write("%d\n"%vid); cnt+=1
        idx=j+1
outp.close()
print("data()=0x%x hits=%d -> %s"%(data,cnt,sys.argv[2]))
d.close()
