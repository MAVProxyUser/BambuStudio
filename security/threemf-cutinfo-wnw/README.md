# 3MF `cut_information.xml` OOB vector index → controlled write-what-where

A second, **stronger** bug than the ADMesh `solid` name overflow (see
`../qidi-solid-name-rce/`): the 3MF importer indexes `model_object->volumes` with an
attacker-controlled `volume_id` read raw from `Metadata/cut_information.xml`, then writes
a `CutInfo` struct (built from attacker-controlled connector floats/type) through the
out-of-bounds pointer. This is a **controlled write-what-where**, not a crash/DoS.

```cpp
// src/libslic3r/Format/bbs_3mf.cpp  (cut-connector apply loop)
model_object->volumes[connector.volume_id]->cut_info =
    ModelVolume::CutInfo(type, radius, height, r_tolerance, h_tolerance, true);
```

Fixed upstream by BambuLab in `5829aa45f` ("FIX: validate cut connector volume_id and
type from cut_information.xml", 2026-08-22). Vulnerable in shipped releases that predate
that fix (BambuStudio ≤ v02.08.02.61 and same-vintage forks / QIDIStudio `qds_3mf.cpp`).

## Contents
- `PROOF_windows.md` — Win11, BambuStudio v2.8.2.61. Autonomous trigger (PsExec `-i 2`
  into the active console session — no double-click), the exact write site in
  `BambuStudio.dll` (`mov rdx,[rax+rcx*8]` → `movups [rdx+0x1e8],xmm1`), live proof that
  the 28-byte attacker-controlled write executes through the attacker-selected pointer,
  and the grooming analysis (Windows ASLR defeats the naive marker spray — 0 cross-run
  `vid` overlap, ~1.3 GB jitter).
- `PROOF_macos.md` — QIDIStudio arm64. Same primitive; ASLR-off heap is **deterministic**
  (identical run → identical `P`), making it the tractable target for reliable-`P`.
- `tooling/` — `build_spray.py` (marker-mesh spray 3mf generator), `winmarker*.py`
  (full-dump marker scanner / vid solver), `cutparse.py`/`ripmod.py`/`slotwalk.py`/
  `slotscan.py` (minidump/full-dump parsers), `wloop.py` (autonomous build→launch→dump→
  parse loop).

## Status
Write-what-where proven live and autonomously on both OSes: attacker-chosen fault
address (`data()+volume_id*8`), 28 controlled bytes at `P+0x1e8` (Win) / 16 at `P+0x1e0`
(macOS), the store executing through `P`, and reachable writable targets. The remaining
step for a single-shot payload is reliable control of `P` (heap grooming): deterministic
and in progress on macOS; ASLR-blocked via naive spray on Windows (needs an info leak or
precise same-size adjacent-allocation grooming).
