# ADMesh `solid`-name overflow — exploitation research (macOS / Apple Silicon)

This folder documents the exploitation research behind the one-line fix in
PR #12153 (bound the ASCII-STL `solid`-name `fscanf`). The bug is the unbounded
`fscanf(fp, " solid %[^\n]", solid_content)` into a 256-byte stack buffer in
`src/admesh/stlinit.cpp`, inherited by BambuStudio, OrcaSlicer and their vendor
forks (QIDIStudio here).

**Scope / authorization.** Security research on the author's own machine as part
of coordinated disclosure. The end-to-end code-execution demonstration runs under
**ASLR disabled** (a controlled harness, via `tooling/runoff.c`); it is not a
turnkey weapon against a shipped, ASLR-on install. See the "ASLR, examined"
section of `README_leakfree_qidi.md` for exactly why a no-leak, ASLR-on version
is blocked. The intent is to substantiate impact for the fix, not to arm attacks.

## What is here

- **`README_leakfree_qidi.md`** — the full writeup: the canary-bypassing C++
  virtual-call hijack in `ProgressDialog::Update`, the register-reload gadget that
  defeats the x0-as-string constraint, the buffer layout, the observer-free and
  reliability results (~19/20), and the ASLR analysis (partial overwrite blocked
  by the `fscanf` NUL terminator).

- **`exploit/`** — the QIDIStudio chain and how it was built.
  - `build_exploit.py` — single-address PoC STL (`system("touch /tmp/pwned")`).
  - `build_robust.py` — jitter-tolerant PoC (replicates each planted field across
    a +/-0x40 window to absorb x19 stack jitter); the reliable version.
  - `calib.py` — index-encoded name pattern; the observer's `[x19]` value pins the
    exact name offset at `x19` (=9288) and the stack address.
  - `sweep.py` — name-length sweep used to prove the partial-overwrite target.
  - `attack.stl`, `attack_robust.stl` — ready PoC inputs.
  - `scan*.py` — gadget searches over the disassembled `__text` (vtable-dispatch,
    register-reload, x0-adjust-then-branch, stack pivots, direct `system` sites).
  - `fire.sh` — launch + wait-for-payload harness.

- **`tooling/`** — instrumentation and environment.
  - `observer.c` — crash-handler dylib that dumps registers + pointer-target memory
    at the fault (the "eyes" used to pin every value); injected with `inject.py`.
  - `inject.py` — adds an `LC_LOAD_DYLIB` in header padding (with
    `disable-library-validation`) to observe an otherwise hardened binary.
  - `runoff.c` — `posix_spawn` launcher with ASLR disabled (the controlled harness).
  - `whereis.c` — prints boot-stable libc addresses (`system`, `popen`) to confirm
    per-boot stability.

- **`primitives/`** — building-block proofs on controlled targets.
  - `vuln.c` — minimal reproduction of the vulnerable parse.
  - `f1_ret2system2.c` — working ret2libc `/tmp/pwned` on a controlled harness
    (canary/ASLR context matched to the real binary).
  - `prove_partial.c` — partial-overwrite ASLR-bypass proof (region-local redirect).
  - `make_stl.py`, `build_f1a.py`, `f1a_solid_overflow_poc.py` — STL generators
    targeting real offsets (368 = saved return; the F1a `solid %[^\n]` form).

- **`headless-admesh/`** — a GUI-free harness that compiles the real
  `src/admesh/stlinit.cpp` against small stubs, so the raw overflow and saved-return
  control can be demonstrated deterministically without launching a slicer.

## One-line reproduction (controlled harness)

```
clang -O2 -o runoff tooling/runoff.c
rm -f /tmp/pwned
./runoff /path/to/QIDIStudio.app/Contents/MacOS/<bin> exploit/attack_robust.stl
ls -l /tmp/pwned
```

The fix in PR #12153 (`%255[^\n]`) closes the overflow and neutralizes this entire
chain at the source.
