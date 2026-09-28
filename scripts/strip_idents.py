#!/usr/bin/env python3
"""strip_idents.py — zero out compiler-ident strings (same-length, offsets
preserved).  The MinGW CRT objects carry .ident records ("GCC: (GNU) x.y.z")
that the linker merges into .rdata and -s cannot remove; they are never read
at runtime.

    python3 scripts/strip_idents.py <binary>
"""
import pathlib
import re
import sys

pat = re.compile(rb"GCC: \(GNU\) [0-9.]+")

for arg in sys.argv[1:]:
    p = pathlib.Path(arg)
    d = bytearray(p.read_bytes())
    n = 0
    for m in pat.finditer(d):
        d[m.start():m.end()] = b"\x00" * (m.end() - m.start())
        n += 1
    p.write_bytes(d)
    print(f"[idents] {arg}: {n} compiler idents zeroed")
