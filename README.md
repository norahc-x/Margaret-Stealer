# Margaret Stealer

**Margaret** is a compact, position-independent x64 shellcode that extracts cookies — with fully de-obfuscated values — from a live Chrome *network utility* process. It walks the in-memory cookie store and invokes Chrome's own per-process de-obfuscation routine, so plaintext values are recovered by the process itself: no disk access, no DevTools, no attack on at-rest encryption (DPAPI / App-Bound).

Margaret is a **capability, not an implant**: no C2 endpoint, no persistence, no network code, no strings.

> I designed this stealer to be C2-agnostic — red teams and researchers should adapt it to their specific needs and frameworks. The delivery is yours.

> Research project for authorized testing environments only.

## Architecture

| Component | Role |
|---|---|
| `src/`, `asm/`, `linker/` | The blob: freestanding C + a minimal entry stub, linked as a single ordered `.text` with strict static gates. Zero imports, zero strings, zero writable globals; every API is resolved at runtime by dual-32 hashing. |
| `src/adapter.c` | Per-build anchor tables (encrypted at rest in the blob, decrypted on stack) plus **runtime cross-build discovery**: when no pinned table matches, the blob self-locates the two anchors it needs — see below. |
| `loader/` | The delivery component: a standalone injector via thread-context hijacking. Has its own [README](loader/README.md). Swap it for your own — the blob is delivery-agnostic. |
| `scripts/` + gates | Deterministic build pipeline: three static gates (objects / linked image / raw blob) abort the build on any violation; post-build encryption of the anchor tables and the discovery needles; reproducible output. |

Building (Linux host, MinGW-w64 cross toolchain):

```bash
make shellcode      # blob + all gates (fail-closed)
python3 scripts/encrypt_blob.py
make loader         # quiet loader (string-free)
make loader-verbose # dev loader with diagnostics
```

## How it works — in brief

The network utility process keeps every cookie in RAM inside `CookieMonster` objects; since recent versions, the values are stored encrypted with a **process-bound key** that never touches disk. Margaret reaches them by:

1. **Reverse engineering** pinned builds (Ghidra for structure, x64dbg hardware breakpoints to catch Chrome de-obfuscating a live value) identified two anchors: the `CookieMonster` vtable and Chrome's de-obfuscation function (`crypto::ProcessBound<std::string>::value()`).
2. Anchors were first shipped as **per-build tables**, fail-closed on any mismatch.
3. Making it **cross-build** meant finding what recompilation cannot change. Two compiler invariants, located at runtime by byte-pattern scanning, carry the whole approach:
   - **String-pattern search** — every build contains exactly one copy of the method-name string `CookieMonster::GetCookieListWithOptionsAsync`, referenced by exactly one piece of code. That code lives inside the method itself, and the method occupies a fixed vtable slot: string → code reference → function → slot index, so the vtable is located without ever being memorized.
   - **Code-shape matching** — every value read performs the same three-step gesture. The canonical site, as compiled inside Chrome's value accessor:

     ```asm
     cmp  byte ptr [rdi+0x108], 1   ; 80 BF 08 01 00 00 01    flag: value is obfuscated
     lea  rcx, [rdi+0xE0]           ; 48 8D 8F E0 00 00 00    &obfuscated value
     lea  rdx, [rsp+0x30]           ; 48 8D 54 24 30          &out string
     call <de-obfuscator>           ; E8 <rel32>              the anchor
     ```

     The scanner matches this shape with register wildcards — `80 ?? 08 01 00 00 ??` (flag check at `+0x108`), `48 8D ?? E0 00 00 00` or `add rcx, 0xE0` (value pointer at `+0xE0`), then `E8 ?? ?? ?? ??` — tallies the call target of every matching site across `.text`, and takes the strict-majority winner; junk targets are rejected by their first bytes (`ret`/`int3` stubs never win).

   Both run in-process on the loaded module, fail closed on any ambiguity, and let unseen builds work without repinning.
4. A live lesson hardened the gates: patch-level rebuilds can share an identical image size (proven by a `.57`→`.58` auto-update handing the engine a mid-function address), so pinned tables are validated structurally — vtable slots in-module and the de-obfuscator opening with its family prologue `41 57 41 56 41 55 41 54` (`push r15/r14/r13/r12`) — never by size alone.

A visual walkthrough of the runtime discovery — both chains, their byte
signatures and every fail-closed gate — lives in
[diagrams/discovery.md](diagrams/discovery.md).

A full technical write-up is planned.

## Tested builds

| Build | Type | Anchors via | Live validation |
|---|---|---|---|
| 152.0.7972.0 | trunk | discovery | offline, PDB ground truth |
| 152.0.7977.82 | CFT | discovery | offline |
| 153.0.8010.0 | trunk | discovery | offline, PDB ground truth |
| 153.0.8010.53 | CFT | pinned | live extraction |
| 153.0.8010.53 | stable | pinned | offline |
| 154.0.8037.0 | trunk | discovery | offline, PDB 8/8 slot match |
| 154.0.8037.57 | CFT | pinned | offline |
| 154.0.8037.57 | stable | pinned | **live extraction on host** |
| 154.0.8037.58 | stable | **runtime discovery** | extracted after an auto-update, no repin |

Windows 11 24H2 x64 is the validated matrix.

## Limitations

- Validated on Windows 11 24H2 x64 only; other versions need revalidation of the loader offsets.
- The cookie-structure layout is pinned to the 152–154 family; a layout change requires a signature-mask update.
- Discovery relies on two compiler invariants (the method-name string and the value-read shape); a future Chrome refactor that breaks either fails closed with `UNSUPPORTED_BUILD`.
- The secure/httponly attribute dword is not fully verified; authentication cookies are reconstructed from RFC 6265bis name-prefix rules (`__Secure-`, `__Host-`).
- No CDP, no DPAPI/ABE attack, no persistence, no C2 — by design.

