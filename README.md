# Margaret Stealer

**Margaret** is a compact, position-independent x64 shellcode that extracts cookies — with fully de-obfuscated values — from a live Chrome *network utility* process. It walks the in-memory cookie store and invokes Chrome's own per-process de-obfuscation routine, so plaintext values are recovered by the process itself: no disk access, no DevTools, no attack on at-rest encryption (DPAPI / App-Bound).

Margaret is a **capability, not an implant**: no C2 endpoint, no persistence, no network code, no strings.

> I designed this stealer to be C2-agnostic — red teams and researchers should adapt it to their specific needs and frameworks. The delivery is yours.

> Research project for authorized testing environments only.

## Architecture

| Component | Role |
|---|---|
| `src/`, `asm/`, `linker/` | The blob: freestanding C + a minimal entry stub, linked as a single ordered `.text` with strict static gates. Zero imports, zero strings, zero writable globals; every API is resolved at runtime by dual-32 hashing. |
| `src/adapter.c` | **Runtime discovery** — the blob self-locates the two anchors it needs by byte-pattern chains on the live module; no per-build table ships in the blob. |
| `loader/` | The delivery component: a standalone injector via thread-context hijacking. Has its own [README](loader/README.md). Swap it for your own — the blob is delivery-agnostic. |
| `scripts/` + gates | Deterministic build pipeline: three static gates (objects / linked image / raw blob) abort the build on any violation; compile-time needle encryption; reproducible output. |

Building (Linux host, MinGW-w64 cross toolchain):

```bash
make shellcode      # blob + all gates (fail-closed)
make loader         # quiet loader (string-free)
make loader-verbose # dev loader with diagnostics
```

## How it works — in brief

The network utility process keeps every cookie in RAM inside `CookieMonster` objects; since recent versions, the values are stored encrypted with a **process-bound key** that never touches disk. Margaret reaches them by:

1. **Reverse engineering** pinned builds (Ghidra for structure, x64dbg hardware breakpoints to catch Chrome de-obfuscating a live value) identified two anchors: the `CookieMonster` vtable and Chrome's de-obfuscation function (`crypto::ProcessBound<std::string>::value()`).
2. Locating them **without per-build tables** meant finding what recompilation cannot change. Two compiler invariants, located at runtime by byte-pattern scanning, carry the whole approach:
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
4. A live lesson killed the table idea for good: a `.57`→`.58` auto-update shared an identical image size and shifted code, handing a pinned RVA mid-instruction. Nothing per-build is trusted anymore — the discovered de-obfuscator must open with its family prologue `41 57 41 56 41 55 41 54` (`push r15/r14/r13/r12`), the vtable slots must land in-module, and the layout itself is calibrated per run (next point).
5. **The cookie structure is calibrated at runtime too** (`src/cc_layout.c`): a sample of live cookies yields every field offset through cross-instance invariants — the libc++ string grid, path starting `/`, domain containing `.`, the ProcessBound value block (non-printable ciphertext), its flag at `value+0x28`, creation as the minimum plausible timestamp, session/persistent expiry, the bounded enum/port pair. Every step is a strict-majority quorum that tolerates legal oddities (empty values, empty names) and fails closed on ambiguity.

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
| 153.0.8010.53 | CFT/stable | discovery | offline + live extraction |
| 154.0.8037.0 | trunk | discovery | offline, PDB 8/8 slot match |
| 154.0.8037.57 | CFT/stable | discovery | offline + **live extraction on host** |
| 154.0.8037.58 | stable | discovery | extracted after an auto-update, layout recalibrated |
| 156.0.8076.0 | canary | discovery | **live extraction**, never pinned — pure discovery |

Windows 11 24H2 x64 is the validated matrix.

## Limitations

- Validated on Windows 11 24H2 x64 only; other versions need revalidation of the loader offsets.
- The cookie layout is calibrated per run from live bytes; a struct change that breaks an invariant fails closed with `UNSUPPORTED_BUILD` instead of misreading.
- Discovery relies on two compiler invariants (the method-name string and the value-read shape); a future Chrome refactor that breaks either fails closed with `UNSUPPORTED_BUILD`.
- secure/httponly are calibrated by RFC 6265bis name-prefix evidence (`__Secure-`, `__Host-` force Secure); when the vote does not converge the flags serialize as 0 and the prefix rules still hold.
- No CDP, no DPAPI/ABE attack, no persistence, no C2 — by design.
- **Per-value heap leak (accepted cost):** each de-obfuscated long value (>22 bytes — the common case) leaves one `std::string` heap allocation behind in the network utility process (the sret buffer is never destroyed). The footprint is bounded by the cookie count and dies with the process; proper teardown would need a third discovered anchor (the string destructor).
- **Timeout granularity:** the scan timeout is evaluated between `VirtualQuery` regions; a single region's inner scan (max 256 MB) cannot be interrupted, so the effective bound can overshoot `timeout_ms` by seconds. Committed regions larger than 256 MB are scanned only up to that bound.
- **Hijack-point risk:** the victim thread is suspended at an arbitrary point. If it holds an allocator lock or the per-process key lock that the de-obfuscator's path re-acquires, the call deadlocks — the loader timeout observes it, but the thread stays wedged. Thread selection maximizes stack headroom, not lock safety.
- **No unwind across the blob:** unwind metadata is deliberately absent. If resolved Chrome code ever throws (e.g. `bad_alloc` on a long value), unwinding cannot cross the blob's frames and the process crashes. `ProcessBound::Value()` is not expected to throw; the risk is documented, not handled.

