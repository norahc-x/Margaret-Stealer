# Runtime discovery — visual walkthrough

How the blob orients itself on **any** Chrome build with zero per-build
knowledge. Nothing here is memorized: every anchor and every struct
offset is derived from the bytes of the build actually in memory, at
every execution. Two layers:

1. **Anchor discovery** (`src/adapter.c`) — where the CookieMonster
   vtable and Chrome's de-obfuscation routine live in `chrome.dll`;
2. **Per-run layout calibration** (`src/cc_layout.c`) — where every
   field lives inside the cookie objects themselves.

Every diamond is a fail-closed gate: ambiguity selects nothing.

## 1 — Anchor discovery (byte-pattern chains on the DLL)

```mermaid
flowchart TD
    START(["chrome.dll located<br/>(PEB walk, bounded module list)"]) --> NEEDLE
    START --> SCAN

    subgraph CHAIN2["Chain A — string-pattern search → vtable"]
        NEEDLE["decrypt needle on stack<br/>(chained-XOR, compile-time key)"]
        NEEDLE --> N1{"CookieMonster::<br/>GetCookieListWithOptionsAsync<br/>exactly once in .rdata?"}
        N1 -- no --> FAIL
        N1 -- yes --> N2{"exactly one rip-relative<br/>lea xref in .text?"}
        N2 -- "no / >1" --> FAIL
        N2 -- yes --> N3["the xref lives inside the method<br/>⇒ its start IS vtable slot 3"]
        N3 --> N4["vtable = slot3 − 24<br/>verify slots 0,4 point into .text"]
        N4 --> VT(["vtable RVA"])
    end

    subgraph CHAIN1["Chain B — code-shape matching → de-obfuscator"]
        SCAN["scan .text for the value-read shape"]
        SCAN --> S1["80 ?? 08 01 00 00 ??<br/>cmp byte [reg+0x108], imm"]
        S1 --> S2{"within 56 bytes:<br/>48 8D ?? E0 00 00 00<br/>or add rcx, 0xE0 ?"}
        S2 -- no --> SKIP["skip site"]
        SKIP --> SCAN
        S2 -- yes --> S3["E8 ?? ?? ?? ??<br/>→ tally the call target"]
        S3 --> SCAN
        SCAN --> VOTE{"strict majority?<br/>≥3 votes, beats runner-up"}
        VOTE -- no --> FAIL
        VOTE -- yes --> JUNK{"winner prologue:<br/>41 57 41 56 41 55 41 54<br/>(push r15/r14/r13/r12)<br/>and not ret / int3 ?"}
        JUNK -- no --> FAIL
        JUNK -- yes --> DEOBF(["de-obfuscator RVA<br/>= crypto::ProcessBound&lt;std::string&gt;::value()"])
    end

    VT --> ASSEMBLE
    DEOBF --> ASSEMBLE{"assemble runtime adapter<br/>(nothing per-build shipped)"}
    ASSEMBLE -- "any gate failed" --> FAIL
    ASSEMBLE -- ok --> NEXT(["memory scan for CookieMonster<br/>instances → tree walk →<br/>layout calibration (next diagram)"])

    FAIL(["UNSUPPORTED_BUILD<br/>fail-closed, nothing selected"])
```

## 2 — Per-run cookie layout calibration (`src/cc_layout.c`)

The walk starts, but **nothing is serialized yet**: the first cookies
are stashed and the struct map is derived from their bytes by
cross-instance invariants, under a strict-majority quorum (> n/2) that
tolerates legal oddities (empty values, empty names, a corrupt cookie).

```mermaid
flowchart TD
    STASH(["stash first cookies<br/>(≤16, nothing serialized)"]) --> ATTEMPT
    ATTEMPT{"calibrate on<br/>growing sample 4…16"}
    ATTEMPT -- fail --> MORE{"more cookies?"}
    MORE -- yes --> STASH2["grow sample"] --> ATTEMPT
    MORE -- "no / 16 failed" --> FAIL(["UNSUPPORTED_BUILD<br/>zero cookies emitted"])

    ATTEMPT -- ok --> G1

    subgraph GRID["the string grid"]
        G1{"valid libc++ string at offset<br/>for a quorum of cookies?<br/>(SSO: printable, len 1–22 ·<br/>long: heap ptr + len 23–4096)"}
        G1 -- "≥3 candidates" --> G2{"path: first byte '/'<br/>in a quorum — unique?"}
        G2 -- no --> FAIL
        G2 -- yes --> G3{"domain: contains '.'<br/>in a quorum — unique?"}
        G3 -- no --> FAIL
        G3 -- yes --> G4{"name/domain/path are three<br/>consecutive 24-byte strings<br/>(stride 0x18)?"}
        G4 -- no --> FAIL
    end

    G4 -- yes --> V1

    subgraph PB["the ProcessBound value"]
        V1{"plausible heap ptr + len 1–4096<br/>at offset, for a quorum —<br/>and ciphertext (non-printable)<br/>in ≥1 cookie — unique?"}
        V1 -- no --> FAIL
        V1 -- yes --> V2{"flag at value+0x28 equals the<br/>ciphertext indicator<br/>for a quorum?"}
        V2 -- no --> FAIL
    end

    V2 -- yes --> T1

    subgraph TIMES["the timestamps"]
        T1{"Time-like qwords<br/>(µs since 1601, years 2008–2100)<br/>for a quorum?"}
        T1 -- none --> FAIL
        T1 -- ok --> T2["creation = per-cookie minimum<br/>(lowest offset among min-holders)"]
        T2 --> T3["expiry = mixed zero/Time signature,<br/>else strict-ahead Time,<br/>else best-effort 0"]
    end

    T3 --> SP{"same_site/port pair at value−8<br/>bounded (enum ≤3, port ≤0xFFFF)<br/>for a quorum?"}
    SP -- "no → serialize as 0" --> LAYOUT
    SP -- yes --> LAYOUT(["layout calibrated:<br/>9 offsets derived from live bytes"])

    LAYOUT --> FLUSH["flush the stash, then serialize<br/>every cookie with the calibrated map"]
    FLUSH --> FLAGS["secure_/httponly: per-cookie evidence from<br/>RFC 6265bis prefixes (__Secure-, __Host-<br/>force Secure); non-converged → flags 0,<br/>prefix rules still hold"]
    FLAGS --> OUT(["MCEA output"])
```

## Why per-run

A patch-level rebuild that moves a field (the `.57` → `.58` lesson:
identical image size, code shifted) cannot make the engine misread:
either the invariants hold on the new bytes and the new layout is
derived correctly, or they do not and the run fails closed. The failure
mode went from *silently corrupted cookies* to *refuses to guess*.
