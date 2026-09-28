# Runtime anchor discovery — visual walkthrough

How the blob selects its two Engine anchors on any Chrome build:
the **pinned fast-path** and, when nothing matches, the two
**byte-pattern chains** described in the
[README](../README.md#how-it-works--in-brief). The de-obfuscator chain
locates `crypto::ProcessBound<std::string>::value()` — Chrome's
process-bound decryption routine — by recognizing the code that calls it.

```mermaid
flowchart TD
    START(["chrome.dll located<br/>(PEB walk)"]) --> PINNED

    subgraph PINNED["Pinned tables — fast path"]
        P1{"table matches?<br/>image_size + slot0/slot3 in-module<br/>+ prologue 41 57 41 56 41 55 41 54"}
    end

    P1 -- "yes" --> ANCHORS(["anchors ready<br/>(pinned)"])
    P1 -- "no table matches" --> NEEDLE

    subgraph CHAIN2["String-pattern search → vtable"]
        NEEDLE["decrypt needle on stack<br/>(chained-XOR, campaign key)"]
        NEEDLE --> N1{"CookieMonster::<br/>GetCookieListWithOptionsAsync<br/>exactly once in .rdata?"}
        N1 -- no --> FAIL
        N1 -- yes --> N2{"exactly one rip-relative<br/>lea xref in .text?"}
        N2 -- no / >1 --> FAIL
        N2 -- yes --> N3["the xref lives inside the method<br/>⇒ its start IS vtable slot 3"]
        N3 --> N4["vtable = slot − 24<br/>verify slots 0-2, 4 point into .text"]
        N4 --> VT["vtable RVA"]
    end

    subgraph CHAIN1["Code-shape matching → de-obfuscator"]
        SCAN["scan .text for the value-read shape"]
        SCAN --> S1["80 ?? 08 01 00 00 ??<br/>cmp byte [reg+0x108], imm"]
        S1 --> S2{"within 56 bytes:<br/>48 8D ?? E0 00 00 00<br/>or add rcx, 0xE0 ?"}
        S2 -- no --> SKIP["skip site"]
        S2 -- yes --> S3["E8 ?? ?? ?? ??<br/>→ tally the call target"]
        S3 --> SCAN
        SCAN --> VOTE{"strict majority?<br/>≥3 votes, beats runner-up"}
        VOTE -- no --> FAIL
        JUNK -- yes --> DEOBF["de-obfuscator RVA<br/>= crypto::ProcessBound&lt;std::string&gt;::value()"]
        JUNK -- no --> FAIL
    end

    VT --> ASSEMBLE
    DEOBF --> ASSEMBLE{"assemble runtime adapter<br/>(version 2)"}
    ASSEMBLE --> OK(["engine proceeds:<br/>find CookieMonster instances → walk → de-obfuscate"])
    ASSEMBLE -- "any gate failed" --> FAIL

    FAIL(["UNSUPPORTED_BUILD<br/>fail-closed, nothing selected"])
```

Every diamond is a fail-closed gate: ambiguity selects nothing.
