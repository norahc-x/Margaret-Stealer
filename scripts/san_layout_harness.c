/*
 * san_layout_harness.c — ASan/UBSan host harness for the CanonicalCookie
 * layout calibration (src/engine_a.c, byte-identical TU).
 *
 * Builds synthetic cookies for three struct layouts — the worksheet
 * build (152-154), a hypothetically shifted rebuild, and a corrupted
 * one — then runs the exact runtime calibrator and asserts it recovers
 * every offset (or fails closed where it must).
 *
 * Build:
 *   gcc -fsanitize=address,undefined -O1 -g -Iinclude \
 *       scripts/san_layout_harness.c src/runtime.c -o build/san_layout
 *
 * Exit 0 = all variants matched expectations, sanitizers silent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* the exact shipped calibration TU (statics become visible) */
#include "../src/cc_layout.c"

/* stubs: the resolver chain is never exercised by the calibrator */
RESOLVE_STATUS MS_ABI FindModule(RESOLVER_CONTEXT *ctx,
                                              const API_HASH *hash,
                                              PVOID*out)
{
    (void)ctx; (void)hash; *out = NULL;
    return ResolveStatusModuleNotFound;
}

BOOL MS_ABI MargaretLocateChromeDll(RESOLVER_CONTEXT *ctx,
                                               PVOID*base,
                                               PDWORD size)
{
    (void)ctx; (void)base; (void)size;
    return FALSE;
}

/* fake VirtualQuery: every host pointer is committed, readable, RW */
static ULONG_PTR MS_ABI FakeVq(PCVOID address,
                                   MEMORY_BASIC_INFORMATION *info,
                                   SIZE_T length)
{
    (void)address; (void)length;
    memset(info, 0, sizeof(*info));
    info->State = MEM_COMMIT;
    info->Protect = 0x04u; /* PAGE_READWRITE */
    return 1u;
}

/* --- synthetic CanonicalCookie construction ------------------------- */

typedef struct {
    uint32_t OffName, OffDomain, OffPath;
    uint32_t OffCreation, OffExpiry;
    uint32_t OffSame, OffPort;
    uint32_t OffValue, OffFlag;
} LAYOUT;

static void wq(uint8_t *c, uint32_t off, uint64_t v)
{
    for (int i = 0; i < 8; i++) c[off + (uint32_t)i] = (uint8_t)(v >> (8 * i));
}

static void Wu32(uint8_t *c, uint32_t off, uint32_t v)
{
    for (int i = 0; i < 4; i++) c[off + (uint32_t)i] = (uint8_t)(v >> (8 * i));
}

/* libc++ short string exactly as the shipped reader decodes it */
static void Wsso(uint8_t *c, uint32_t off, const char *s)
{
    size_t n = strlen(s);
    memset(c + off, 0, 24);
    memcpy(c + off, s, n);
    c[off + 23] = (uint8_t)n; /* len in low 7 bits, bit 7 clear */
}

static uint8_t *MakeCookie(const LAYOUT *L, const char *name,
                            int session, int obf)
{
    uint8_t *c = (uint8_t *)calloc(1, 0x180);
    if (!c) abort();

    wq(c, 0, 0x00007FF600000000ull); /* any qword: unused by the calibrator */
    Wsso(c, L->OffName, name);
    Wsso(c, L->OffDomain, ".google.com");
    Wsso(c, L->OffPath, "/");

    /* real shape (live .58 dump): a single strict Time (creation) at
     * 0x50; expiry Time only for persistent cookies, zero otherwise */
    wq(c, L->OffCreation, 13300000000000000ull);
    wq(c, L->OffExpiry, session ? 0u : 13450000000000000ull);

    if (L->OffSame) Wu32(c, L->OffSame, 1u);
    if (L->OffPort) Wu32(c, L->OffPort, 443u);

    if (obf == 1) {
        /* crypto::ProcessBound: {ptr, len, cap, ...} holding ciphertext
         * (non-printable) — NOT a libc++ string, no long marker byte */
        uint8_t *ct = (uint8_t *)malloc(48);
        if (!ct) abort();
        for (int i = 0; i < 48; i++) ct[i] = (uint8_t)(i & 0x1Fu);
        wq(c, L->OffValue, (uint64_t)(uintptr_t)ct);
        wq(c, L->OffValue + 8u, 48u);
        wq(c, L->OffValue + 16u, 48u);
        c[L->OffFlag] = 1u;
    } else if (obf == 2) {
        /* EMPTY value: null ProcessBound */
        c[L->OffFlag] = 0u;
    } else {
        /* plaintext long value in a ProcessBound with flag 0 */
        uint8_t *pt = (uint8_t *)malloc(32);
        if (!pt) abort();
        for (int i = 0; i < 31; i++) pt[i] = (uint8_t)('a' + (i % 26));
        pt[31] = 0;
        wq(c, L->OffValue, (uint64_t)(uintptr_t)pt);
        wq(c, L->OffValue + 8u, 31u);
        wq(c, L->OffValue + 16u, 31u);
        c[L->OffFlag] = 0u;
    }
    return c;
}

static int Check(const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("  FAIL %s: got 0x%X want 0x%X\n", what, got, want);
        return 1;
    }
    return 0;
}

static int RunVariant(const char *tag, const LAYOUT *L,
                       int withSession, int expectOk)
{
    const uint8_t *sample[6];
    CC_LAYOUT lay;
    int bad = 0;

    sample[0] = MakeCookie(L, "SID", 0, 1);
    sample[1] = MakeCookie(L, "HSID", withSession ? 1 : 0, 1);
    sample[2] = MakeCookie(L, "NID", 0, 0);
    sample[3] = MakeCookie(L, "__Secure-1PSID", 0, 1);
    sample[4] = MakeCookie(L, "APISID", withSession ? 1 : 0, 1);
    sample[5] = MakeCookie(L, "SSID", 0, 0);

    memset(&lay, 0, sizeof(lay));
    {
        BOOL ok = MargaretCcCalibrate(sample, 6u, FakeVq, &lay, NULL);
        if (expectOk && !ok) {
            printf("[%s] FAIL: calibrator rejected a valid layout\n", tag);
            return 1;
        }
        if (!expectOk) {
            if (ok) {
                printf("[%s] FAIL: calibrator accepted a corrupt layout\n", tag);
                return 1;
            }
            printf("[%s] PASS (fail-closed as required)\n", tag);
            return 0;
        }
        bad += Check("name", lay.OffName, L->OffName);
        bad += Check("domain", lay.OffDomain, L->OffDomain);
        bad += Check("path", lay.OffPath, L->OffPath);
        bad += Check("value", lay.OffValue, L->OffValue);
        bad += Check("flag", lay.OffFlag, L->OffFlag);
        bad += Check("creation", lay.OffCreation, L->OffCreation);
        bad += Check("expiry", lay.OffExpiry, L->OffExpiry);
        bad += Check("same_site", lay.OffSameSite, L->OffSame);
        bad += Check("port", lay.OffPort, L->OffPort);
        printf("[%s] %s\n", tag, bad ? "FAIL" : "PASS");
    }
    return bad;
}

int main(void)
{
    /* worksheet layout, validated live on 152-154 */
    static const LAYOUT worksheet = {
        0x08u, 0x20u, 0x38u, 0x50u, 0x78u, 0xD8u, 0xDCu, 0xE0u, 0x108u,
    };
    /* hypothetical patch-level rebuild: tail shifted by 8 */
    static const LAYOUT shifted = {
        0x08u, 0x20u, 0x38u, 0x50u, 0x80u, 0xE0u, 0xE4u, 0xE8u, 0x110u,
    };
    /* corrupted: path does not start with '/' */
    static const LAYOUT corrupt = {
        0x08u, 0x20u, 0x38u, 0x50u, 0x78u, 0xD8u, 0xDCu, 0xE0u, 0x108u,
    };
    int bad = 0;

    bad += RunVariant("worksheet-152-154 (mixed session/persistent)",
                       &worksheet, 1, 1);
    bad += RunVariant("worksheet-152-154 (all persistent)",
                       &worksheet, 0, 1);
    bad += RunVariant("shifted-tail (mixed)", &shifted, 1, 1);

    /* real-jar shape: empty values and one empty name mixed into the
     * sample — the quorum must absorb them */
    {
        static const LAYOUT wk = {
            0x08u, 0x20u, 0x38u, 0x50u, 0x78u, 0xD8u, 0xDCu, 0xE0u, 0x108u,
        };
        const uint8_t *sample[8];
        CC_LAYOUT lay;
        int bad2 = 0;
        sample[0] = MakeCookie(&wk, "SID", 0, 1);
        sample[1] = MakeCookie(&wk, "HSID", 1, 1);
        sample[2] = MakeCookie(&wk, "NID", 0, 0);
        sample[3] = MakeCookie(&wk, "__Secure-1PSID", 0, 1);
        sample[4] = MakeCookie(&wk, "showdetails-search", 0, 2); /* empty val */
        sample[5] = MakeCookie(&wk, "rog_close_advert", 0, 2);    /* empty val */
        sample[6] = MakeCookie(&wk, "", 0, 2);                    /* empty name+val */
        sample[7] = MakeCookie(&wk, "APISID", 1, 1);
        memset(&lay, 0, sizeof(lay));
        if (!MargaretCcCalibrate(sample, 8u, FakeVq, &lay, NULL)) {
            printf("[real-jar empties] FAIL: rejected a valid layout\n");
            bad++;
        } else {
            bad2 += Check("name", lay.OffName, wk.OffName);
            bad2 += Check("domain", lay.OffDomain, wk.OffDomain);
            bad2 += Check("path", lay.OffPath, wk.OffPath);
            bad2 += Check("value", lay.OffValue, wk.OffValue);
            bad2 += Check("flag", lay.OffFlag, wk.OffFlag);
            bad2 += Check("creation", lay.OffCreation, wk.OffCreation);
            bad2 += Check("expiry", lay.OffExpiry, wk.OffExpiry);
            bad2 += Check("same_site", lay.OffSameSite, wk.OffSame);
            bad2 += Check("port", lay.OffPort, wk.OffPort);
            printf("[real-jar empties] %s\n", bad2 ? "FAIL" : "PASS");
            bad += bad2;
        }
    }

    {
    /* extension-partition shape (the live failure): every cookie is a
     * session cookie — a single strict Time, expiry invisible in the
     * zero padding.  Calibrated layout must recover the triple, the
     * ProcessBound anchors and creation, with expiry best-effort 0. */
    {
        static const LAYOUT wk = {
            0x08u, 0x20u, 0x38u, 0x50u, 0x78u, 0xD8u, 0xDCu, 0xE0u, 0x108u,
        };
        const uint8_t *sample[8];
        CC_LAYOUT lay;
        int bad2 = 0;
        sample[0] = MakeCookie(&wk, "evn_client_key", 1, 1);
        sample[1] = MakeCookie(&wk, "g_state", 1, 1);
        sample[2] = MakeCookie(&wk, "other1", 1, 1);
        sample[3] = MakeCookie(&wk, "other2", 1, 1);
        sample[4] = MakeCookie(&wk, "other3", 1, 2);
        sample[5] = MakeCookie(&wk, "other4", 1, 1);
        sample[6] = MakeCookie(&wk, "other5", 1, 0);
        sample[7] = MakeCookie(&wk, "other6", 1, 1);
        memset(&lay, 0, sizeof(lay));
        if (!MargaretCcCalibrate(sample, 8u, FakeVq, &lay, NULL)) {
            printf("[extension all-session] FAIL: rejected\n");
            bad++;
        } else {
            bad2 += Check("name", lay.OffName, wk.OffName);
            bad2 += Check("domain", lay.OffDomain, wk.OffDomain);
            bad2 += Check("path", lay.OffPath, wk.OffPath);
            bad2 += Check("value", lay.OffValue, wk.OffValue);
            bad2 += Check("flag", lay.OffFlag, wk.OffFlag);
            bad2 += Check("creation", lay.OffCreation, wk.OffCreation);
            bad2 += Check("expiry=0", lay.OffExpiry, 0u);
            bad2 += Check("same_site", lay.OffSameSite, wk.OffSame);
            bad2 += Check("port", lay.OffPort, wk.OffPort);
            printf("[extension all-session] %s\n", bad2 ? "FAIL" : "PASS");
            bad += bad2;
        }
    }

        /* corrupt the path of MORE than a quorum of cookies (one bad
         * cookie is inside the tolerated minority by design): the
         * calibrator must fail closed */
        const uint8_t *sample[4];
        CC_LAYOUT lay;
        uint8_t *c0 = MakeCookie(&corrupt, "A", 0, 1);
        uint8_t *c1 = MakeCookie(&corrupt, "B", 1, 1);
        c0[corrupt.OffPath] = (uint8_t)'x';
        c1[corrupt.OffPath] = (uint8_t)'y';
        sample[0] = c0;
        sample[1] = c1;
        sample[2] = MakeCookie(&corrupt, "C", 0, 0);
        sample[3] = MakeCookie(&corrupt, "D", 0, 1);
        memset(&lay, 0, sizeof(lay));
        if (MargaretCcCalibrate(sample, 4u, FakeVq, &lay, NULL)) {
            printf("[corrupt-path majority] FAIL: accepted\n");
            bad++;
        } else {
            printf("[corrupt-path majority] PASS (fail-closed)\n");
        }

        /* a single corrupt cookie is the tolerated minority: the
         * layout must still calibrate */
        {
            uint8_t *c = MakeCookie(&corrupt, "SID", 0, 1);
            const uint8_t *s2[4];
            c[corrupt.OffPath] = (uint8_t)'x';
            s2[0] = MakeCookie(&corrupt, "A", 0, 1);
            s2[1] = MakeCookie(&corrupt, "B", 1, 1);
            s2[2] = MakeCookie(&corrupt, "C", 0, 0);
            s2[3] = c;
            memset(&lay, 0, sizeof(lay));
            if (!MargaretCcCalibrate(s2, 4u, FakeVq, &lay, NULL)) {
                printf("[corrupt-path minority] FAIL: rejected\n");
                bad++;
            } else {
                printf("[corrupt-path minority] PASS (tolerated)\n");
            }
        }
    }

    printf(bad ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return bad ? 1 : 0;
}
