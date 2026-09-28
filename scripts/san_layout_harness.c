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
PIC_RESOLVE_STATUS PIC_MS_ABI pic_find_module(PIC_CONTEXT *ctx,
                                              const PIC_HASH *hash,
                                              void **out)
{
    (void)ctx; (void)hash; *out = NULL;
    return PIC_RESOLVE_MODULE_NOT_FOUND;
}

pic_bool PIC_MS_ABI margaret_locate_chrome_dll(PIC_CONTEXT *ctx,
                                               void **base,
                                               pic_u32 *size)
{
    (void)ctx; (void)base; (void)size;
    return PIC_FALSE;
}

/* fake VirtualQuery: every host pointer is committed, readable, RW */
static pic_uptr PIC_MS_ABI fake_vq(const void *address,
                                   PIC_CC_MBI *info,
                                   pic_size length)
{
    (void)address; (void)length;
    memset(info, 0, sizeof(*info));
    info->State = MEM_COMMIT;
    info->Protect = 0x04u; /* PAGE_READWRITE */
    return 1u;
}

/* --- synthetic CanonicalCookie construction ------------------------- */

typedef struct {
    uint32_t off_name, off_domain, off_path;
    uint32_t off_creation, off_expiry;
    uint32_t off_same, off_port;
    uint32_t off_value, off_flag;
} LAYOUT;

static void wq(uint8_t *c, uint32_t off, uint64_t v)
{
    for (int i = 0; i < 8; i++) c[off + (uint32_t)i] = (uint8_t)(v >> (8 * i));
}

static void wu32(uint8_t *c, uint32_t off, uint32_t v)
{
    for (int i = 0; i < 4; i++) c[off + (uint32_t)i] = (uint8_t)(v >> (8 * i));
}

/* libc++ short string exactly as the shipped reader decodes it */
static void wsso(uint8_t *c, uint32_t off, const char *s)
{
    size_t n = strlen(s);
    memset(c + off, 0, 24);
    memcpy(c + off, s, n);
    c[off + 23] = (uint8_t)n; /* len in low 7 bits, bit 7 clear */
}

static uint8_t *make_cookie(const LAYOUT *L, const char *name,
                            int session, int obf)
{
    uint8_t *c = (uint8_t *)calloc(1, 0x180);
    if (!c) abort();

    wq(c, 0, 0x00007FF600000000ull); /* any qword: unused by the calibrator */
    wsso(c, L->off_name, name);
    wsso(c, L->off_domain, ".google.com");
    wsso(c, L->off_path, "/");

    /* real shape (live .58 dump): a single strict Time (creation) at
     * 0x50; expiry Time only for persistent cookies, zero otherwise */
    wq(c, L->off_creation, 13300000000000000ull);
    wq(c, L->off_expiry, session ? 0u : 13450000000000000ull);

    if (L->off_same) wu32(c, L->off_same, 1u);
    if (L->off_port) wu32(c, L->off_port, 443u);

    if (obf == 1) {
        /* crypto::ProcessBound: {ptr, len, cap, ...} holding ciphertext
         * (non-printable) — NOT a libc++ string, no long marker byte */
        uint8_t *ct = (uint8_t *)malloc(48);
        if (!ct) abort();
        for (int i = 0; i < 48; i++) ct[i] = (uint8_t)(i & 0x1Fu);
        wq(c, L->off_value, (uint64_t)(uintptr_t)ct);
        wq(c, L->off_value + 8u, 48u);
        wq(c, L->off_value + 16u, 48u);
        c[L->off_flag] = 1u;
    } else if (obf == 2) {
        /* EMPTY value: null ProcessBound */
        c[L->off_flag] = 0u;
    } else {
        /* plaintext long value in a ProcessBound with flag 0 */
        uint8_t *pt = (uint8_t *)malloc(32);
        if (!pt) abort();
        for (int i = 0; i < 31; i++) pt[i] = (uint8_t)('a' + (i % 26));
        pt[31] = 0;
        wq(c, L->off_value, (uint64_t)(uintptr_t)pt);
        wq(c, L->off_value + 8u, 31u);
        wq(c, L->off_value + 16u, 31u);
        c[L->off_flag] = 0u;
    }
    return c;
}

static int check(const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("  FAIL %s: got 0x%X want 0x%X\n", what, got, want);
        return 1;
    }
    return 0;
}

static int run_variant(const char *tag, const LAYOUT *L,
                       int with_session, int expect_ok)
{
    const uint8_t *sample[6];
    PIC_CC_LAYOUT lay;
    int bad = 0;

    sample[0] = make_cookie(L, "SID", 0, 1);
    sample[1] = make_cookie(L, "HSID", with_session ? 1 : 0, 1);
    sample[2] = make_cookie(L, "NID", 0, 0);
    sample[3] = make_cookie(L, "__Secure-1PSID", 0, 1);
    sample[4] = make_cookie(L, "APISID", with_session ? 1 : 0, 1);
    sample[5] = make_cookie(L, "SSID", 0, 0);

    memset(&lay, 0, sizeof(lay));
    {
        pic_bool ok = margaret_cc_calibrate(sample, 6u, fake_vq, &lay, NULL);
        if (expect_ok && !ok) {
            printf("[%s] FAIL: calibrator rejected a valid layout\n", tag);
            return 1;
        }
        if (!expect_ok) {
            if (ok) {
                printf("[%s] FAIL: calibrator accepted a corrupt layout\n", tag);
                return 1;
            }
            printf("[%s] PASS (fail-closed as required)\n", tag);
            return 0;
        }
        bad += check("name", lay.off_name, L->off_name);
        bad += check("domain", lay.off_domain, L->off_domain);
        bad += check("path", lay.off_path, L->off_path);
        bad += check("value", lay.off_value, L->off_value);
        bad += check("flag", lay.off_flag, L->off_flag);
        bad += check("creation", lay.off_creation, L->off_creation);
        bad += check("expiry", lay.off_expiry, L->off_expiry);
        bad += check("same_site", lay.off_same_site, L->off_same);
        bad += check("port", lay.off_port, L->off_port);
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

    bad += run_variant("worksheet-152-154 (mixed session/persistent)",
                       &worksheet, 1, 1);
    bad += run_variant("worksheet-152-154 (all persistent)",
                       &worksheet, 0, 1);
    bad += run_variant("shifted-tail (mixed)", &shifted, 1, 1);

    /* real-jar shape: empty values and one empty name mixed into the
     * sample — the quorum must absorb them */
    {
        static const LAYOUT wk = {
            0x08u, 0x20u, 0x38u, 0x50u, 0x78u, 0xD8u, 0xDCu, 0xE0u, 0x108u,
        };
        const uint8_t *sample[8];
        PIC_CC_LAYOUT lay;
        int bad2 = 0;
        sample[0] = make_cookie(&wk, "SID", 0, 1);
        sample[1] = make_cookie(&wk, "HSID", 1, 1);
        sample[2] = make_cookie(&wk, "NID", 0, 0);
        sample[3] = make_cookie(&wk, "__Secure-1PSID", 0, 1);
        sample[4] = make_cookie(&wk, "showdetails-search", 0, 2); /* empty val */
        sample[5] = make_cookie(&wk, "rog_close_advert", 0, 2);    /* empty val */
        sample[6] = make_cookie(&wk, "", 0, 2);                    /* empty name+val */
        sample[7] = make_cookie(&wk, "APISID", 1, 1);
        memset(&lay, 0, sizeof(lay));
        if (!margaret_cc_calibrate(sample, 8u, fake_vq, &lay, NULL)) {
            printf("[real-jar empties] FAIL: rejected a valid layout\n");
            bad++;
        } else {
            bad2 += check("name", lay.off_name, wk.off_name);
            bad2 += check("domain", lay.off_domain, wk.off_domain);
            bad2 += check("path", lay.off_path, wk.off_path);
            bad2 += check("value", lay.off_value, wk.off_value);
            bad2 += check("flag", lay.off_flag, wk.off_flag);
            bad2 += check("creation", lay.off_creation, wk.off_creation);
            bad2 += check("expiry", lay.off_expiry, wk.off_expiry);
            bad2 += check("same_site", lay.off_same_site, wk.off_same);
            bad2 += check("port", lay.off_port, wk.off_port);
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
        PIC_CC_LAYOUT lay;
        int bad2 = 0;
        sample[0] = make_cookie(&wk, "evn_client_key", 1, 1);
        sample[1] = make_cookie(&wk, "g_state", 1, 1);
        sample[2] = make_cookie(&wk, "other1", 1, 1);
        sample[3] = make_cookie(&wk, "other2", 1, 1);
        sample[4] = make_cookie(&wk, "other3", 1, 2);
        sample[5] = make_cookie(&wk, "other4", 1, 1);
        sample[6] = make_cookie(&wk, "other5", 1, 0);
        sample[7] = make_cookie(&wk, "other6", 1, 1);
        memset(&lay, 0, sizeof(lay));
        if (!margaret_cc_calibrate(sample, 8u, fake_vq, &lay, NULL)) {
            printf("[extension all-session] FAIL: rejected\n");
            bad++;
        } else {
            bad2 += check("name", lay.off_name, wk.off_name);
            bad2 += check("domain", lay.off_domain, wk.off_domain);
            bad2 += check("path", lay.off_path, wk.off_path);
            bad2 += check("value", lay.off_value, wk.off_value);
            bad2 += check("flag", lay.off_flag, wk.off_flag);
            bad2 += check("creation", lay.off_creation, wk.off_creation);
            bad2 += check("expiry=0", lay.off_expiry, 0u);
            bad2 += check("same_site", lay.off_same_site, wk.off_same);
            bad2 += check("port", lay.off_port, wk.off_port);
            printf("[extension all-session] %s\n", bad2 ? "FAIL" : "PASS");
            bad += bad2;
        }
    }

        /* corrupt the path of MORE than a quorum of cookies (one bad
         * cookie is inside the tolerated minority by design): the
         * calibrator must fail closed */
        const uint8_t *sample[4];
        PIC_CC_LAYOUT lay;
        uint8_t *c0 = make_cookie(&corrupt, "A", 0, 1);
        uint8_t *c1 = make_cookie(&corrupt, "B", 1, 1);
        c0[corrupt.off_path] = (uint8_t)'x';
        c1[corrupt.off_path] = (uint8_t)'y';
        sample[0] = c0;
        sample[1] = c1;
        sample[2] = make_cookie(&corrupt, "C", 0, 0);
        sample[3] = make_cookie(&corrupt, "D", 0, 1);
        memset(&lay, 0, sizeof(lay));
        if (margaret_cc_calibrate(sample, 4u, fake_vq, &lay, NULL)) {
            printf("[corrupt-path majority] FAIL: accepted\n");
            bad++;
        } else {
            printf("[corrupt-path majority] PASS (fail-closed)\n");
        }

        /* a single corrupt cookie is the tolerated minority: the
         * layout must still calibrate */
        {
            uint8_t *c = make_cookie(&corrupt, "SID", 0, 1);
            const uint8_t *s2[4];
            c[corrupt.off_path] = (uint8_t)'x';
            s2[0] = make_cookie(&corrupt, "A", 0, 1);
            s2[1] = make_cookie(&corrupt, "B", 1, 1);
            s2[2] = make_cookie(&corrupt, "C", 0, 0);
            s2[3] = c;
            memset(&lay, 0, sizeof(lay));
            if (!margaret_cc_calibrate(s2, 4u, fake_vq, &lay, NULL)) {
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
