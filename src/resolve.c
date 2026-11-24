#define CODE_SECTION_NAME ".text$D"
#include "resolve.h"

/*
 * Byte-read PE/API-set parsing for x64. All traversals are bounded.
 * Forwarders use depth and cycle guards; API-set schema v6 fails closed.
 * Module-cache entries remain valid for one operation.
 */

static CODE_SECTION WORD ReadU16(const BYTE *data)
{
    return (WORD)((WORD)data[0] | ((WORD)data[1] << 8u));
}

static CODE_SECTION DWORD ReadU32(const BYTE *data)
{
    return (DWORD)((DWORD)data[0] |
                     ((DWORD)data[1] << 8u) |
                     ((DWORD)data[2] << 16u) |
                     ((DWORD)data[3] << 24u));
}

/* Compare both hash words. */
static CODE_SECTION BOOL HashEqual(const API_HASH *a, const API_HASH *b)
{
    return (a->Fnv == b->Fnv && a->Djb == b->Djb) ? TRUE : FALSE;
}

static CODE_SECTION BOOL HashIsZero(const API_HASH *h)
{
    return (h->Fnv == 0u && h->Djb == 0u) ? TRUE : FALSE;
}

static CODE_SECTION BYTE FoldU8(BYTE value)
{
    if (value >= (BYTE)'a' && value <= (BYTE)'z') {
        return (BYTE)(value - ((BYTE)'a' - (BYTE)'A'));
    }
    return value;
}

/* Fold ASCII a-z to A-Z in one UTF-16 unit. */
static CODE_SECTION WORD FoldU16(WORD value)
{
    if (value >= (WORD)'a' && value <= (WORD)'z') {
        return (WORD)(value - ((WORD)'a' - (WORD)'A'));
    }
    return value;
}

static CODE_SECTION BOOL RangeWithin(DWORD offset, DWORD length, DWORD limit)
{
    ULONGLONG end = (ULONGLONG)offset + (ULONGLONG)length;
    return end <= (ULONGLONG)limit ? TRUE : FALSE;
}

static CODE_SECTION RESOLVE_STATUS Fail(RESOLVER_CONTEXT *ctx, RESOLVE_STATUS code)
{
    ctx->LastError = (DWORD)code;
    return code;
}

/* Offsets into asserted mapped-image views. */
#define NT_FILE_OFF(field) \
    ((DWORD)offsetof(IMAGE_NT_HEADERS64, FileHeader) + \
     (DWORD)offsetof(IMAGE_FILE_HEADER, field))
#define NT_OPT_OFF(field) \
    ((DWORD)offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + \
     (DWORD)offsetof(IMAGE_OPTIONAL_HEADER64, field))
#define EXP_OFF(field) \
    ((DWORD)offsetof(IMAGE_EXPORT_DIRECTORY, field))

/* NT headers must start in the first page. */
#define PE_MAX_E_LFANEW 0x1000u

/* Validate a mapped PE32+ image and return image/export bounds. */
static CODE_SECTION RESOLVE_STATUS ValidateImage(PVOID moduleBase,
                                              PDWORD imageSize,
                                              PDWORD exportRva,
                                              PDWORD exportSize)
{
    const BYTE *base = (const BYTE *)moduleBase;
    DWORD lfanew;
    DWORD numberOfRva;
    DWORD sizeOfImage;
    DWORD directoryOffset;

    if (ReadU16(base) != IMAGE_DOS_SIGNATURE) {
        return ResolveStatusBadImage;
    }
    lfanew = (DWORD)ReadU32(
        base + (DWORD)offsetof(IMAGE_DOS_HEADER, e_lfanew));
    if (lfanew < (DWORD)sizeof(IMAGE_DOS_HEADER) ||
        lfanew > PE_MAX_E_LFANEW - (DWORD)sizeof(IMAGE_NT_HEADERS64) ||
        (lfanew & 3u) != 0u) {
        return ResolveStatusBadImage;
    }
    if (ReadU32(base + lfanew) != IMAGE_NT_SIGNATURE) {
        return ResolveStatusBadImage;
    }
    if (ReadU16(base + lfanew + NT_FILE_OFF(Machine)) !=
        IMAGE_FILE_MACHINE_AMD64) {
        return ResolveStatusBadImage;
    }
    if (ReadU16(base + lfanew + NT_OPT_OFF(Magic)) !=
        IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return ResolveStatusBadImage;
    }
    numberOfRva = ReadU32(base + lfanew + NT_OPT_OFF(NumberOfRvaAndSizes));
    if (numberOfRva <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return ResolveStatusBadImage;
    }
    sizeOfImage = ReadU32(base + lfanew + NT_OPT_OFF(SizeOfImage));
    if (sizeOfImage == 0u) {
        return ResolveStatusBadImage;
    }

    directoryOffset = lfanew + NT_OPT_OFF(DataDirectory) +
                       IMAGE_DIRECTORY_ENTRY_EXPORT *
                           (DWORD)sizeof(IMAGE_DATA_DIRECTORY);
    *exportRva = ReadU32(base + directoryOffset);
    *exportSize = ReadU32(base + directoryOffset + 4u);
    if (*exportRva == 0u ||
        *exportSize < (DWORD)sizeof(IMAGE_EXPORT_DIRECTORY) ||
        !RangeWithin(*exportRva, *exportSize, sizeOfImage)) {
        return ResolveStatusBadImage;
    }
    *imageSize = sizeOfImage;
    return ResolveStatusOk;
}

#define NAME_INVALID 0xFFFFFFFFu

/* Return a bounded export-name length, or NAME_INVALID. */
static CODE_SECTION DWORD ScanAsciiName(const BYTE *base,
                                    DWORD imageSize,
                                    DWORD nameRva)
{
    DWORD limit;
    DWORD index;

    if (nameRva == 0u || nameRva >= imageSize) {
        return NAME_INVALID;
    }
    limit = imageSize - nameRva;
    if (limit > MAX_EXPORT_NAME_BYTES) {
        limit = MAX_EXPORT_NAME_BYTES;
    }
    for (index = 0u; index < limit; ++index) {
        if (base[nameRva + index] == 0u) {
            return index == 0u ? NAME_INVALID : index;
        }
    }
    return NAME_INVALID;
}

/* Resolve an export RVA directly or through a guarded forwarder chain. */
static CODE_SECTION RESOLVE_STATUS ExportFinish(RESOLVER_CONTEXT *ctx,
                                            const BYTE *base,
                                            DWORD imageSize,
                                            DWORD dirRva,
                                            DWORD dirSize,
                                            DWORD functionRva,
                                            PVOID*address)
{
    if (functionRva == 0u) {
        return Fail(ctx, ResolveStatusExportNotFound);
    }
    if (functionRva >= imageSize) {
        return Fail(ctx, ResolveStatusBadImage);
    }

    if ((ULONGLONG)functionRva >= (ULONGLONG)dirRva &&
        (ULONGLONG)functionRva < (ULONGLONG)dirRva + (ULONGLONG)dirSize) {
        RESOLVE_STATUS status;
        DWORD forwarderLength;
        DWORD depth;
        API_HASH visitedHash;
        DWORD index;

        forwarderLength = ScanAsciiName(base, imageSize, functionRva);
        if (forwarderLength == NAME_INVALID) {
            return Fail(ctx, ResolveStatusBadImage);
        }

        depth = ctx->ForwardDepth + 1u;
        if (depth > MAX_FORWARD_DEPTH) {
            return Fail(ctx, ResolveStatusForwardDepth);
        }

        HashAsciiUpper(base + functionRva, forwarderLength,
                             &visitedHash);
        for (index = 0u; index < ctx->ForwardVisitedCount; ++index) {
            if (HashEqual(&ctx->ForwardVisited[index], &visitedHash) == TRUE) {
                return Fail(ctx, ResolveStatusForwardCycle);
            }
        }
        if (ctx->ForwardVisitedCount >= MAX_FORWARD_VISITED) {
            return Fail(ctx, ResolveStatusBoundExceeded);
        }
        ctx->ForwardVisited[ctx->ForwardVisitedCount] = visitedHash;
        ctx->ForwardVisitedCount += 1u;
        ctx->ForwardDepth = depth;

        status = ResolveForwarder(ctx,
                                       (const char *)(base + functionRva),
                                       forwarderLength, depth, address);

        ctx->ForwardDepth = depth - 1u;
        ctx->ForwardVisitedCount -= 1u;
        return status;
    }

    *address = (PVOID)(base + functionRva);
    return ResolveStatusOk;
}

CODE_SECTION PPEB_PARTIAL MS_ABI CurrentPeb(void)
{
    PPEB_PARTIAL peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
    return peb;
}

CODE_SECTION void MS_ABI HashAsciiUpper(const BYTE *data,
                                               DWORD length,
                                               API_HASH *out)
{
    DWORD fnv;
    DWORD djb;
    DWORD index;

    if (out == NULL) {
        return;
    }
    if (data == NULL || length > MAX_EXPORT_NAME_BYTES) {
        out->Fnv = 0u;
        out->Djb = 0u;
        return;
    }

    fnv = API_HASH_SEED_FNV;
    djb = API_HASH_SEED_DJB;
    for (index = 0u; index < length; ++index) {
        DWORD value = (DWORD)FoldU8(data[index]);
        fnv ^= value;
        fnv *= API_HASH_PRIME;
        djb = (djb << 5u) + djb + value;
    }
    out->Fnv = fnv;
    out->Djb = djb;
}


CODE_SECTION void MS_ABI HashUtf16Upper(PCWSTR data,
                                               DWORD codeUnits,
                                               API_HASH *out)
{
    DWORD fnv;
    DWORD djb;
    DWORD index;

    if (out == NULL) {
        return;
    }
    if (data == NULL || codeUnits > MAX_MODULE_NAME_CHARS) {
        out->Fnv = 0u;
        out->Djb = 0u;
        return;
    }

    fnv = API_HASH_SEED_FNV;
    djb = API_HASH_SEED_DJB;
    for (index = 0u; index < codeUnits; ++index) {
        WORD value = FoldU16(data[index]);
        DWORD low;
        DWORD high;

        low = (DWORD)(value & 0xFFu);
        high = (DWORD)((value >> 8u) & 0xFFu);
        fnv ^= low;
        fnv *= API_HASH_PRIME;
        djb = (djb << 5u) + djb + low;
        fnv ^= high;
        fnv *= API_HASH_PRIME;
        djb = (djb << 5u) + djb + high;
    }
    out->Fnv = fnv;
    out->Djb = djb;
}

/* Hash byte-read UTF-16 using the loader-name rules. */
static CODE_SECTION void HashUtf16BytesUpper(const BYTE *bytes,
                                                DWORD codeUnits,
                                                API_HASH *out)
{
    DWORD fnv;
    DWORD djb;
    DWORD index;

    if (out == NULL) {
        return;
    }
    if (bytes == NULL || codeUnits > MAX_MODULE_NAME_CHARS) {
        out->Fnv = 0u;
        out->Djb = 0u;
        return;
    }

    fnv = API_HASH_SEED_FNV;
    djb = API_HASH_SEED_DJB;
    for (index = 0u; index < codeUnits; ++index) {
        WORD value = FoldU16(ReadU16(bytes + index * 2u));
        DWORD low;
        DWORD high;

        low = (DWORD)(value & 0xFFu);
        high = (DWORD)((value >> 8u) & 0xFFu);
        fnv ^= low;
        fnv *= API_HASH_PRIME;
        djb = (djb << 5u) + djb + low;
        fnv ^= high;
        fnv *= API_HASH_PRIME;
        djb = (djb << 5u) + djb + high;
    }
    out->Fnv = fnv;
    out->Djb = djb;
}

CODE_SECTION RESOLVE_STATUS MS_ABI FindModule(RESOLVER_CONTEXT *ctx,
                                                        const API_HASH *moduleHash,
                                                        PVOID*moduleBase)
{
    PPEB_PARTIAL peb;
    PLIST_ENTRY head;
    PLIST_ENTRY link;
    DWORD walked;
    DWORD index;

    if (ctx == NULL || moduleBase == NULL || moduleHash == NULL ||
        HashIsZero(moduleHash) == TRUE) {
        return ResolveStatusBadArgument;
    }
    *moduleBase = NULL;

    /* Cache entries assume modules stay loaded for this operation. */
    for (index = 0u; index < MODULE_CACHE_CAPACITY; ++index) {
        if (HashEqual(&ctx->Modules[index].NameHash, moduleHash) == TRUE &&
            ctx->Modules[index].Base != NULL) {
            *moduleBase = ctx->Modules[index].Base;
            return ResolveStatusOk;
        }
    }

    peb = CurrentPeb();
    if (peb == NULL) {
        ctx->LastError = (DWORD)ResolveStatusNoPeb;
        return ResolveStatusNoPeb;
    }
    if (peb->Ldr == NULL) {
        ctx->LastError = (DWORD)ResolveStatusNoLdr;
        return ResolveStatusNoLdr;
    }

    head = &peb->Ldr->InLoadOrderModuleList;
    link = head->Flink;
    for (walked = 0u; link != NULL && link != head &&
                       walked < MAX_MODULE_WALK; ++walked) {
        PLDR_DATA_TABLE_ENTRY_PARTIAL entry;
        DWORD codeUnits;
        API_HASH hash;

        entry = (PLDR_DATA_TABLE_ENTRY_PARTIAL)link;
        if (entry->BaseDllName.Buffer != NULL &&
            entry->BaseDllName.Length <= entry->BaseDllName.MaximumLength &&
            (entry->BaseDllName.Length & 1u) == 0u) {
            codeUnits = (DWORD)entry->BaseDllName.Length / 2u;
            if (codeUnits <= MAX_MODULE_NAME_CHARS) {
                HashUtf16Upper(entry->BaseDllName.Buffer, codeUnits, &hash);
                if (HashEqual(&hash, moduleHash) == TRUE &&
                    entry->DllBase != NULL &&
                    entry->SizeOfImage != 0u) {
                    /* Fill the first free cache slot. */
                    for (index = 0u; index < MODULE_CACHE_CAPACITY; ++index) {
                        if (HashIsZero(&ctx->Modules[index].NameHash) == TRUE) {
                            ctx->Modules[index].NameHash = *moduleHash;
                            ctx->Modules[index].ImageSize = entry->SizeOfImage;
                            ctx->Modules[index].Base = entry->DllBase;
                            break;
                        }
                    }
                    *moduleBase = entry->DllBase;
                    return ResolveStatusOk;
                }
            }
        }
        link = link->Flink;
    }

    if (walked >= MAX_MODULE_WALK) {
        ctx->LastError = (DWORD)ResolveStatusBoundExceeded;
        return ResolveStatusBoundExceeded;
    }
    ctx->LastError = (DWORD)ResolveStatusModuleNotFound;
    return ResolveStatusModuleNotFound;
}

CODE_SECTION RESOLVE_STATUS MS_ABI ResolveExport(RESOLVER_CONTEXT *ctx,
                                                           PVOID moduleBase,
                                                           const API_HASH *exportHash,
                                                           PVOID*address)
{
    const BYTE *base;
    DWORD imageSize;
    DWORD dirRva;
    DWORD dirSize;
    DWORD nameCount;
    DWORD functionCount;
    DWORD namesRva;
    DWORD ordinalsRva;
    DWORD functionsRva;
    RESOLVE_STATUS status;
    DWORD index;

    if (ctx == NULL || moduleBase == NULL || address == NULL ||
        exportHash == NULL ||
        HashIsZero(exportHash) == TRUE) {
        return ResolveStatusBadArgument;
    }
    *address = NULL;

    status = ValidateImage(moduleBase, &imageSize, &dirRva, &dirSize);
    if (status != ResolveStatusOk) {
        return Fail(ctx, status);
    }

    base = (const BYTE *)moduleBase;
    nameCount = ReadU32(base + dirRva + EXP_OFF(NumberOfNames));
    functionCount = ReadU32(base + dirRva + EXP_OFF(NumberOfFunctions));
    namesRva = ReadU32(base + dirRva + EXP_OFF(AddressOfNames));
    ordinalsRva = ReadU32(base + dirRva + EXP_OFF(AddressOfNameOrdinals));
    functionsRva = ReadU32(base + dirRva + EXP_OFF(AddressOfFunctions));

    if (nameCount > MAX_EXPORT_NAMES || functionCount > MAX_EXPORT_NAMES) {
        return Fail(ctx, ResolveStatusBoundExceeded);
    }
    if (nameCount == 0u || functionsRva == 0u) {
        return Fail(ctx, ResolveStatusExportNotFound);
    }
    if (!RangeWithin(namesRva, nameCount * 4u, imageSize) ||
        !RangeWithin(ordinalsRva, nameCount * 2u, imageSize) ||
        !RangeWithin(functionsRva, functionCount * 4u, imageSize)) {
        return Fail(ctx, ResolveStatusBadImage);
    }

    /* Hash lookup requires a bounded linear scan. */
    for (index = 0u; index < nameCount; ++index) {
        DWORD nameRva = ReadU32(base + namesRva + index * 4u);
        DWORD nameLength = ScanAsciiName(base, imageSize, nameRva);
        API_HASH nameHash;

        if (nameLength == NAME_INVALID) {
            continue;
        }
        HashAsciiUpper(base + nameRva, nameLength, &nameHash);
        if (HashEqual(&nameHash, exportHash) == TRUE) {
            DWORD hint = (DWORD)ReadU16(base + ordinalsRva + index * 2u);
            DWORD functionRva;

            if (hint >= functionCount) {
                return Fail(ctx, ResolveStatusBadImage);
            }
            functionRva = ReadU32(base + functionsRva + hint * 4u);
            return ExportFinish(ctx, base, imageSize, dirRva, dirSize,
                                     functionRva, address);
        }
    }
    return Fail(ctx, ResolveStatusExportNotFound);
}

CODE_SECTION RESOLVE_STATUS MS_ABI ResolveOrdinal(RESOLVER_CONTEXT *ctx,
                                                            PVOID moduleBase,
                                                            WORD ordinal,
                                                            PVOID*address)
{
    const BYTE *base;
    DWORD imageSize;
    DWORD dirRva;
    DWORD dirSize;
    DWORD functionCount;
    DWORD functionsRva;
    DWORD ordinalBase;
    DWORD ordinalValue;
    DWORD index;
    DWORD functionRva;
    RESOLVE_STATUS status;

    if (ctx == NULL || moduleBase == NULL || address == NULL) {
        return ResolveStatusBadArgument;
    }
    *address = NULL;

    status = ValidateImage(moduleBase, &imageSize, &dirRva, &dirSize);
    if (status != ResolveStatusOk) {
        return Fail(ctx, status);
    }

    base = (const BYTE *)moduleBase;
    functionCount = ReadU32(base + dirRva + EXP_OFF(NumberOfFunctions));
    functionsRva = ReadU32(base + dirRva + EXP_OFF(AddressOfFunctions));
    ordinalBase = ReadU32(base + dirRva + EXP_OFF(Base));

    /* Convert the true ordinal to an address-table index. */
    ordinalValue = (DWORD)ordinal;
    if (ordinalValue < ordinalBase || functionCount == 0u ||
        functionsRva == 0u || functionCount > MAX_EXPORT_NAMES ||
        !RangeWithin(functionsRva, functionCount * 4u, imageSize)) {
        return Fail(ctx, ResolveStatusOrdinalOutOfRange);
    }
    index = ordinalValue - ordinalBase;
    if (index >= functionCount) {
        return Fail(ctx, ResolveStatusOrdinalOutOfRange);
    }

    functionRva = ReadU32(base + functionsRva + index * 4u);
    return ExportFinish(ctx, base, imageSize, dirRva, dirSize,
                             functionRva, address);
}

/* Test for an api- or ext- prefix. */
static CODE_SECTION BOOL AsciiIsApiSetPrefix(const char *name, DWORD length)
{
    BYTE c0;
    BYTE c1;
    BYTE c2;
    BYTE c3;

    if (length < 4u) {
        return FALSE;
    }
    c0 = FoldU8((BYTE)name[0]);
    c1 = FoldU8((BYTE)name[1]);
    c2 = FoldU8((BYTE)name[2]);
    c3 = FoldU8((BYTE)name[3]);
    if (c0 == (BYTE)'A' && c1 == (BYTE)'P' && c2 == (BYTE)'I' &&
        c3 == (BYTE)'-') {
        return TRUE;
    }
    if (c0 == (BYTE)'E' && c1 == (BYTE)'X' && c2 == (BYTE)'T' &&
        c3 == (BYTE)'-') {
        return TRUE;
    }
    return FALSE;
}

/* Resolve a bounded ASCII API-set name through a stack UTF-16 copy. */
static CODE_SECTION RESOLVE_STATUS ForwarderApiSetModule(RESOLVER_CONTEXT *ctx,
                                                       const char *module,
                                                       DWORD moduleLength,
                                                       PVOID*moduleBase)
{
    WORD wide[MAX_APISET_CONTRACT_CHARS];
    DWORD index;

    if (moduleLength > MAX_APISET_CONTRACT_CHARS) {
        return Fail(ctx, ResolveStatusBoundExceeded);
    }
    for (index = 0u; index < moduleLength; ++index) {
        wide[index] = (WORD)(BYTE)module[index];
    }
    return ResolveApiSetContract(ctx, wide, moduleLength, moduleBase);
}

CODE_SECTION RESOLVE_STATUS MS_ABI ResolveForwarder(
    RESOLVER_CONTEXT *ctx,
    const char *forwarder,
    DWORD forwarderLength,
    DWORD depth,
    PVOID*address)
{
    DWORD dot;
    DWORD moduleLen;
    DWORD entryOff;
    DWORD entryLen;
    DWORD index;
    PVOID moduleBase;
    RESOLVE_STATUS status;

    if (ctx == NULL || forwarder == NULL || address == NULL ||
        forwarderLength == 0u ||
        forwarderLength > MAX_EXPORT_NAME_BYTES) {
        return ResolveStatusBadArgument;
    }
    *address = NULL;
    if (depth == 0u || depth > MAX_FORWARD_DEPTH) {
        return Fail(ctx, ResolveStatusForwardDepth);
    }

    /* Split at the last dot because API-set module names contain dots. */
    dot = forwarderLength;
    for (index = 0u; index < forwarderLength; ++index) {
        if (forwarder[index] == '.') {
            dot = index;
        }
    }
    if (dot == forwarderLength) {
        return Fail(ctx, ResolveStatusBadImage);
    }
    moduleLen = dot;
    entryOff = dot + 1u;
    entryLen = forwarderLength - entryOff;
    if (moduleLen == 0u || entryLen == 0u) {
        return Fail(ctx, ResolveStatusBadImage);
    }

    if (AsciiIsApiSetPrefix(forwarder, moduleLen) == TRUE) {
        status = ForwarderApiSetModule(ctx, forwarder, moduleLen,
                                             &moduleBase);
    } else {
        {
            API_HASH moduleHash;
            HashAsciiUpper((const BYTE *)forwarder, moduleLen,
                                 &moduleHash);
            status = FindModule(ctx, &moduleHash, &moduleBase);
        }
    }
    if (status != ResolveStatusOk) {
        return status;
    }

    if (forwarder[entryOff] == '#') {
        DWORD ordinalValue = 0u;

        if (entryLen == 1u) {
            return Fail(ctx, ResolveStatusBadImage);
        }
        for (index = entryOff + 1u; index < forwarderLength; ++index) {
            BYTE digitChar = (BYTE)forwarder[index];
            DWORD digit;

            if (digitChar < (BYTE)'0' || digitChar > (BYTE)'9') {
                return Fail(ctx, ResolveStatusBadImage);
            }
            digit = (DWORD)(digitChar - (BYTE)'0');
            if (ordinalValue > (0xFFFFu - digit) / 10u) {
                return Fail(ctx, ResolveStatusOrdinalOutOfRange);
            }
            ordinalValue = ordinalValue * 10u + digit;
        }
        return ResolveOrdinal(ctx, moduleBase,
                                   (WORD)ordinalValue, address);
    }
    {
        API_HASH entryHash;
        HashAsciiUpper((const BYTE *)forwarder + entryOff, entryLen,
                             &entryHash);
        return ResolveExport(ctx, moduleBase, &entryHash, address);
    }
}

/* Compare a contract with a byte-read schema name. */
static CODE_SECTION BOOL ApiSetNameEqual(PCWSTR contract,
                                       DWORD units,
                                       const BYTE *stored)
{
    DWORD index;

    for (index = 0u; index < units; ++index) {
        if (FoldU16(contract[index]) !=
            FoldU16(ReadU16(stored + index * 2u))) {
            return FALSE;
        }
    }
    return TRUE;
}

CODE_SECTION RESOLVE_STATUS MS_ABI ResolveApiSetContract(
    RESOLVER_CONTEXT *ctx,
    PCWSTR contract,
    DWORD contractCodeUnits,
    PVOID*moduleBase)
{
    PPEB_PARTIAL peb;
    const BYTE *schema;
    DWORD schemaSize;
    DWORD entryCount;
    DWORD entryOffset;
    DWORD hashedUnits;
    DWORD cut;
    BOOL haveCut;
    DWORD index;
    WORD p0;
    WORD p1;
    WORD p2;
    WORD p3;

    if (ctx == NULL || contract == NULL || moduleBase == NULL ||
        contractCodeUnits == 0u ||
        contractCodeUnits > MAX_APISET_CONTRACT_CHARS) {
        return ResolveStatusBadArgument;
    }
    *moduleBase = NULL;

    /* Accept api-/ext- contracts with an optional .dll suffix. */
    if (contractCodeUnits < 4u) {
        return Fail(ctx, ResolveStatusBadArgument);
    }
    p0 = FoldU16(contract[0]);
    p1 = FoldU16(contract[1]);
    p2 = FoldU16(contract[2]);
    p3 = FoldU16(contract[3]);
    if (!((p0 == (WORD)'A' && p1 == (WORD)'P' && p2 == (WORD)'I' &&
           p3 == (WORD)'-') ||
          (p0 == (WORD)'E' && p1 == (WORD)'X' && p2 == (WORD)'T' &&
           p3 == (WORD)'-'))) {
        return Fail(ctx, ResolveStatusBadArgument);
    }

    /* Match the contract prefix through its last hyphen. */
    haveCut = FALSE;
    for (index = contractCodeUnits; index > 0u; --index) {
        if (contract[index - 1u] == (WORD)'-') {
            cut = index - 1u;
            haveCut = TRUE;
            break;
        }
    }
    if (haveCut != TRUE || cut == 0u) {
        return Fail(ctx, ResolveStatusBadArgument);
    }
    hashedUnits = cut;

    peb = CurrentPeb();
    if (peb == NULL) {
        ctx->LastError = (DWORD)ResolveStatusNoPeb;
        return ResolveStatusNoPeb;
    }
    if (peb->ApiSetMap == NULL) {
        return Fail(ctx, ResolveStatusApiSetUnsupported);
    }
    schema = (const BYTE *)peb->ApiSetMap;

    if (ReadU32(schema + (DWORD)offsetof(APISET_NAMESPACE_V6, Version)) !=
        APISET_SCHEMA_VERSION_6) {
        return Fail(ctx, ResolveStatusApiSetUnsupported);
    }
    schemaSize = ReadU32(
        schema + (DWORD)offsetof(APISET_NAMESPACE_V6, Size));
    entryCount = ReadU32(
        schema + (DWORD)offsetof(APISET_NAMESPACE_V6, Count));
    entryOffset = ReadU32(
        schema + (DWORD)offsetof(APISET_NAMESPACE_V6, EntryOffset));
    if (schemaSize == 0u || entryCount == 0u ||
        entryCount > MAX_APISET_ENTRIES) {
        return Fail(ctx, ResolveStatusApiSetUnsupported);
    }
    if (!RangeWithin(entryOffset,
                          entryCount *
                              (DWORD)sizeof(APISET_NAMESPACE_ENTRY_V6),
                          schemaSize)) {
        return Fail(ctx, ResolveStatusApiSetUnsupported);
    }

    for (index = 0u; index < entryCount; ++index) {
        const BYTE *entry = schema + entryOffset +
                              index *
                                  (DWORD)sizeof(APISET_NAMESPACE_ENTRY_V6);
        DWORD nameOffset = ReadU32(
            entry + (DWORD)offsetof(APISET_NAMESPACE_ENTRY_V6, NameOffset));
        DWORD hashedLength = ReadU32(
            entry + (DWORD)offsetof(APISET_NAMESPACE_ENTRY_V6, HashedLength));
        DWORD valueOffset = ReadU32(
            entry + (DWORD)offsetof(APISET_NAMESPACE_ENTRY_V6, ValueOffset));
        DWORD valueCount = ReadU32(
            entry + (DWORD)offsetof(APISET_NAMESPACE_ENTRY_V6, ValueCount));
        const BYTE *value;
        DWORD hostOffset;
        DWORD hostLength;
        DWORD hostUnits;
        API_HASH hostHash;

        if (hashedLength == 0u || (hashedLength & 1u) != 0u ||
            hashedLength / 2u != hashedUnits ||
            !RangeWithin(nameOffset, hashedLength, schemaSize)) {
            continue;
        }
        if (ApiSetNameEqual(contract, hashedUnits,
                                  schema + nameOffset) != TRUE) {
            continue;
        }

        /* The first value entry is the default host. */
        if (valueCount == 0u || valueCount > MAX_APISET_VALUES ||
            !RangeWithin(valueOffset,
                              valueCount *
                                  (DWORD)sizeof(APISET_VALUE_ENTRY_V6),
                              schemaSize)) {
            return Fail(ctx, ResolveStatusBadImage);
        }
        value = schema + valueOffset;
        hostOffset = ReadU32(
            value + (DWORD)offsetof(APISET_VALUE_ENTRY_V6, ValueOffset));
        hostLength = ReadU32(
            value + (DWORD)offsetof(APISET_VALUE_ENTRY_V6, ValueLength));
        if (hostLength == 0u || (hostLength & 1u) != 0u ||
            !RangeWithin(hostOffset, hostLength, schemaSize)) {
            return Fail(ctx, ResolveStatusBadImage);
        }
        hostUnits = hostLength / 2u;
        if (hostUnits > MAX_MODULE_NAME_CHARS) {
            return Fail(ctx, ResolveStatusBoundExceeded);
        }

        /* Strip .dll before hashing against loader names. */
        if (hostUnits >= 5u) {
            const BYTE *suffix = schema + hostOffset + (hostUnits - 4u) * 2u;
            if (FoldU16(ReadU16(suffix)) == (WORD)'.' &&
                FoldU16(ReadU16(suffix + 2u)) == (WORD)'D' &&
                FoldU16(ReadU16(suffix + 4u)) == (WORD)'L' &&
                FoldU16(ReadU16(suffix + 6u)) == (WORD)'L') {
                hostUnits -= 4u;
            }
        }
        if (hostUnits == 0u) {
            return Fail(ctx, ResolveStatusBadImage);
        }

        HashUtf16BytesUpper(schema + hostOffset, hostUnits, &hostHash);
        if (HashIsZero(&hostHash) == TRUE) {
            return Fail(ctx, ResolveStatusBoundExceeded);
        }
        return FindModule(ctx, &hostHash, moduleBase);
    }

    return Fail(ctx, ResolveStatusModuleNotFound);
}
