#define PIC_CODE_SECTION_NAME ".text$D"
#include "pic_resolve.h"

/*
 * Resolver implementation notes
 * =============================
 * - Every PE/API-set field is read byte-wise (pic_read_u16/pic_read_u32) at
 *   offsets taken from the asserted structures in pic_resolve.h.  No
 *   structure pointer is ever formed into a mapped image or into the
 *   API-set schema: those bytes are not guaranteed to be aligned, and this
 *   also keeps -Wcast-align=strict clean.  x64 is little-endian only.
 * - Every loop is bounded by the PIC_* limits in pic_resolve.h.
 * - Forwarded exports: recursion depth lives in ctx->forward_depth and is
 *   checked before each hop; cycles are detected by the visited-stack of
 *   forwarder-string hashes in ctx->forward_visited.
 * - API-set parsing is isolated in this file and pinned to schema
 *   version 6; any other version fails closed.
 * - The module cache in ctx->modules memoizes Ldr lookups by name hash.
 *   Modules are assumed not to unload for the duration of one operation
 *   (snapshot semantics); the assumption is documented in docs/.
 */

static PIC_CODE pic_u16 pic_read_u16(const pic_u8 *data)
{
    return (pic_u16)((pic_u16)data[0] | ((pic_u16)data[1] << 8u));
}

static PIC_CODE pic_u32 pic_read_u32(const pic_u8 *data)
{
    return (pic_u32)((pic_u32)data[0] |
                     ((pic_u32)data[1] << 8u) |
                     ((pic_u32)data[2] << 16u) |
                     ((pic_u32)data[3] << 24u));
}

/* pic_u8 ASCII a-z -> A-Z fold. */
static PIC_CODE pic_bool pic_hash_equal(const PIC_HASH *a, const PIC_HASH *b)
{
    return (a->fnv == b->fnv && a->djb == b->djb) ? PIC_TRUE : PIC_FALSE;
}

static PIC_CODE pic_bool pic_hash_is_zero(const PIC_HASH *h)
{
    return (h->fnv == 0u && h->djb == 0u) ? PIC_TRUE : PIC_FALSE;
}

static PIC_CODE pic_u8 pic_fold_u8(pic_u8 value)
{
    if (value >= (pic_u8)'a' && value <= (pic_u8)'z') {
        return (pic_u8)(value - ((pic_u8)'a' - (pic_u8)'A'));
    }
    return value;
}

/* pic_u16 ASCII a-z -> A-Z fold. */
static PIC_CODE pic_u16 pic_fold_u16(pic_u16 value)
{
    if (value >= (pic_u16)'a' && value <= (pic_u16)'z') {
        return (pic_u16)(value - ((pic_u16)'a' - (pic_u16)'A'));
    }
    return value;
}

static PIC_CODE pic_bool pic_range_within(pic_u32 offset, pic_u32 length, pic_u32 limit)
{
    pic_u64 end = (pic_u64)offset + (pic_u64)length;
    return end <= (pic_u64)limit ? PIC_TRUE : PIC_FALSE;
}

static PIC_CODE PIC_RESOLVE_STATUS pic_fail(PIC_CONTEXT *ctx, PIC_RESOLVE_STATUS code)
{
    ctx->last_error = (pic_u32)code;
    return code;
}

/* Field offsets inside a mapped image, expressed through the asserted
 * structures in pic_resolve.h. */
#define PIC_NT_FILE_OFF(field) \
    ((pic_u32)PIC_OFFSETOF(PIC_IMAGE_NT_HEADERS64, FileHeader) + \
     (pic_u32)PIC_OFFSETOF(PIC_IMAGE_FILE_HEADER, field))
#define PIC_NT_OPT_OFF(field) \
    ((pic_u32)PIC_OFFSETOF(PIC_IMAGE_NT_HEADERS64, OptionalHeader) + \
     (pic_u32)PIC_OFFSETOF(PIC_IMAGE_OPTIONAL_HEADER64, field))
#define PIC_EXP_OFF(field) \
    ((pic_u32)PIC_OFFSETOF(PIC_IMAGE_EXPORT_DIRECTORY, field))

/* NT headers always begin inside the first page of a mapped image. */
#define PIC_PE_MAX_E_LFANEW 0x1000u

/*
 * Validate a mapped x64 PE image and return its size plus the export
 * directory bounds.  Checks: DOS/NT signatures, machine type, PE32+
 * optional-header magic, NumberOfRvaAndSizes covers the export entry,
 * non-zero SizeOfImage, and an export directory fully inside the image.
 */
static PIC_CODE PIC_RESOLVE_STATUS pic_validate_image(void *module_base,
                                              pic_u32 *image_size,
                                              pic_u32 *export_rva,
                                              pic_u32 *export_size)
{
    const pic_u8 *base = (const pic_u8 *)module_base;
    pic_u32 lfanew;
    pic_u32 number_of_rva;
    pic_u32 size_of_image;
    pic_u32 directory_offset;

    if (pic_read_u16(base) != PIC_IMAGE_DOS_SIGNATURE) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    lfanew = (pic_u32)pic_read_u32(
        base + (pic_u32)PIC_OFFSETOF(PIC_IMAGE_DOS_HEADER, e_lfanew));
    if (lfanew < (pic_u32)sizeof(PIC_IMAGE_DOS_HEADER) ||
        lfanew > PIC_PE_MAX_E_LFANEW - (pic_u32)sizeof(PIC_IMAGE_NT_HEADERS64) ||
        (lfanew & 3u) != 0u) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    if (pic_read_u32(base + lfanew) != PIC_IMAGE_NT_SIGNATURE) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    if (pic_read_u16(base + lfanew + PIC_NT_FILE_OFF(Machine)) !=
        PIC_IMAGE_FILE_MACHINE_AMD64) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    if (pic_read_u16(base + lfanew + PIC_NT_OPT_OFF(Magic)) !=
        PIC_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    number_of_rva = pic_read_u32(base + lfanew + PIC_NT_OPT_OFF(NumberOfRvaAndSizes));
    if (number_of_rva <= PIC_IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    size_of_image = pic_read_u32(base + lfanew + PIC_NT_OPT_OFF(SizeOfImage));
    if (size_of_image == 0u) {
        return PIC_RESOLVE_BAD_IMAGE;
    }

    directory_offset = lfanew + PIC_NT_OPT_OFF(DataDirectory) +
                       PIC_IMAGE_DIRECTORY_ENTRY_EXPORT *
                           (pic_u32)sizeof(PIC_IMAGE_DATA_DIRECTORY);
    *export_rva = pic_read_u32(base + directory_offset);
    *export_size = pic_read_u32(base + directory_offset + 4u);
    if (*export_rva == 0u ||
        *export_size < (pic_u32)sizeof(PIC_IMAGE_EXPORT_DIRECTORY) ||
        !pic_range_within(*export_rva, *export_size, size_of_image)) {
        return PIC_RESOLVE_BAD_IMAGE;
    }
    *image_size = size_of_image;
    return PIC_RESOLVE_OK;
}

#define PIC_NAME_INVALID 0xFFFFFFFFu

/*
 * Bounded scan for a NUL-terminated ASCII string at name_rva.  Returns the
 * length without the terminator, or PIC_NAME_INVALID when the rva is out of
 * bounds, the string is empty, or no terminator appears within the smaller
 * of the image and PIC_MAX_EXPORT_NAME_BYTES.
 */
static PIC_CODE pic_u32 pic_scan_ascii_name(const pic_u8 *base,
                                    pic_u32 image_size,
                                    pic_u32 name_rva)
{
    pic_u32 limit;
    pic_u32 index;

    if (name_rva == 0u || name_rva >= image_size) {
        return PIC_NAME_INVALID;
    }
    limit = image_size - name_rva;
    if (limit > PIC_MAX_EXPORT_NAME_BYTES) {
        limit = PIC_MAX_EXPORT_NAME_BYTES;
    }
    for (index = 0u; index < limit; ++index) {
        if (base[name_rva + index] == 0u) {
            return index == 0u ? PIC_NAME_INVALID : index;
        }
    }
    return PIC_NAME_INVALID;
}

/*
 * Shared completion for export lookups: a non-forwarded RVA resolves
 * directly; an RVA inside the export directory range is a forwarder string
 * and recurses through pic_resolve_forwarder with depth and cycle checks.
 */
static PIC_CODE PIC_RESOLVE_STATUS pic_export_finish(PIC_CONTEXT *ctx,
                                            const pic_u8 *base,
                                            pic_u32 image_size,
                                            pic_u32 dir_rva,
                                            pic_u32 dir_size,
                                            pic_u32 function_rva,
                                            void **address)
{
    if (function_rva == 0u) {
        return pic_fail(ctx, PIC_RESOLVE_EXPORT_NOT_FOUND);
    }
    if (function_rva >= image_size) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
    }

    if ((pic_u64)function_rva >= (pic_u64)dir_rva &&
        (pic_u64)function_rva < (pic_u64)dir_rva + (pic_u64)dir_size) {
        PIC_RESOLVE_STATUS status;
        pic_u32 forwarder_length;
        pic_u32 depth;
        PIC_HASH visited_hash;
        pic_u32 index;

        forwarder_length = pic_scan_ascii_name(base, image_size, function_rva);
        if (forwarder_length == PIC_NAME_INVALID) {
            return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
        }

        depth = ctx->forward_depth + 1u;
        if (depth > PIC_MAX_FORWARD_DEPTH) {
            return pic_fail(ctx, PIC_RESOLVE_FORWARD_DEPTH);
        }

        pic_hash_ascii_upper(base + function_rva, forwarder_length,
                             &visited_hash);
        for (index = 0u; index < ctx->forward_visited_count; ++index) {
            if (pic_hash_equal(&ctx->forward_visited[index], &visited_hash) == PIC_TRUE) {
                return pic_fail(ctx, PIC_RESOLVE_FORWARD_CYCLE);
            }
        }
        if (ctx->forward_visited_count >= PIC_MAX_FORWARD_VISITED) {
            return pic_fail(ctx, PIC_RESOLVE_BOUND_EXCEEDED);
        }
        ctx->forward_visited[ctx->forward_visited_count] = visited_hash;
        ctx->forward_visited_count += 1u;
        ctx->forward_depth = depth;

        status = pic_resolve_forwarder(ctx,
                                       (const char *)(base + function_rva),
                                       forwarder_length, depth, address);

        ctx->forward_depth = depth - 1u;
        ctx->forward_visited_count -= 1u;
        return status;
    }

    *address = (void *)(base + function_rva);
    return PIC_RESOLVE_OK;
}

PIC_CODE PIC_PEB *PIC_MS_ABI pic_current_peb(void)
{
    PIC_PEB *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
    return peb;
}

PIC_CODE void PIC_MS_ABI pic_hash_ascii_upper(const pic_u8 *data,
                                               pic_u32 length,
                                               PIC_HASH *out)
{
    pic_u32 fnv;
    pic_u32 djb;
    pic_u32 index;

    if (out == PIC_NULL) {
        return;
    }
    if (data == PIC_NULL || length > PIC_MAX_EXPORT_NAME_BYTES) {
        out->fnv = 0u;
        out->djb = 0u;
        return;
    }

    fnv = PIC_HASH_SEED_FNV;
    djb = PIC_HASH_SEED_DJB;
    for (index = 0u; index < length; ++index) {
        pic_u32 value = (pic_u32)pic_fold_u8(data[index]);
        fnv ^= value;
        fnv *= PIC_HASH_PRIME;
        djb = (djb << 5u) + djb + value;
    }
    out->fnv = fnv;
    out->djb = djb;
}


PIC_CODE void PIC_MS_ABI pic_hash_utf16_upper(const pic_u16 *data,
                                               pic_u32 code_units,
                                               PIC_HASH *out)
{
    pic_u32 fnv;
    pic_u32 djb;
    pic_u32 index;

    if (out == PIC_NULL) {
        return;
    }
    if (data == PIC_NULL || code_units > PIC_MAX_MODULE_NAME_CHARS) {
        out->fnv = 0u;
        out->djb = 0u;
        return;
    }

    fnv = PIC_HASH_SEED_FNV;
    djb = PIC_HASH_SEED_DJB;
    for (index = 0u; index < code_units; ++index) {
        pic_u16 value = pic_fold_u16(data[index]);
        pic_u32 low;
        pic_u32 high;

        low = (pic_u32)(value & 0xFFu);
        high = (pic_u32)((value >> 8u) & 0xFFu);
        fnv ^= low;
        fnv *= PIC_HASH_PRIME;
        djb = (djb << 5u) + djb + low;
        fnv ^= high;
        fnv *= PIC_HASH_PRIME;
        djb = (djb << 5u) + djb + high;
    }
    out->fnv = fnv;
    out->djb = djb;
}

/* Dual-32 over byte-read UTF-16 units; identical values to
 * pic_hash_utf16_upper for the same text, so schema host names hash the
 * same as Ldr BaseDllName contents. */
static PIC_CODE void pic_hash_utf16_bytes_upper(const pic_u8 *bytes,
                                                pic_u32 code_units,
                                                PIC_HASH *out)
{
    pic_u32 fnv;
    pic_u32 djb;
    pic_u32 index;

    if (out == PIC_NULL) {
        return;
    }
    if (bytes == PIC_NULL || code_units > PIC_MAX_MODULE_NAME_CHARS) {
        out->fnv = 0u;
        out->djb = 0u;
        return;
    }

    fnv = PIC_HASH_SEED_FNV;
    djb = PIC_HASH_SEED_DJB;
    for (index = 0u; index < code_units; ++index) {
        pic_u16 value = pic_fold_u16(pic_read_u16(bytes + index * 2u));
        pic_u32 low;
        pic_u32 high;

        low = (pic_u32)(value & 0xFFu);
        high = (pic_u32)((value >> 8u) & 0xFFu);
        fnv ^= low;
        fnv *= PIC_HASH_PRIME;
        djb = (djb << 5u) + djb + low;
        fnv ^= high;
        fnv *= PIC_HASH_PRIME;
        djb = (djb << 5u) + djb + high;
    }
    out->fnv = fnv;
    out->djb = djb;
}

PIC_CODE PIC_RESOLVE_STATUS PIC_MS_ABI pic_find_module(PIC_CONTEXT *ctx,
                                                        const PIC_HASH *module_hash,
                                                        void **module_base)
{
    PIC_PEB *peb;
    PIC_LIST_ENTRY *head;
    PIC_LIST_ENTRY *link;
    pic_u32 walked;
    pic_u32 index;

    if (ctx == PIC_NULL || module_base == PIC_NULL || module_hash == PIC_NULL ||
        pic_hash_is_zero(module_hash) == PIC_TRUE) {
        return PIC_RESOLVE_BAD_ARGUMENT;
    }
    *module_base = PIC_NULL;

    /* Cache hit: modules are assumed not to unload during one operation. */
    for (index = 0u; index < PIC_MODULE_CACHE_CAPACITY; ++index) {
        if (pic_hash_equal(&ctx->modules[index].name_hash, module_hash) == PIC_TRUE &&
            ctx->modules[index].base != PIC_NULL) {
            *module_base = ctx->modules[index].base;
            return PIC_RESOLVE_OK;
        }
    }

    peb = pic_current_peb();
    if (peb == PIC_NULL) {
        ctx->last_error = (pic_u32)PIC_RESOLVE_NO_PEB;
        return PIC_RESOLVE_NO_PEB;
    }
    if (peb->Ldr == PIC_NULL) {
        ctx->last_error = (pic_u32)PIC_RESOLVE_NO_LDR;
        return PIC_RESOLVE_NO_LDR;
    }

    head = &peb->Ldr->InLoadOrderModuleList;
    link = head->Flink;
    for (walked = 0u; link != PIC_NULL && link != head &&
                       walked < PIC_MAX_MODULE_WALK; ++walked) {
        PIC_LDR_DATA_TABLE_ENTRY *entry;
        pic_u32 code_units;
        PIC_HASH hash;

        entry = (PIC_LDR_DATA_TABLE_ENTRY *)link;
        if (entry->BaseDllName.Buffer != PIC_NULL &&
            entry->BaseDllName.Length <= entry->BaseDllName.MaximumLength &&
            (entry->BaseDllName.Length & 1u) == 0u) {
            code_units = (pic_u32)entry->BaseDllName.Length / 2u;
            if (code_units <= PIC_MAX_MODULE_NAME_CHARS) {
                pic_hash_utf16_upper(entry->BaseDllName.Buffer, code_units, &hash);
                if (pic_hash_equal(&hash, module_hash) == PIC_TRUE &&
                    entry->DllBase != PIC_NULL &&
                    entry->SizeOfImage != 0u) {
                    /* Cache fill: first free slot only, no eviction. */
                    for (index = 0u; index < PIC_MODULE_CACHE_CAPACITY; ++index) {
                        if (pic_hash_is_zero(&ctx->modules[index].name_hash) == PIC_TRUE) {
                            ctx->modules[index].name_hash = *module_hash;
                            ctx->modules[index].image_size = entry->SizeOfImage;
                            ctx->modules[index].base = entry->DllBase;
                            break;
                        }
                    }
                    *module_base = entry->DllBase;
                    return PIC_RESOLVE_OK;
                }
            }
        }
        link = link->Flink;
    }

    if (walked >= PIC_MAX_MODULE_WALK) {
        ctx->last_error = (pic_u32)PIC_RESOLVE_BOUND_EXCEEDED;
        return PIC_RESOLVE_BOUND_EXCEEDED;
    }
    ctx->last_error = (pic_u32)PIC_RESOLVE_MODULE_NOT_FOUND;
    return PIC_RESOLVE_MODULE_NOT_FOUND;
}

PIC_CODE PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_export(PIC_CONTEXT *ctx,
                                                           void *module_base,
                                                           const PIC_HASH *export_hash,
                                                           void **address)
{
    const pic_u8 *base;
    pic_u32 image_size;
    pic_u32 dir_rva;
    pic_u32 dir_size;
    pic_u32 name_count;
    pic_u32 function_count;
    pic_u32 names_rva;
    pic_u32 ordinals_rva;
    pic_u32 functions_rva;
    PIC_RESOLVE_STATUS status;
    pic_u32 index;

    if (ctx == PIC_NULL || module_base == PIC_NULL || address == PIC_NULL ||
        export_hash == PIC_NULL ||
        pic_hash_is_zero(export_hash) == PIC_TRUE) {
        return PIC_RESOLVE_BAD_ARGUMENT;
    }
    *address = PIC_NULL;

    status = pic_validate_image(module_base, &image_size, &dir_rva, &dir_size);
    if (status != PIC_RESOLVE_OK) {
        return pic_fail(ctx, status);
    }

    base = (const pic_u8 *)module_base;
    name_count = pic_read_u32(base + dir_rva + PIC_EXP_OFF(NumberOfNames));
    function_count = pic_read_u32(base + dir_rva + PIC_EXP_OFF(NumberOfFunctions));
    names_rva = pic_read_u32(base + dir_rva + PIC_EXP_OFF(AddressOfNames));
    ordinals_rva = pic_read_u32(base + dir_rva + PIC_EXP_OFF(AddressOfNameOrdinals));
    functions_rva = pic_read_u32(base + dir_rva + PIC_EXP_OFF(AddressOfFunctions));

    if (name_count > PIC_MAX_EXPORT_NAMES || function_count > PIC_MAX_EXPORT_NAMES) {
        return pic_fail(ctx, PIC_RESOLVE_BOUND_EXCEEDED);
    }
    if (name_count == 0u || functions_rva == 0u) {
        return pic_fail(ctx, PIC_RESOLVE_EXPORT_NOT_FOUND);
    }
    if (!pic_range_within(names_rva, name_count * 4u, image_size) ||
        !pic_range_within(ordinals_rva, name_count * 2u, image_size) ||
        !pic_range_within(functions_rva, function_count * 4u, image_size)) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
    }

    /* Hashed lookup cannot binary-search (names are sorted lexically, not
     * by hash): a bounded linear scan is the deterministic option. */
    for (index = 0u; index < name_count; ++index) {
        pic_u32 name_rva = pic_read_u32(base + names_rva + index * 4u);
        pic_u32 name_length = pic_scan_ascii_name(base, image_size, name_rva);
        PIC_HASH name_hash;

        if (name_length == PIC_NAME_INVALID) {
            continue;
        }
        pic_hash_ascii_upper(base + name_rva, name_length, &name_hash);
        if (pic_hash_equal(&name_hash, export_hash) == PIC_TRUE) {
            pic_u32 hint = (pic_u32)pic_read_u16(base + ordinals_rva + index * 2u);
            pic_u32 function_rva;

            if (hint >= function_count) {
                return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
            }
            function_rva = pic_read_u32(base + functions_rva + hint * 4u);
            return pic_export_finish(ctx, base, image_size, dir_rva, dir_size,
                                     function_rva, address);
        }
    }
    return pic_fail(ctx, PIC_RESOLVE_EXPORT_NOT_FOUND);
}

PIC_CODE PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_ordinal(PIC_CONTEXT *ctx,
                                                            void *module_base,
                                                            pic_u16 ordinal,
                                                            void **address)
{
    const pic_u8 *base;
    pic_u32 image_size;
    pic_u32 dir_rva;
    pic_u32 dir_size;
    pic_u32 function_count;
    pic_u32 functions_rva;
    pic_u32 ordinal_base;
    pic_u32 ordinal_value;
    pic_u32 index;
    pic_u32 function_rva;
    PIC_RESOLVE_STATUS status;

    if (ctx == PIC_NULL || module_base == PIC_NULL || address == PIC_NULL) {
        return PIC_RESOLVE_BAD_ARGUMENT;
    }
    *address = PIC_NULL;

    status = pic_validate_image(module_base, &image_size, &dir_rva, &dir_size);
    if (status != PIC_RESOLVE_OK) {
        return pic_fail(ctx, status);
    }

    base = (const pic_u8 *)module_base;
    function_count = pic_read_u32(base + dir_rva + PIC_EXP_OFF(NumberOfFunctions));
    functions_rva = pic_read_u32(base + dir_rva + PIC_EXP_OFF(AddressOfFunctions));
    ordinal_base = pic_read_u32(base + dir_rva + PIC_EXP_OFF(Base));

    /* A genuine ordinal: subtract the export ordinal base; the remainder is
     * the address-table index, not an ordinal itself. */
    ordinal_value = (pic_u32)ordinal;
    if (ordinal_value < ordinal_base || function_count == 0u ||
        functions_rva == 0u || function_count > PIC_MAX_EXPORT_NAMES ||
        !pic_range_within(functions_rva, function_count * 4u, image_size)) {
        return pic_fail(ctx, PIC_RESOLVE_ORDINAL_OUT_OF_RANGE);
    }
    index = ordinal_value - ordinal_base;
    if (index >= function_count) {
        return pic_fail(ctx, PIC_RESOLVE_ORDINAL_OUT_OF_RANGE);
    }

    function_rva = pic_read_u32(base + functions_rva + index * 4u);
    return pic_export_finish(ctx, base, image_size, dir_rva, dir_size,
                             function_rva, address);
}

/* "api-" / "ext-" prefix test on the module part of a forwarder. */
static PIC_CODE pic_bool pic_ascii_is_apiset_prefix(const char *name, pic_u32 length)
{
    pic_u8 c0;
    pic_u8 c1;
    pic_u8 c2;
    pic_u8 c3;

    if (length < 4u) {
        return PIC_FALSE;
    }
    c0 = pic_fold_u8((pic_u8)name[0]);
    c1 = pic_fold_u8((pic_u8)name[1]);
    c2 = pic_fold_u8((pic_u8)name[2]);
    c3 = pic_fold_u8((pic_u8)name[3]);
    if (c0 == (pic_u8)'A' && c1 == (pic_u8)'P' && c2 == (pic_u8)'I' &&
        c3 == (pic_u8)'-') {
        return PIC_TRUE;
    }
    if (c0 == (pic_u8)'E' && c1 == (pic_u8)'X' && c2 == (pic_u8)'T' &&
        c3 == (pic_u8)'-') {
        return PIC_TRUE;
    }
    return PIC_FALSE;
}

/* Widen an ASCII forwarder module name on the stack and resolve it through
 * the API-set schema.  Bounded by PIC_MAX_APISET_CONTRACT_CHARS. */
static PIC_CODE PIC_RESOLVE_STATUS pic_forwarder_apiset_module(PIC_CONTEXT *ctx,
                                                       const char *module,
                                                       pic_u32 module_length,
                                                       void **module_base)
{
    pic_u16 wide[PIC_MAX_APISET_CONTRACT_CHARS];
    pic_u32 index;

    if (module_length > PIC_MAX_APISET_CONTRACT_CHARS) {
        return pic_fail(ctx, PIC_RESOLVE_BOUND_EXCEEDED);
    }
    for (index = 0u; index < module_length; ++index) {
        wide[index] = (pic_u16)(pic_u8)module[index];
    }
    return pic_resolve_apiset_contract(ctx, wide, module_length, module_base);
}

PIC_CODE PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_forwarder(
    PIC_CONTEXT *ctx,
    const char *forwarder,
    pic_u32 forwarder_length,
    pic_u32 depth,
    void **address)
{
    pic_u32 dot;
    pic_u32 module_len;
    pic_u32 entry_off;
    pic_u32 entry_len;
    pic_u32 index;
    void *module_base;
    PIC_RESOLVE_STATUS status;

    if (ctx == PIC_NULL || forwarder == PIC_NULL || address == PIC_NULL ||
        forwarder_length == 0u ||
        forwarder_length > PIC_MAX_EXPORT_NAME_BYTES) {
        return PIC_RESOLVE_BAD_ARGUMENT;
    }
    *address = PIC_NULL;
    if (depth == 0u || depth > PIC_MAX_FORWARD_DEPTH) {
        return pic_fail(ctx, PIC_RESOLVE_FORWARD_DEPTH);
    }

    /* Split at the LAST dot: module names may themselves contain dots
     * (api-set contracts), while entry names cannot. */
    dot = forwarder_length;
    for (index = 0u; index < forwarder_length; ++index) {
        if (forwarder[index] == '.') {
            dot = index;
        }
    }
    if (dot == forwarder_length) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
    }
    module_len = dot;
    entry_off = dot + 1u;
    entry_len = forwarder_length - entry_off;
    if (module_len == 0u || entry_len == 0u) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
    }

    if (pic_ascii_is_apiset_prefix(forwarder, module_len) == PIC_TRUE) {
        status = pic_forwarder_apiset_module(ctx, forwarder, module_len,
                                             &module_base);
    } else {
        {
            PIC_HASH module_hash;
            pic_hash_ascii_upper((const pic_u8 *)forwarder, module_len,
                                 &module_hash);
            status = pic_find_module(ctx, &module_hash, &module_base);
        }
    }
    if (status != PIC_RESOLVE_OK) {
        return status;
    }

    if (forwarder[entry_off] == '#') {
        pic_u32 ordinal_value = 0u;

        if (entry_len == 1u) {
            return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
        }
        for (index = entry_off + 1u; index < forwarder_length; ++index) {
            pic_u8 digit_char = (pic_u8)forwarder[index];
            pic_u32 digit;

            if (digit_char < (pic_u8)'0' || digit_char > (pic_u8)'9') {
                return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
            }
            digit = (pic_u32)(digit_char - (pic_u8)'0');
            if (ordinal_value > (0xFFFFu - digit) / 10u) {
                return pic_fail(ctx, PIC_RESOLVE_ORDINAL_OUT_OF_RANGE);
            }
            ordinal_value = ordinal_value * 10u + digit;
        }
        return pic_resolve_ordinal(ctx, module_base,
                                   (pic_u16)ordinal_value, address);
    }
    {
        PIC_HASH entry_hash;
        pic_hash_ascii_upper((const pic_u8 *)forwarder + entry_off, entry_len,
                             &entry_hash);
        return pic_resolve_export(ctx, module_base, &entry_hash, address);
    }
}

/* Case-insensitive compare of contract[0..units) against byte-read schema
 * name bytes. */
static PIC_CODE pic_bool pic_apiset_name_equal(const pic_u16 *contract,
                                       pic_u32 units,
                                       const pic_u8 *stored)
{
    pic_u32 index;

    for (index = 0u; index < units; ++index) {
        if (pic_fold_u16(contract[index]) !=
            pic_fold_u16(pic_read_u16(stored + index * 2u))) {
            return PIC_FALSE;
        }
    }
    return PIC_TRUE;
}

PIC_CODE PIC_RESOLVE_STATUS PIC_MS_ABI pic_resolve_apiset_contract(
    PIC_CONTEXT *ctx,
    const pic_u16 *contract,
    pic_u32 contract_code_units,
    void **module_base)
{
    PIC_PEB *peb;
    const pic_u8 *schema;
    pic_u32 schema_size;
    pic_u32 entry_count;
    pic_u32 entry_offset;
    pic_u32 hashed_units;
    pic_u32 cut;
    pic_bool have_cut;
    pic_u32 index;
    pic_u16 p0;
    pic_u16 p1;
    pic_u16 p2;
    pic_u16 p3;

    if (ctx == PIC_NULL || contract == PIC_NULL || module_base == PIC_NULL ||
        contract_code_units == 0u ||
        contract_code_units > PIC_MAX_APISET_CONTRACT_CHARS) {
        return PIC_RESOLVE_BAD_ARGUMENT;
    }
    *module_base = PIC_NULL;

    /* Loader rule: contract names start with api- or ext- (any case).  A
     * trailing ".dll" is accepted and ignored by the truncation below. */
    if (contract_code_units < 4u) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_ARGUMENT);
    }
    p0 = pic_fold_u16(contract[0]);
    p1 = pic_fold_u16(contract[1]);
    p2 = pic_fold_u16(contract[2]);
    p3 = pic_fold_u16(contract[3]);
    if (!((p0 == (pic_u16)'A' && p1 == (pic_u16)'P' && p2 == (pic_u16)'I' &&
           p3 == (pic_u16)'-') ||
          (p0 == (pic_u16)'E' && p1 == (pic_u16)'X' && p2 == (pic_u16)'T' &&
           p3 == (pic_u16)'-'))) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_ARGUMENT);
    }

    /* Loader rule: matching uses the name truncated at the last hyphen. */
    have_cut = PIC_FALSE;
    for (index = contract_code_units; index > 0u; --index) {
        if (contract[index - 1u] == (pic_u16)'-') {
            cut = index - 1u;
            have_cut = PIC_TRUE;
            break;
        }
    }
    if (have_cut != PIC_TRUE || cut == 0u) {
        return pic_fail(ctx, PIC_RESOLVE_BAD_ARGUMENT);
    }
    hashed_units = cut;

    peb = pic_current_peb();
    if (peb == PIC_NULL) {
        ctx->last_error = (pic_u32)PIC_RESOLVE_NO_PEB;
        return PIC_RESOLVE_NO_PEB;
    }
    if (peb->ApiSetMap == PIC_NULL) {
        return pic_fail(ctx, PIC_RESOLVE_APISET_UNSUPPORTED);
    }
    schema = (const pic_u8 *)peb->ApiSetMap;

    if (pic_read_u32(schema + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE, version)) !=
        PIC_APISET_SCHEMA_VERSION_6) {
        return pic_fail(ctx, PIC_RESOLVE_APISET_UNSUPPORTED);
    }
    schema_size = pic_read_u32(
        schema + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE, size));
    entry_count = pic_read_u32(
        schema + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE, count));
    entry_offset = pic_read_u32(
        schema + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE, entry_offset));
    if (schema_size == 0u || entry_count == 0u ||
        entry_count > PIC_MAX_APISET_ENTRIES) {
        return pic_fail(ctx, PIC_RESOLVE_APISET_UNSUPPORTED);
    }
    if (!pic_range_within(entry_offset,
                          entry_count *
                              (pic_u32)sizeof(PIC_APISET_NAMESPACE_ENTRY),
                          schema_size)) {
        return pic_fail(ctx, PIC_RESOLVE_APISET_UNSUPPORTED);
    }

    for (index = 0u; index < entry_count; ++index) {
        const pic_u8 *entry = schema + entry_offset +
                              index *
                                  (pic_u32)sizeof(PIC_APISET_NAMESPACE_ENTRY);
        pic_u32 name_offset = pic_read_u32(
            entry + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE_ENTRY, name_offset));
        pic_u32 hashed_length = pic_read_u32(
            entry + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE_ENTRY, hashed_length));
        pic_u32 value_offset = pic_read_u32(
            entry + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE_ENTRY, value_offset));
        pic_u32 value_count = pic_read_u32(
            entry + (pic_u32)PIC_OFFSETOF(PIC_APISET_NAMESPACE_ENTRY, value_count));
        const pic_u8 *value;
        pic_u32 host_offset;
        pic_u32 host_length;
        pic_u32 host_units;
        PIC_HASH host_hash;

        if (hashed_length == 0u || (hashed_length & 1u) != 0u ||
            hashed_length / 2u != hashed_units ||
            !pic_range_within(name_offset, hashed_length, schema_size)) {
            continue;
        }
        if (pic_apiset_name_equal(contract, hashed_units,
                                  schema + name_offset) != PIC_TRUE) {
            continue;
        }

        /* Match: default (first) value entry is the host. */
        if (value_count == 0u || value_count > PIC_MAX_APISET_VALUES ||
            !pic_range_within(value_offset,
                              value_count *
                                  (pic_u32)sizeof(PIC_APISET_VALUE_ENTRY),
                              schema_size)) {
            return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
        }
        value = schema + value_offset;
        host_offset = pic_read_u32(
            value + (pic_u32)PIC_OFFSETOF(PIC_APISET_VALUE_ENTRY, value_offset));
        host_length = pic_read_u32(
            value + (pic_u32)PIC_OFFSETOF(PIC_APISET_VALUE_ENTRY, value_length));
        if (host_length == 0u || (host_length & 1u) != 0u ||
            !pic_range_within(host_offset, host_length, schema_size)) {
            return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
        }
        host_units = host_length / 2u;
        if (host_units > PIC_MAX_MODULE_NAME_CHARS) {
            return pic_fail(ctx, PIC_RESOLVE_BOUND_EXCEEDED);
        }

        /* Schema values include the ".dll" suffix; strip it so the hash
         * matches Ldr BaseDllName contents. */
        if (host_units >= 5u) {
            const pic_u8 *suffix = schema + host_offset + (host_units - 4u) * 2u;
            if (pic_fold_u16(pic_read_u16(suffix)) == (pic_u16)'.' &&
                pic_fold_u16(pic_read_u16(suffix + 2u)) == (pic_u16)'D' &&
                pic_fold_u16(pic_read_u16(suffix + 4u)) == (pic_u16)'L' &&
                pic_fold_u16(pic_read_u16(suffix + 6u)) == (pic_u16)'L') {
                host_units -= 4u;
            }
        }
        if (host_units == 0u) {
            return pic_fail(ctx, PIC_RESOLVE_BAD_IMAGE);
        }

        pic_hash_utf16_bytes_upper(schema + host_offset, host_units, &host_hash);
        if (pic_hash_is_zero(&host_hash) == PIC_TRUE) {
            return pic_fail(ctx, PIC_RESOLVE_BOUND_EXCEEDED);
        }
        return pic_find_module(ctx, &host_hash, module_base);
    }

    return pic_fail(ctx, PIC_RESOLVE_MODULE_NOT_FOUND);
}
