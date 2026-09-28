/*
 * san_adapter_harness.c — ASan/UBSan host harness for the shipped
 * adapter/discovery code (src/adapter.c, byte-identical TU).
 *
 * Loads a pinned chrome.dll the way the live process maps it (headers +
 * each section at its virtual offset, .rdata slots relocated to the
 * buffer address), then runs the exact runtime discovery and the pinned
 * adapter gates.  Any out-of-bounds read of the image or undefined
 * behavior in the scanner trips ASan/UBSan.
 *
 * Build (see scripts/run_san.sh):
 *   gcc -fsanitize=address,undefined -O1 -g -Iinclude \
 *       scripts/san_adapter_harness.c src/runtime.c -o build/san_harness
 *
 * Usage:
 *   ./san_harness <chrome.dll> <expected_deobf_hex> <expected_vtable_hex>
 * Exit 0 = discovery matched expectations, gates behaved, sanitizers silent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* the exact shipped TU (statics become visible) */
#include "../src/adapter.c"


/* stub: locate_chrome_dll links against the resolver; the harness
 * never calls it (the image is loaded by load_image) */
PIC_RESOLVE_STATUS PIC_MS_ABI pic_find_module(PIC_CONTEXT *ctx,
                                              const PIC_HASH *hash,
                                              void **out)
{
    (void)ctx; (void)hash; *out = NULL;
    return PIC_RESOLVE_MODULE_NOT_FOUND;
}

static uint8_t *load_image(const char *path, uint32_t *out_size)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long fsz;
    uint32_t image_size, lfanew, nsec, opt, i;

    if (!f) { perror("open"); return NULL; }
    fseek(f, 0, SEEK_END); fsz = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsz < 0x1000) { fclose(f); return NULL; }

    lfanew = adapter_read_u32((const uint8_t *)"\0\0\0\0" /* placeholder */);
    (void)lfanew;

    /* header pass on a raw copy to learn sizes */
    {
        uint8_t *raw = (uint8_t *)malloc((size_t)fsz);
        if (!raw || fread(raw, 1, (size_t)fsz, f) != (size_t)fsz) {
            free(raw); fclose(f); return NULL;
        }
        image_size = adapter_image_size(raw);
        if (image_size == 0u) { free(raw); fclose(f); return NULL; }
        buf = (uint8_t *)calloc(1, image_size);
        if (!buf) { free(raw); fclose(f); return NULL; }

        /* DOS + NT headers at offset 0 */
        memcpy(buf, raw, 0x1000);
        lfanew = adapter_read_u32(buf + 0x3Cu);
        nsec = adapter_read_u16(buf + lfanew + 0x06u);
        opt = adapter_read_u16(buf + lfanew + 0x14u);
        for (i = 0u; i < nsec; i++) {
            const uint8_t *s = buf + lfanew + 0x18u + opt + i * 40u;
            uint32_t vsize = adapter_read_u32(s + 0x08u);
            uint32_t va = adapter_read_u32(s + 0x0Cu);
            uint32_t rsize = adapter_read_u32(s + 0x10u);
            uint32_t rawoff = adapter_read_u32(s + 0x14u);
            if (rsize > vsize) rsize = vsize;
            if (va + rsize > image_size) rsize = image_size - va;
            if (rsize) memcpy(buf + va, raw + rawoff, rsize);
        }
        free(raw);
    }
    fclose(f);
    *out_size = image_size;
    return buf;
}

/* simulate loader relocations: .rdata qwords that pointed into the
 * on-disk image (IB 0x180000000) now point into our buffer */
static void relocate(uint8_t *buf, uint32_t image_size)
{
    const uint64_t IB = 0x180000000ull;
    uint32_t rd_rva, rd_size, off;
    if (!adapter_section_range(buf, (const uint8_t *)".rdata\0\0",
                                &rd_rva, &rd_size)) {
        return;
    }
    if ((uint64_t)rd_rva + rd_size > image_size) return;
    for (off = rd_rva; off + 8u <= rd_rva + rd_size; off += 8u) {
        uint64_t v = adapter_read_u64(buf + off);
        if (v >= IB && v - IB < 0x14000000ull) {
            uint64_t nv = (uint64_t)(uintptr_t)buf + (v - IB);
            memcpy(buf + off, &nv, 8);
        }
    }
}

int main(int argc, char **argv)
{
    uint32_t image_size;
    uint8_t *img;
    uint32_t exp_deobf, exp_vt, text_rva, text_size, rd_rva, rd_size;
    uint32_t got_deobf = 0, got_vt = 0;
    uint64_t base_va;
    int ok = 1;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <dll> <deobf_hex> <vtable_hex>\n", argv[0]);
        return 2;
    }
    exp_deobf = (uint32_t)strtoul(argv[2], NULL, 16);
    exp_vt = (uint32_t)strtoul(argv[3], NULL, 16);

    img = load_image(argv[1], &image_size);
    if (!img) { fprintf(stderr, "load failed\n"); return 2; }
    base_va = (uint64_t)(uintptr_t)img;
    relocate(img, image_size);

    if (!adapter_section_range(img, (const uint8_t *)".text\0\0\0",
                               &text_rva, &text_size) ||
        !adapter_section_range(img, (const uint8_t *)".rdata\0\0",
                               &rd_rva, &rd_size)) {
        fprintf(stderr, "sections not found\n"); free(img); return 2;
    }

    /* exact shipped discovery */
    if (adapter_discover_deobfuscator(img, text_rva, text_size, &got_deobf)) {
        printf("deobf: %#x (expected %#x) %s\n", got_deobf, exp_deobf,
               got_deobf == exp_deobf ? "OK" : "MISMATCH");
        ok &= (got_deobf == exp_deobf);
    } else { printf("deobf: DISCOVERY-FAILED (expected %#x)\n", exp_deobf); ok = 0; }

    if (adapter_discover_vtable(img, base_va, text_rva, text_size,
                                rd_rva, rd_size, &got_vt)) {
        printf("vtable: %#x (expected %#x) %s\n", got_vt, exp_vt,
               got_vt == exp_vt ? "OK" : "MISMATCH");
        ok &= (got_vt == exp_vt);
    } else { printf("vtable: DISCOVERY-FAILED (expected %#x)\n", exp_vt); ok = 0; }

    free(img);
    printf(ok ? "RESULT: PASS\n" : "RESULT: FAIL\n");
    return ok ? 0 : 1;
}
