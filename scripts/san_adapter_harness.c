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
 *   ./san_harness <chrome.dll> <expectedDeobfHex> <expectedVtableHex>
 * Exit 0 = discovery matched expectations, gates behaved, sanitizers silent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* the exact shipped TU (statics become visible) */
#include "../src/adapter.c"


/* stub: LocateChromeDll links against the resolver; the harness
 * never calls it (the image is loaded by LoadImage) */
RESOLVE_STATUS MS_ABI FindModule(RESOLVER_CONTEXT *ctx,
                                              const API_HASH *hash,
                                              PVOID*out)
{
    (void)ctx; (void)hash; *out = NULL;
    return ResolveStatusModuleNotFound;
}

static uint8_t *LoadImage(const char *path, uint32_t *outSize)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long fsz;
    uint32_t imageSize, lfanew, nsec, opt, i;

    if (!f) { perror("open"); return NULL; }
    fseek(f, 0, SEEK_END); fsz = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsz < 0x1000) { fclose(f); return NULL; }

    lfanew = AdapterReadU32((const uint8_t *)"\0\0\0\0" /* placeholder */);
    (void)lfanew;

    /* header pass on a raw copy to learn sizes */
    {
        uint8_t *raw = (uint8_t *)malloc((size_t)fsz);
        if (!raw || fread(raw, 1, (size_t)fsz, f) != (size_t)fsz) {
            free(raw); fclose(f); return NULL;
        }
        imageSize = AdapterImageSize(raw);
        if (imageSize == 0u) { free(raw); fclose(f); return NULL; }
        buf = (uint8_t *)calloc(1, imageSize);
        if (!buf) { free(raw); fclose(f); return NULL; }

        /* DOS + NT headers at offset 0 */
        memcpy(buf, raw, 0x1000);
        lfanew = AdapterReadU32(buf + 0x3Cu);
        nsec = AdapterReadU16(buf + lfanew + 0x06u);
        opt = AdapterReadU16(buf + lfanew + 0x14u);
        for (i = 0u; i < nsec; i++) {
            const uint8_t *s = buf + lfanew + 0x18u + opt + i * 40u;
            uint32_t vsize = AdapterReadU32(s + 0x08u);
            uint32_t va = AdapterReadU32(s + 0x0Cu);
            uint32_t rsize = AdapterReadU32(s + 0x10u);
            uint32_t rawoff = AdapterReadU32(s + 0x14u);
            if (rsize > vsize) rsize = vsize;
            if (va + rsize > imageSize) rsize = imageSize - va;
            if (rsize) memcpy(buf + va, raw + rawoff, rsize);
        }
        free(raw);
    }
    fclose(f);
    *outSize = imageSize;
    return buf;
}

/* simulate loader relocations: .rdata qwords that pointed into the
 * on-disk image (IB 0x180000000) now point into our buffer */
static void relocate(uint8_t *buf, uint32_t imageSize)
{
    const uint64_t IB = 0x180000000ull;
    uint32_t rdRva, rdSize, off;
    if (!AdapterSectionRange(buf, (const uint8_t *)".rdata\0\0",
                                &rdRva, &rdSize)) {
        return;
    }
    if ((uint64_t)rdRva + rdSize > imageSize) return;
    for (off = rdRva; off + 8u <= rdRva + rdSize; off += 8u) {
        uint64_t v = AdapterReadU64(buf + off);
        if (v >= IB && v - IB < 0x14000000ull) {
            uint64_t nv = (uint64_t)(uintptr_t)buf + (v - IB);
            memcpy(buf + off, &nv, 8);
        }
    }
}

int main(int argc, char **argv)
{
    uint32_t imageSize;
    uint8_t *img;
    uint32_t expDeobf, expVt, textRva, textSize, rdRva, rdSize;
    uint32_t gotDeobf = 0, gotVt = 0;
    uint64_t baseVa;
    int ok = 1;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <dll> <deobfHex> <vtableHex>\n", argv[0]);
        return 2;
    }
    expDeobf = (uint32_t)strtoul(argv[2], NULL, 16);
    expVt = (uint32_t)strtoul(argv[3], NULL, 16);

    img = LoadImage(argv[1], &imageSize);
    if (!img) { fprintf(stderr, "load failed\n"); return 2; }
    baseVa = (uint64_t)(uintptr_t)img;
    relocate(img, imageSize);

    if (!AdapterSectionRange(img, (const uint8_t *)".text\0\0\0",
                               &textRva, &textSize) ||
        !AdapterSectionRange(img, (const uint8_t *)".rdata\0\0",
                               &rdRva, &rdSize)) {
        fprintf(stderr, "sections not found\n"); free(img); return 2;
    }

    /* exact shipped discovery */
    if (AdapterDiscoverDeobfuscator(img, textRva, textSize, &gotDeobf)) {
        printf("deobf: %#x (expected %#x) %s\n", gotDeobf, expDeobf,
               gotDeobf == expDeobf ? "OK" : "MISMATCH");
        ok &= (gotDeobf == expDeobf);
    } else { printf("deobf: DISCOVERY-FAILED (expected %#x)\n", expDeobf); ok = 0; }

    if (AdapterDiscoverVtable(img, baseVa, textRva, textSize,
                                rdRva, rdSize, &gotVt)) {
        printf("vtable: %#x (expected %#x) %s\n", gotVt, expVt,
               gotVt == expVt ? "OK" : "MISMATCH");
        ok &= (gotVt == expVt);
    } else { printf("vtable: DISCOVERY-FAILED (expected %#x)\n", expVt); ok = 0; }

    free(img);
    printf(ok ? "RESULT: PASS\n" : "RESULT: FAIL\n");
    return ok ? 0 : 1;
}
