#define CODE_SECTION_NAME ".text$C"
#include "margaret.h"

CODE_SECTION PVOID MS_ABI MargaretMemzero(PVOID buffer, SIZE_T length)
{
    volatile BYTE *cursor;

    if (buffer == NULL) {
        return NULL;
    }

    cursor = (volatile BYTE *)buffer;
    while (length != 0u) {
        *cursor = 0u;
        ++cursor;
        --length;
    }
    return buffer;
}

CODE_SECTION PVOID MS_ABI MargaretMemcpy(PVOID destination,
                                          PCVOID source,
                                          SIZE_T length)
{
    PBYTE out;
    const BYTE *in;

    if (destination == NULL || source == NULL) {
        return NULL;
    }

    out = (PBYTE)destination;
    in = (const BYTE *)source;
    while (length != 0u) {
        *out = *in;
        ++out;
        ++in;
        --length;
    }
    return destination;
}
