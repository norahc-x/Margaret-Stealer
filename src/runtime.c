#define PIC_CODE_SECTION_NAME ".text$C"
#include "margaret.h"

PIC_CODE void *PIC_MS_ABI margaret_memzero(void *buffer, pic_size length)
{
    volatile pic_u8 *cursor;

    if (buffer == PIC_NULL) {
        return PIC_NULL;
    }

    cursor = (volatile pic_u8 *)buffer;
    while (length != 0u) {
        *cursor = 0u;
        ++cursor;
        --length;
    }
    return buffer;
}

PIC_CODE void *PIC_MS_ABI margaret_memcpy(void *destination,
                                          const void *source,
                                          pic_size length)
{
    pic_u8 *out;
    const pic_u8 *in;

    if (destination == PIC_NULL || source == PIC_NULL) {
        return PIC_NULL;
    }

    out = (pic_u8 *)destination;
    in = (const pic_u8 *)source;
    while (length != 0u) {
        *out = *in;
        ++out;
        ++in;
        --length;
    }
    return destination;
}
