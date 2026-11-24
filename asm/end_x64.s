.intel_syntax noprefix

.section .text$Z,"xr"
.global margaret_blob_end

/* Aligned NOP tail; margaret_blob_end is the extracted size at base zero. */
.byte 0x90
.balign 16, 0x90
margaret_blob_end:
