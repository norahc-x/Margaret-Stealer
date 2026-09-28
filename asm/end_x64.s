.intel_syntax noprefix

.section .text$Z,"xr"
.global margaret_blob_end

/* Deliberate NOP tail, including alignment bytes.  margaret_blob_end denotes
 * the first byte beyond the raw blob and therefore equals the extracted file
 * size at base zero. */
.byte 0x90
.balign 16, 0x90
margaret_blob_end:
