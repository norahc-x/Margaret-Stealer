.intel_syntax noprefix

.section .text$A,"xr"
.global margaret_blob_start
.global margaret_entry
.extern margaret_main
.extern margaret_blob_end

/*
 * CALL entry only: RSP % 16 == 8. Preserve nonvolatile GPRs and reserve
 * aligned shadow space before C. Unwinding across the blob is unsupported.
 */
margaret_blob_start:
margaret_entry:
    push rbp
    mov  rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  r12, rcx
    sub  rsp, 0x28
    mov  rcx, r12
    lea  rdx, [rip + margaret_blob_start]
    lea  r8, [rip + margaret_blob_end]
    sub  r8, rdx
    call margaret_main
    add  rsp, 0x28

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
