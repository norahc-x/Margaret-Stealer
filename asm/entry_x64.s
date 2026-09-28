.intel_syntax noprefix

.section .text$A,"xr"
.global margaret_blob_start
.global margaret_entry
.extern margaret_main
.extern margaret_blob_end

/*
 * Margaret x64 shellcode ABI:
 *   RCX = MARGARET_ARGS* (may be NULL; C returns BAD_ARGUMENT)
 *   RAX = MARGARET_STATUS
 *
 * The C function follows the Windows x64 ABI.  This stub preserves every
 * nonvolatile GPR it touches/potentially exposes and reserves 32 bytes of
 * shadow space plus 8 bytes to align RSP to 16 before CALL.  XMM6-XMM15 are
 * untouched by the stub and are preserved by the conforming C callee.
 * Unwind metadata is deliberately absent; exceptions/unwinding across the
 * blob are unsupported.
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
