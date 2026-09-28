OUTPUT_FORMAT(pei-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(margaret_entry)

SECTIONS
{
    . = 0;

    .text ALIGN(16) :
    {
        __margaret_text_start = .;
        KEEP(*(.text$A))
        *(.text$B)
        *(.text$C)
        *(.text$D)
        *(.text$E)
        __margaret_rodata_start = .;
         *(.text$R)
        __margaret_rodata_end = .;
        *(.text$F)
        *(.text$G)
        KEEP(*(.text$Z))
        __margaret_text_end = .;
    }

    /* Any runtime-bearing section here is a build failure.  The verifier also
     * checks input objects so this section is diagnostic, not a discard path. */
    .unexpected ALIGN(16) :
    {
        *(.text)
        *(.text.*)
        *(.text$*)
        *(.rdata)
        *(.rdata.*)
        *(.rodata)
        *(.rodata.*)
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
        *(COMMON)
        *(.idata)
        *(.idata.*)
        *(.reloc)
        *(.reloc.*)
        *(.pdata)
        *(.pdata.*)
        *(.xdata)
        *(.xdata.*)
        *(.tls)
        *(.tls.*)
        *(.CRT)
        *(.CRT.*)
        *(.drectve)
        *(.eh_frame)
        *(.eh_frame.*)
        *(.gcc_except_table*)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.debug*)
        *(.gnu.attributes)
    }

    __margaret_blob_size = margaret_blob_end - margaret_entry;

    ASSERT(margaret_entry == ADDR(.text),
           "Margaret entry must be the first extracted byte")
    ASSERT(margaret_blob_start == margaret_entry,
           "Margaret anchor and entry must match")
    ASSERT(margaret_blob_end == __margaret_text_end,
           "Margaret end marker must terminate the extracted range")
    ASSERT(SIZEOF(.unexpected) == 0,
           "Unexpected runtime-bearing input section")
    ASSERT(__margaret_blob_size > 0,
           "Margaret blob must not be empty")
    ASSERT(__margaret_blob_size <= 0x10000,
           "Margaret milestone-1 size limit is 64 KiB")
}
