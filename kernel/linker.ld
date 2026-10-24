ENTRY(_start)

/* One packed segment: the image goes into a 256 KiB slot, so no page
   alignment padding between sections (there is no W^X to keep apart). */
PHDRS
{
    image PT_LOAD FLAGS(7);
    zero PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 1M;
    .text : ALIGN(64) {
        KEEP(*(.multiboot))
        *(.text.boot)
        *(.text .text.*)
    } :image
    .rodata : ALIGN(64) { *(.rodata .rodata.*) } :image
    .data : ALIGN(64) { *(.data .data.*) *(.got .got.*) } :image
    .bss : ALIGN(4K) {
        *(.bss .bss.*)
        *(COMMON)
    } :zero
    __kernel_end = .;
    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
