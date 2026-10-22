//! Multiboot2 header and the 32-bit -> 64-bit trampoline.
//!
//! GRUB (BIOS or UEFI) jumps to `_start` in 32-bit protected mode with paging
//! off, EAX = multiboot2 magic and EBX = physical address of the boot info.
//! We identity-map the first 4 GiB with 2 MiB pages, enter long mode and call
//! `kmain(magic, info)`.

core::arch::global_asm!(
    r#"
    .section .multiboot, "a"
    .balign 8
mb2_start:
    .long 0xE85250D6
    .long 0
    .long mb2_end - mb2_start
    .long 0x100000000 - (0xE85250D6 + (mb2_end - mb2_start))
    /* framebuffer request, optional: 1024x768x32 */
    .balign 8
    .short 5, 1
    .long 20
    .long 1024, 768, 32
    /* end tag */
    .balign 8
    .short 0, 0
    .long 8
mb2_end:

    .section .text.boot, "ax"
    .code32
    .global _start
_start:
    cli
    cld
    mov $boot_stack_top, %esp
    mov %eax, boot_magic
    mov %ebx, boot_info

    /* clear PML4 + PDPT */
    mov $boot_pml4, %edi
    xor %eax, %eax
    mov $2048, %ecx
    rep stosl

    /* PML4[0] -> PDPT, PDPT[0..4] -> 4 page directories */
    mov $boot_pdpt, %eax
    or $3, %eax
    mov %eax, boot_pml4
    mov $boot_pd, %eax
    or $3, %eax
    mov $boot_pdpt, %edi
    mov $4, %ecx
1:  mov %eax, (%edi)
    movl $0, 4(%edi)
    add $4096, %eax
    add $8, %edi
    loop 1b

    /* 2048 x 2 MiB pages = 4 GiB identity map */
    mov $boot_pd, %edi
    xor %ecx, %ecx
2:  mov %ecx, %eax
    shl $21, %eax
    or $0x83, %eax
    mov %eax, (%edi,%ecx,8)
    movl $0, 4(%edi,%ecx,8)
    inc %ecx
    cmp $2048, %ecx
    jb 2b

    mov $boot_pml4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $0x20, %eax              /* PAE */
    mov %eax, %cr4
    mov $0xC0000080, %ecx       /* EFER */
    rdmsr
    or $0x100, %eax             /* LME */
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax        /* PG | PE */
    mov %eax, %cr0
    lgdt gdt64_ptr
    ljmp $0x08, $long_mode

    .code64
long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs
    mov $boot_stack_top, %rsp
    movl boot_magic, %edi
    movl boot_info, %esi
    call kmain
3:  cli
    hlt
    jmp 3b

/* ---- interrupt entry stubs ---- */
    .macro ISR_NOERR num
isr_\num:
    push $0
    push $\num
    jmp isr_common
    .endm
    .macro ISR_ERR num
isr_\num:
    push $\num
    jmp isr_common
    .endm

    .irp num, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31
    ISR_NOERR \num
    .endr
    .irp num, 8,10,11,12,13,14,17,21,29,30
    ISR_ERR \num
    .endr
    .irp num, 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
    ISR_NOERR \num
    .endr

isr_common:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, %rdi
    call isr_handler
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    add $16, %rsp
    iretq

/* vectors >= 48: nothing of ours, just ack a possible local-APIC interrupt */
    .global isr_other
isr_other:
    push %rax
    mov $0xFEE000B0, %rax
    movl $0, (%rax)
    pop %rax
    iretq

    .section .rodata
    .balign 8
    .global isr_table
isr_table:
    .irp num, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
    .quad isr_\num
    .endr

    .balign 8
gdt64:
    .quad 0
    .quad 0x00AF9A000000FFFF    /* 0x08: 64-bit code */
    .quad 0x00CF92000000FFFF    /* 0x10: data */
gdt64_ptr:
    .short gdt64_ptr - gdt64 - 1
    .long gdt64

    .section .bss
    .balign 4096
    .global boot_pml4, boot_pdpt
boot_pml4: .skip 4096
boot_pdpt: .skip 4096
boot_pd:   .skip 4096 * 4
boot_magic: .skip 4
boot_info:  .skip 4
    .balign 16
    .skip 256 * 1024
boot_stack_top:
"#,
    options(att_syntax)
);
