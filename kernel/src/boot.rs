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
    cld
    mov %rsp, %rdi
    call isr_handler
    /* from user mode: the process stops here, back to the main loop */
    testb $3, 144(%rsp)
    jnz from_user
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
from_user:
    mov %rsp, %rdi
    call user_trap
    jmp kernel_resume

/* vectors >= 48: nothing of ours, just ack a possible local-APIC interrupt
   (device MSIs); from user mode the process stops too */
    .global isr_other
isr_other:
    push %rax
    mov $0xFEE000B0, %rax
    movl $0, (%rax)
    pop %rax
    testb $3, 8(%rsp)
    jnz 1f
    iretq
1:  push $0
    push $255
    jmp isr_common

/* ---- user mode (proc.rs): user_enter(regs) runs the process until a
   system call, an interrupt or a fault, then returns the reason (1, 2, 3)
   on the main loop's stack. UserRegs: rax rbx rcx rdx rsi rdi rbp r8-r15
   (0..112), rip 120, rflags 128, rsp 136. */
    .global user_enter
user_enter:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, kctx_rsp(%rip)
    mov %rdi, cur_regs(%rip)
    pushq $0x23
    pushq 136(%rdi)
    pushq 128(%rdi)
    pushq $0x2B
    pushq 120(%rdi)
    mov 0(%rdi), %rax
    mov 8(%rdi), %rbx
    mov 16(%rdi), %rcx
    mov 24(%rdi), %rdx
    mov 32(%rdi), %rsi
    mov 48(%rdi), %rbp
    mov 56(%rdi), %r8
    mov 64(%rdi), %r9
    mov 72(%rdi), %r10
    mov 80(%rdi), %r11
    mov 88(%rdi), %r12
    mov 96(%rdi), %r13
    mov 104(%rdi), %r14
    mov 112(%rdi), %r15
    mov 40(%rdi), %rdi
    iretq

/* back on the main loop's stack, out of user_enter with eax = reason */
kernel_resume:
    mov kctx_rsp(%rip), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret

/* `syscall` (Linux ABI): rcx = return address, r11 = rflags, interrupts
   off (SFMASK); the registers go into the process's UserRegs */
    .global syscall_entry
syscall_entry:
    mov %rsp, user_rsp(%rip)
    mov cur_regs(%rip), %rsp
    mov %rax, 0(%rsp)
    mov %rbx, 8(%rsp)
    mov %rcx, 16(%rsp)
    mov %rdx, 24(%rsp)
    mov %rsi, 32(%rsp)
    mov %rdi, 40(%rsp)
    mov %rbp, 48(%rsp)
    mov %r8, 56(%rsp)
    mov %r9, 64(%rsp)
    mov %r10, 72(%rsp)
    mov %r11, 80(%rsp)
    mov %r12, 88(%rsp)
    mov %r13, 96(%rsp)
    mov %r14, 104(%rsp)
    mov %r15, 112(%rsp)
    mov %rcx, 120(%rsp)
    mov %r11, 128(%rsp)
    mov user_rsp(%rip), %rax
    mov %rax, 136(%rsp)
    cld
    mov $1, %eax
    jmp kernel_resume

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
    .balign 8
kctx_rsp: .skip 8
cur_regs: .skip 8
user_rsp: .skip 8
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
