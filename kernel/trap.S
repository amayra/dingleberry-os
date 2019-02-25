#include "memory.h"

/* Offsets/sizes for struct asm_regs. */
#define ASM_REGS_SIZE   (32 * 8 + 6 * 8)
#define ASM_REGS_REGS   (0 * 8)
#define ASM_REGS_PC     (32 * 8 + 0 * 8)
#define ASM_REGS_STATUS (32 * 8 + 1 * 8)
#define ASM_REGS_CAUSE  (32 * 8 + 2 * 8)
#define ASM_REGS_TVAL   (32 * 8 + 3 * 8)
#define ASM_REGS_IP     (32 * 8 + 4 * 8)

/* Offsets for struct thread. */
#define THREAD_SCRATCH_SP   (0 * 8)
#define THREAD_SCRATCH_TP   (1 * 8)
#define THREAD_SYSCALL_RA   (2 * 8)
#define THREAD_SYSCALL_SP   (3 * 8)
#define THREAD_SYSCALL_GP   (4 * 8)
#define THREAD_SYSCALL_TP   (5 * 8)
#define THREAD_SYSCALL_PC   (6 * 8)
#define THREAD_KERNEL_GP    (7 * 8)

/* Number of entries in syscall_table[]. */
#define ASM_SYSCALL_COUNT   4

/* Load/Store operation for all registers, _except_ sp (x2) and tp (x4). */
#define ALL_REGS_LS(INS, BASE, BREG)    \
    INS x1,  (BASE +  1 * 8)(BREG);     \
    INS x3,  (BASE +  3 * 8)(BREG);     \
    INS x5,  (BASE +  5 * 8)(BREG);     \
    INS x6,  (BASE +  6 * 8)(BREG);     \
    INS x7,  (BASE +  7 * 8)(BREG);     \
    INS x8,  (BASE +  8 * 8)(BREG);     \
    INS x9,  (BASE +  9 * 8)(BREG);     \
    INS x10, (BASE + 10 * 8)(BREG);     \
    INS x11, (BASE + 11 * 8)(BREG);     \
    INS x12, (BASE + 12 * 8)(BREG);     \
    INS x13, (BASE + 13 * 8)(BREG);     \
    INS x14, (BASE + 14 * 8)(BREG);     \
    INS x15, (BASE + 15 * 8)(BREG);     \
    INS x16, (BASE + 16 * 8)(BREG);     \
    INS x17, (BASE + 17 * 8)(BREG);     \
    INS x18, (BASE + 18 * 8)(BREG);     \
    INS x19, (BASE + 19 * 8)(BREG);     \
    INS x20, (BASE + 20 * 8)(BREG);     \
    INS x21, (BASE + 21 * 8)(BREG);     \
    INS x22, (BASE + 22 * 8)(BREG);     \
    INS x23, (BASE + 23 * 8)(BREG);     \
    INS x24, (BASE + 24 * 8)(BREG);     \
    INS x25, (BASE + 25 * 8)(BREG);     \
    INS x26, (BASE + 26 * 8)(BREG);     \
    INS x27, (BASE + 27 * 8)(BREG);     \
    INS x28, (BASE + 28 * 8)(BREG);     \
    INS x29, (BASE + 29 * 8)(BREG);     \
    INS x30, (BASE + 30 * 8)(BREG);     \
    INS x31, (BASE + 31 * 8)(BREG)

.section ".text", "ax"

.balign 32
.globl trap
trap:
    /* sscratch always holds the thread pointer. When coming from user mode,
     * this is also the kernel stack pointer, as the stack is located below the
     * thread struct, and nothing is pushed on the kernel stack yet. In kernel
     * mode, this is normally a NOP, because the kernel never changes tp (except
     * on context switches, where it also changes sscratch).
     * (NB: Linux sets sscratch to 0 in kernel mode to detect whether the trap
     * came from user or kernel mode, but I think this makes it harder to
     * recover from unexpected kernel exceptions, i.e. bugs. And even then we'd
     * need to rely on tp being correct. In particular, we want to be able to
     * detect kernel stack overflows.) */
    csrrw tp, sscratch, tp

    /* Free up a register (sp), to get some space to work with. */
    sd sp, (THREAD_SCRATCH_SP)(tp)

    /* Save user tp and restore the sscratch register. Restoring sscratch early
     * seems very important to be able to handle kernel exceptions. (If we're
     * coming from kernel mode, this register shouldn't have changed.) */
    csrrw sp, sscratch, tp
    sd sp, (THREAD_SCRATCH_TP)(tp)

    /* Entering from kernel mode? */
    csrr sp, sstatus
    andi sp, sp, (1 << 8) /* SPP */
    bnez sp, kernel_trap

    /* Check whether this is a syscall (scause == 8). If it's an exception or
     * IRQ, use the generic trap handler. Do this because we want to PREMATURELY
     * OPTIMIZE the syscall entry path. It would be simpler to always use the
     * full path. */
    csrr sp, scause
    addi sp, sp, -8
    bnez sp, user_trap

    /* Save the normal syscall-saved registers. */
    sd ra, (THREAD_SYSCALL_RA)(tp)
    sd gp, (THREAD_SYSCALL_GP)(tp)
    /* (sp/tp need to be awkwardly retrieved from above. Sure would be nice
     * to have 2 more sscratch regs, or different trap vectors, etc.) */
    ld ra, (THREAD_SCRATCH_SP)(tp)
    sd ra, (THREAD_SYSCALL_SP)(tp)
    ld ra, (THREAD_SCRATCH_TP)(tp)
    sd ra, (THREAD_SYSCALL_TP)(tp)

    csrr ra, sepc
    addi ra, ra, 4
    sd ra, (THREAD_SYSCALL_PC)(tp)

    /* Setup kernel stack. */
    mv sp, tp

    /* (Could be computed, but doing so in C seems less messy for now.) */
    ld gp, (THREAD_KERNEL_GP)(tp)

    /* Dispatch the syscall. */
    li t0, ASM_SYSCALL_COUNT
    bltu a7, t0, 1f
    li t1, 1
    la t0, syscall_unavailable
    mv a0, a7
    j 2f
1:
    slli a7, a7, 4
    la t0, syscall_table
    add t0, t0, a7
    ld t1, 0(t0) /* number of return values */
    ld t0, 8(t0) /* function pointer */
2:
    la ra, 1f
    slli t1, t1, 2
    add ra, ra, t1
    jr t0
    /* Zero unsaved registers to avoid leaking kernel information, except
     * registers used for return values.
     * We awkwardly "index" the actual jump target from the number of return
     * values from the syscall_table, so force a fixed instruction size. */
1:
    .option push
    .option norvc
    mv a0, zero
    mv a1, zero
    mv a2, zero
    mv a3, zero
    mv a4, zero
    mv a5, zero
    mv a6, zero
    mv a7, zero
    .option pop

    mv t0, tp

    ld ra, (THREAD_SYSCALL_RA)(t0)
    ld sp, (THREAD_SYSCALL_SP)(t0)
    ld gp, (THREAD_SYSCALL_GP)(t0)
    ld tp, (THREAD_SYSCALL_TP)(t0)

    ld t1, (THREAD_SYSCALL_PC)(t0)
    csrw sepc, t1

    /* Zero more unsaved registers clobbered by C ABI kernel calls. */
    mv t0, zero
    mv t1, zero
    mv t2, zero
    mv t3, zero
    mv t4, zero
    mv t5, zero
    mv t6, zero

    sret

    /* NB: the kernel_trap and user_trap should be put at a lower address
     *     relative to trap, for branch prediction reasons. */

    /* Fallback "slowpath" for user exceptions and IRQs. */
user_trap:
    /* Setup kernel stack. */
    mv sp, tp
    j generic_trap

    /* Kernel exceptions and IRQs. */
kernel_trap:
    /* First try to verify whether we got a kernel exception, such as a stack
     * overflow (relies on guard page), or something equally messy. */

    /* (Note: sp was saved earlier, got clobbered, and is now free.) */
    csrr sp, scause

    /* Is it an IRQ? */
    srli sp, sp, 63
    bnez sp, kernel_generic_trap

    /* Use a special stack in case it was a stack overflow.
     * Would  need to be per-CPU on SMP systems (or stop all CPUs before). */
    la sp, emergency_trap_stack_end

    /* It's an exception. We don't allow any exceptions in kernel mode, except
     * we may want to access user virtual memory, letting the MMU check the
     * access. This will result in page faults, which we want to handle
     * normally. In particular, we want to keep the thread stack, so we can
     * context switch. Since stack overflows will cause page faults too, we
     * need more dumb complexity to filter them. */

    /* So, get some more free registers. */
    add sp, sp, -16
    sd a0, (0)(sp)
    sd a1, (8)(sp)

    csrr a0, scause

    la a1, 13 /* load page fault */
    beq a0, a1, 2f

    la a1, 15 /* store page fault */
    beq a0, a1, 2f

1:
    ld a0, (0)(sp)
    ld a1, (8)(sp)
    j generic_trap

2:
    /* Check the fault address to distinguish between controlled accesses to
     * user virtual memory and kernel address page faults. Kernel addresses
     * are always in the "upper" half. */
    csrr a0, stval
    srli a0, a0, 63
    bnez a0, 1b

    /* If it's a user address, restore our registers and restore real stack. */
    ld a0, (0)(sp)
    ld a1, (8)(sp)
    j kernel_generic_trap

kernel_generic_trap:
    /* Restore the real kernel stack from earlier saved sp. */
    ld sp, (THREAD_SCRATCH_SP)(tp)
    j generic_trap

    /* Generic handler for user IRQs/exceptions and kernel IRQs.
     * This is in the same state as if a normal trap entry happened, except
     *  - tp is set to the kernel thread pointer
     *  - sp is set to the kernel stack
     *  - the old sp/tp values are stored in thread.scratch_*.
     */
generic_trap:
    addi sp, sp, -ASM_REGS_SIZE
    ALL_REGS_LS(sd, ASM_REGS_REGS, sp)

    /* Pointless, but reduces confusion. */
    sd zero, (ASM_REGS_REGS + 0 * 8)(sp) /* x0 (zero) */

    /* Store the earlier awkwardly saved values to the proper location. */
    ld a0, (THREAD_SCRATCH_SP)(tp)
    sd a0, (ASM_REGS_REGS +  2 * 8)(sp) /* x2 (sp) */
    ld a0, (THREAD_SCRATCH_TP)(tp)
    sd a0, (ASM_REGS_REGS +  4 * 8)(sp) /* x4 (tp) */

    csrr a0, sepc
    sd a0, (ASM_REGS_PC)(sp)
    csrr a0, sstatus
    sd a0, (ASM_REGS_STATUS)(sp)
    csrr a0, scause
    sd a0, (ASM_REGS_CAUSE)(sp)
    csrr a0, stval
    sd a0, (ASM_REGS_TVAL)(sp)
    csrr a0, sip
    sd a0, (ASM_REGS_IP)(sp)

    /* (Could be computed, but doing so in C seems less messy for now.) */
    ld gp, (THREAD_KERNEL_GP)(tp)

    mv a0, sp
    jal c_trap

    /* Return from the generic trap (i.e. c_trap returns). This is also used as
     * entrypoint when creating a new kernel thread. */
.globl trap_return
trap_return:
    ld a0, (ASM_REGS_PC)(sp)
    csrw sepc, a0
    ld a0, (ASM_REGS_STATUS)(sp)
    csrw sstatus, a0

    ALL_REGS_LS(ld, ASM_REGS_REGS, sp)

    ld tp, (ASM_REGS_REGS +  4 * 8)(sp) /* x4 (tp) */
    ld sp, (ASM_REGS_REGS +  2 * 8)(sp) /* x2 (sp) */

    sret

/* Load/Store operation for C ABI callee-saved registers. */
#define CALLEE_SAVED_LS(INS)    \
    INS s0,  (0  * 8)(sp);      \
    INS s1,  (1  * 8)(sp);      \
    INS s2,  (2  * 8)(sp);      \
    INS s3,  (3  * 8)(sp);      \
    INS s4,  (4  * 8)(sp);      \
    INS s5,  (5  * 8)(sp);      \
    INS s6,  (6  * 8)(sp);      \
    INS s7,  (7  * 8)(sp);      \
    INS s8,  (8  * 8)(sp);      \
    INS s9,  (9  * 8)(sp);      \
    INS s10, (10 * 8)(sp);      \
    INS s11, (11 * 8)(sp);

.globl memcpy_with_trap
memcpy_with_trap:
    /* (1 unused padding word for C ABI stack alignment.) */
    addi sp, sp, -14 * 8
    CALLEE_SAVED_LS(sd)
    sd ra, (12 * 8)(sp)

    /* On exception, we jump to memcpy_with_trap_restore_pc, and sp is set to
     * the value stored here. */
    sd sp, (0)(a0)

    mv a0, a1
    mv a1, a2
    mv a2, a3
    call memcpy

    /* (On success we don't need to restore s0-s11; the C ABI preserves them.) */
    ld ra, (12 * 8)(sp)
    addi sp, sp, 14 * 8
    li a0, 1
    ret

.globl memcpy_with_trap_restore_pc
memcpy_with_trap_restore_pc:
    CALLEE_SAVED_LS(ld)
    ld ra, (12 * 8)(sp)
    addi sp, sp, 14 * 8
    li a0, 0
    ret

.section ".bss..page_aligned", "w"
.balign PAGE_SIZE

emergency_trap_stack:
    .skip PAGE_SIZE
emergency_trap_stack_end:
