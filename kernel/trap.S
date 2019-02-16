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
#define THREAD_KERNEL_SP    (8 * 8)
#define THREAD_KERNEL_PC    (9 * 8)

.section ".rodata", "a"

syscall_vec:
    .dword syscall_get_timer_freq
    .dword syscall_debug_write_char
    .dword syscall_debug_stop
syscall_vec_end:
    /* This dumb POS of an assembler apparently requires this redundant .set */
    .set syscall_vec_size, syscall_vec_end - syscall_vec
    /* But it wasn't enough of a fucking POS yet: this is the opposite, and
     * doesn't work with .set, only directly at the place of use. */
#define syscall_vec_num (syscall_vec_size / 8)

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
    li t0, syscall_vec_num
    bltu a7, t0, 1f
    la t0, syscall_unavailable
    j 2f
1:
    slli a7, a7, 3
    la t0, syscall_vec
    add t0, t0, a7
    ld t0, 0(t0)
2:
    la ra, 1f
    jr t0
1:
    mv t0, tp

    ld ra, (THREAD_SYSCALL_RA)(t0)
    ld sp, (THREAD_SYSCALL_SP)(t0)
    ld gp, (THREAD_SYSCALL_GP)(t0)
    ld tp, (THREAD_SYSCALL_TP)(t0)

    ld t1, (THREAD_SYSCALL_PC)(t0)
    csrw sepc, t1

    /* Zero unsaved registers to avoid leaking kernel information.
     * Uh, maybe just saving and restoring them would be cheaper in total? */
    mv t0, zero
    mv t1, zero
    mv t2, zero
    mv t3, zero
    mv t4, zero
    mv t5, zero
    mv t6, zero
    mv a1, zero
    mv a2, zero
    mv a3, zero
    mv a4, zero
    mv a5, zero
    mv a6, zero
    mv a7, zero

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

    /* It's an exception. We don't allow any exceptions in kernel mode. (Even
     * if we do later to access user virtual memory, we'd handle it here, in a
     * special, isolated way.) */

    /* Use a special stack in case it was a stack overflow.
     * Would  need to be per-CPU on SMP systems (or stop all CPUs before). */
    la sp, emergency_trap_stack_end

    j generic_trap

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

#if 0

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

.globl thread_switch_to_lowlevel
thread_switch_to_lowlevel:
    /* Special case for switching to initial thread, where don't store the
     * current "thread"'s state anywhere. */
    beqz tp, 1f
    /* Save state specific to this function. */
    addi sp, sp, 13 * 8
    CALLEE_SAVED_LS(sd)
    sd ra, (12 * 8)(sp)
    /* Save thread state. */
    sd sp, (THREAD_KERNEL_SP)(tp)
    la t0, 2f
    sd t0, (THREAD_KERNEL_PC)(tp)
1:
    /* Switch to the thread. */
    mv tp, a0
    ld sp, (THREAD_KERNEL_SP)(tp)
    ld t0, (THREAD_KERNEL_PC)(tp)
    jr t0
2:
    /* Normal target PC set by this function. The target PC is only rarely set
     * to anything else. */
    CALLEE_SAVED_LS(ld)
    ld ra, (12 * 8)(sp)
    addi sp, sp, -13 * 8
    ret
#endif

.balign 4096
.globl userspace_template
userspace_template:
    //ecall
    //wfi
    li a0, 'C'
    li a7, 1
    ecall
    j userspace_template
.balign 4096

.section ".bss..page_aligned", "w"
.align PAGE_SHIFT

emergency_trap_stack:
    .skip PAGE_SIZE
emergency_trap_stack_end: