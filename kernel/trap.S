#include "memory.h"
#include "asm_offsets.h"

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

/* Load/Store operation for C ABI callee-saved registers. */
#define CALLEE_SAVED_LS(INS, BASE, BREG)\
    INS s0,  (BASE +  0 * 8)(BREG);     \
    INS s1,  (BASE +  1 * 8)(BREG);     \
    INS s2,  (BASE +  2 * 8)(BREG);     \
    INS s3,  (BASE +  3 * 8)(BREG);     \
    INS s4,  (BASE +  4 * 8)(BREG);     \
    INS s5,  (BASE +  5 * 8)(BREG);     \
    INS s6,  (BASE +  6 * 8)(BREG);     \
    INS s7,  (BASE +  7 * 8)(BREG);     \
    INS s8,  (BASE +  8 * 8)(BREG);     \
    INS s9,  (BASE +  9 * 8)(BREG);     \
    INS s10, (BASE + 10 * 8)(BREG);     \
    INS s11, (BASE + 11 * 8)(BREG);

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

    /* Check whether this is a syscall (scause == 8). If it's an exception or
     * IRQ, use the generic trap handler. Do this because we want to PREMATURELY
     * OPTIMIZE the syscall entry path. It would be simpler to always use the
     * full path.
     * Also assume scause == 8 happens only in user mode.
     */
    csrr sp, scause
    addi sp, sp, -8
    bnez sp, slow_trap

    /* Setup kernel stack. */
    mv sp, tp

    /* Save the normal syscall-saved registers. */
    sd gp, (THREAD_SYSCALL_GP)(tp)
    /* (sp/tp need to be awkwardly retrieved from above. Sure would be nice
     * to have 2 more sscratch regs, or different trap vectors, etc.) */
    ld ra, (THREAD_SCRATCH_SP)(tp)
    sd ra, (THREAD_SYSCALL_SP)(tp)
    ld ra, (THREAD_SCRATCH_TP)(tp)
    sd ra, (THREAD_SYSCALL_TP)(tp)

    CALLEE_SAVED_LS(sd, THREAD_SYSCALL_CS, tp)

    csrr ra, sstatus
    sd ra, (THREAD_SYSCALL_SSTATUS)(tp)

    csrr ra, sepc
    addi ra, ra, 4
    sd ra, (THREAD_SYSCALL_PC)(tp)

.option push
.option norelax
    lla gp, __global_pointer$
.option pop

    /* Syscall 0, IPC, is special: different ABI, asm fast path. */
    bnez a7, normal_syscall

    /* Check for special send flags. Currently, fast-path does register-only
     * transfer, so all fields must be 0. */
    bnez t3, ipc_slow_path

    /* Save source thread IPC receive parameters. If we don't take the fast
     * path, this is simply a dead store. */
    sd t3, (THREAD_IPC_RECEIVE_EXT_INF)(tp)
    sd t4, (THREAD_IPC_RECEIVE_EXT_PTR)(tp)

    /* Check t0 handle for type. */
    /* Check overflow and compute handle address. */
    srli s0, t0, MAX_HANDLES_LOG
    bnez s0, ipc_slow_path
    slli s0, t0, HANDLE_SIZE_LOG
    li s11, HANDLE_TABLE
    add s0, s0, s11
    /* Access handle (the handle table is sparse and can cause page faults). */
exc_ah_1_s:
    lbu s1, (HANDLE_TYPE)(s0)
exc_ah_1_e:
    /* Look what it is. */
    li s2, HANDLE_TYPE_IPC_TARGET
    beq s1, s2, ipc_send_wait
    li s2, HANDLE_TYPE_IPC_REPLY
    bne s1, s2, ipc_slow_path

ipc_reply_listen:
    /* s0: reply port handle struct
       s11: handle table */
    /* Check t1 handle for type. */
    srli s1, t1, MAX_HANDLES_LOG
    bnez s1, ipc_slow_path
    slli s1, t1, HANDLE_SIZE_LOG
    add s1, s1, s11
    /* Access handle. */
exc_ah_2_s:
    lbu s2, (HANDLE_TYPE)(s1)
exc_ah_2_e:
    /* Look what it is. */
    li s3, HANDLE_TYPE_IPC_LISTENER
    bne s2, s3, ipc_slow_path
    /* At this point, it really looks like a reply/listen call. */
    /* Load pointer to ipc_listener. */
    ld s6, (HANDLE_U_IPC_TARGET_LISTENER)(s1)
    /* Load ipc_listener.waiters; if it's not-NULL, use slow path. */
    ld s3, (IPC_LISTENER_WAITERS)(s6)
    bnez s3, ipc_slow_path
    /* Look for the reply-to thread; if it's dead, use slow path. */
    ld s3, (HANDLE_U_IPC_REPLY_CALLER)(s1)
    beqz s3, ipc_slow_path
    /* Now we know the IPC operation will succeed in all cases. */
    /* Free the reply handle. */
    sb zero, (HANDLE_TYPE)(s2) /* HANDLE_TYPE_INVALID */
    ld s4, (THREAD_IPC_FREE_REPLY_HANDLE)(tp)
    beqz s4, 1f
    /* Free it fully. */
    ld s4, (HANDLE_U_INVALID_NEXT)(s11) /* s11: HANDLE_TABLE */
    sd s4, (HANDLE_U_INVALID_NEXT)(s2)
    sd s2, (HANDLE_U_INVALID_NEXT)(s11)
    j 2f
1:
    /* Store it for the next receive operation. */
    sd s2, (THREAD_IPC_FREE_REPLY_HANDLE)(tp)
2:
    /* Put source thread into listener list. */
    ld s4, (IPC_LISTENER_LISTENERS)(s6)
    sd tp, (IPC_LISTENER_LISTENERS)(s6)
    sd s4, (THREAD_IPC_LIST)(tp)
    /* Change source thread state to waiting for IPC. */
    li s5, THREAD_STATE_WAIT_IPC_LISTEN
    sw s5, (THREAD_STATE)(tp)
    /* Change target thread state to running. */
    li s5, THREAD_STATE_FINE
    sw s5, (THREAD_STATE)(s3)
    /* Save context for sender thread. */
    la s5, ipc_receive_slowpath
    sd s5, (THREAD_KERNEL_PC)(tp)
    sd sp, (THREAD_KERNEL_SP)(tp)
    /* Since we use fast path, target pc is just discarded. The invariant for
     * the THREAD_STATE_WAIT_IPC_LISTEN state allows this. */
    ld sp, (THREAD_KERNEL_SP)(s3)
    /* Actual context switch. */
    mv tp, s3
    /* Fill receive registers. */
    mv t0, zero /* clobbered */
    mv t1, zero /* same */
    mv t3, zero /* receive flags all 0 due to fastpath */
    j ipc_receive_fastpath

ipc_send_wait:
    /* s0: target port handle struct
       s11: handle table */
    /* Check for proper blocking send/wait call. */
    bne t0, t1, ipc_slow_path
    /* At this point, it really looks like a send/wait call. */
    /* Load pointer to ipc_listener. */
    ld s1, (HANDLE_U_IPC_TARGET_LISTENER)(s0)
    /* Also the user_data, for later. */
    ld s6, (HANDLE_U_IPC_TARGET_USER_DATA)(s0)
    /* Load ipc_listener.listeners; if it's NULL, use slow path. */
    ld s3, (IPC_LISTENER_LISTENERS)(s1)
    beqz s3, ipc_slow_path
    /* "Allocate" reply handle held by listener thread. This also avoids having
     * to access the target thread handle table, which would have to happen
     * after address space switch, which would make handling allocation failure
     * slightly more messy. */
    ld s4, (THREAD_IPC_FREE_REPLY_HANDLE)(s3)
    beqz s4, ipc_slow_path
    /* Now we know the IPC operation will succeed in all cases. */
    /* We're going to use the reply handle. */
    sd zero, (THREAD_IPC_FREE_REPLY_HANDLE)(s3)
    /* Switch address space. */
    call ipc_switch_aspace
    /* Initialize reply handle. */
    li s5, HANDLE_TYPE_IPC_REPLY
    sb s5, (HANDLE_TYPE)(s4)
    sd tp, (HANDLE_U_IPC_REPLY_CALLER)(s4)
    /* Unlink target thread from ipc_listener */
    ld s5, (THREAD_IPC_LIST)(s3)
    sd s5, (IPC_LISTENER_LISTENERS)(s1)
    /* Change source thread state to waiting for reply. */
    li s5, THREAD_STATE_WAIT_IPC_REPLY
    sw s5, (THREAD_STATE)(tp)
    /* Change target thread state to running. */
    li s5, THREAD_STATE_FINE
    sw s5, (THREAD_STATE)(s3)
    /* Save context for sender thread. */
    la s5, ipc_receive_slowpath
    sd s5, (THREAD_KERNEL_PC)(tp)
    sd sp, (THREAD_KERNEL_SP)(tp)
    /* Since we use fast path, target pc is just discarded. The invariant for
     * the THREAD_STATE_WAIT_IPC_LISTEN state allows this. */
    ld sp, (THREAD_KERNEL_SP)(s3)
    /* Actual context switch. */
    mv tp, s3
    /* Fill receive registers. */
    mv t1, s6 /* user_data */
    mv t3, zero /* receive flags all 0 due to fastpath */
    /* Turn reply handle pointer to index handle. */
    sub s4, s4, s11
    srli t0, s4, HANDLE_SIZE_LOG
    j ipc_receive_fastpath

    /* Change address space from tp to the thread in s3. There are various
     * complications such as avoiding flushing TLBs when ASIDs are used, or
     * managing ASIDs in the first place.
     * This function cobbers at most s8-s10. */
ipc_switch_aspace:
    ld s4, (THREAD_MMU_SATP)(tp)
    ld s5, (THREAD_MMU_SATP)(s3)
    beq s4, s5, 1f
    /* But for now, always flush TLBs. */
    csrw satp, s5
    sfence.vma zero, zero
1:
    ret

    /* Call slow path C code for arbitrary IPC. */
ipc_slow_path:
    /*...*/
    call abort

    /* Context switch target if C code switches to a receiving thread. */
ipc_receive_slowpath:
    /* ... */
    call abort

    /* This basically just returns, similar to syscall return, but without
     *
     */
ipc_receive_fastpath:
    /* Prevent information leakage through unused registers.
     *  a0-a6: used to transfer user data
     *  a7: return status code
     *  t0, t1, t3: specific IPC return values
     *  ra: handled by return code */
    mv t2, zero
    mv t4, zero
    mv t5, zero
    mv t6, zero
    li a7, 1 /* success; IPC received */
    j return_to_user

normal_syscall:
    /* Dispatch the syscall. */
    li s0, SYSCALL_COUNT
    bltu a7, s0, 1f
    li s1, 1
    la s0, syscall_unavailable
    mv a0, a7
    j 2f
1:
    slli a7, a7, 3
    la s0, syscall_table
    add s0, s0, a7
    ld s0, 0(s0)
2:
    jalr s0

    /* Zero clobbered/unsaved registers to avoid leaking kernel information. */
    mv a1, zero
    mv a2, zero
    mv a3, zero
    mv a4, zero
    mv a5, zero
    mv a6, zero
    mv a7, zero
    mv t0, zero
    mv t1, zero
    mv t2, zero
    mv t3, zero
    mv t4, zero
    mv t5, zero
    mv t6, zero

return_to_user:
    ld ra, (THREAD_SYSCALL_SSTATUS)(tp)
    csrw sstatus, ra

    ld ra, (THREAD_SYSCALL_PC)(tp)
    csrw sepc, ra

    CALLEE_SAVED_LS(ld, THREAD_SYSCALL_CS, tp)

    ld sp, (THREAD_SYSCALL_SP)(tp)
    ld gp, (THREAD_SYSCALL_GP)(tp)
    ld tp, (THREAD_SYSCALL_TP)(tp)

    mv ra, zero

    sret

    /* NB: the slow_trap code should be put at a lower address
     *     relative to trap, for branch prediction reasons. */

    /* Fallback "slowpath" for user exceptions and IRQs. */
slow_trap:
    /* Entering from kernel mode? */
    csrr sp, sstatus
    andi sp, sp, (1 << 8) /* SPP */
    bnez sp, kernel_trap

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

.option push
.option norelax
    lla gp, __global_pointer$
.option pop

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

.globl thread_switch_asm
thread_switch_asm:
    /* (1 unused padding word for C ABI stack alignment.) */
    addi sp, sp, -14 * 8
    CALLEE_SAVED_LS(sd, 0, sp)
    sd ra, (12 * 8)(sp)
    sd sp, (THREAD_KERNEL_SP)(tp)
    la t0, 1f
    sd t0, (THREAD_KERNEL_PC)(tp)
    mv tp, a0
    ld sp, (THREAD_KERNEL_SP)(tp)
    ld a0, (THREAD_KERNEL_PC)(tp)
    csrw sscratch, tp
    /* Typically jumps to 1f, but not always. */
    jr a0
1:
    CALLEE_SAVED_LS(ld, 0, sp)
    ld ra, (12 * 8)(sp)
    addi sp, sp, 14 * 8
    ret

.globl run_with_trap_asm
run_with_trap_asm:
    /* (1 unused padding word for C ABI stack alignment.) */
    addi sp, sp, -14 * 8
    CALLEE_SAVED_LS(sd, 0, sp)
    sd ra, (12 * 8)(sp)

    /* On exception, we jump to TRAP_PC, and sp will be set to TRAP_SP. */
    sd sp, (THREAD_TRAP_SP)(tp)
    la t0, 1f
    sd t0, (THREAD_TRAP_PC)(tp)

    mv t0, a0
    mv a0, a1
    jalr t0

    /* (On success we don't need to restore s0-s11; the C ABI preserves them.) */
    li a0, 1
    j 2f
1:
    CALLEE_SAVED_LS(ld, 0, sp)
    li a0, 0
2:
    ld ra, (12 * 8)(sp)
    addi sp, sp, 14 * 8
    /* _Always_ reset the handler PC, so future faults don't use it. */
    sd zero, (THREAD_TRAP_PC)(tp)
    ret

.section ".bss..page_aligned", "w"
.balign PAGE_SIZE

emergency_trap_stack:
    .skip PAGE_SIZE
emergency_trap_stack_end:

.section .rodata

    /* This is a table with exception handlers. This follows this struct:
     *
     *  struct asm_exception_entry {
     *      void *code_start;
     *      void *code_end;
     *      void *code_target;
     *      size_t type;
     *  }
     *
     * The type field is a bitfield of ASM_EXCEPTION_TYPE_* values. When an
     * exception happens in [code_start, code_end), and there is a matching type
     * bit, the kernel will jump to code_target, and resume execution.
     *
     * Note that this works for ASM code only, since there is not stack rollback
     * or register restoring.
     */
#define EXCEPTION_ENTRY(s, e, h, t) \
    .dword (s), (e), (h), (t)
#define EXCEPTION_KLOAD(s, e, h) \
    EXCEPTION_ENTRY(s, e, h, ASM_EXCEPTION_TYPE_KERNEL_LOAD)
.balign 8
asm_exception_table:
    EXCEPTION_KLOAD(exc_ah_1_s, exc_ah_1_e, ipc_slow_path)
    EXCEPTION_KLOAD(exc_ah_2_s, exc_ah_2_e, ipc_slow_path)
    /* Termination. */
    EXCEPTION_ENTRY(0, 0, 0, 0)
