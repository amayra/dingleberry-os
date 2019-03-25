#include "handle.h"
#include "ipc.h"
#include "kernel.h"
#include "thread_internal.h"

#define STRINGIFY(x) #x

#define DEFINT_NAMED(name, i) \
    asm volatile("O><|" name "|%0" : : "i" (i));

#define DEFINT(name) \
    DEFINT_NAMED(# name, name)

#define OFFSET(type, field) \
    DEFINT_NAMED(STRINGIFY(type) "_" STRINGIFY(field), offsetof(type, field))

#define SIZE(type) \
    DEFINT_NAMED(STRINGIFY(type) "_size", sizeof(type))

void unused(void) {
    SIZE(struct asm_regs)

    OFFSET(struct asm_regs, regs)
    OFFSET(struct asm_regs, pc)
    OFFSET(struct asm_regs, status)
    OFFSET(struct asm_regs, cause)
    OFFSET(struct asm_regs, tval)
    OFFSET(struct asm_regs, ip)

    OFFSET(struct thread, scratch_sp)
    OFFSET(struct thread, scratch_tp)
    OFFSET(struct thread, kernel_sp)
    OFFSET(struct thread, kernel_pc)
    OFFSET(struct thread, syscall_sp)
    OFFSET(struct thread, syscall_gp)
    OFFSET(struct thread, syscall_tp)
    OFFSET(struct thread, syscall_pc)
    OFFSET(struct thread, syscall_sstatus)
    OFFSET(struct thread, syscall_cs)
    OFFSET(struct thread, trap_sp)
    OFFSET(struct thread, trap_pc)
    OFFSET(struct thread, ipc_handle)
    OFFSET(struct thread, ipc_receive_ext_inf)
    OFFSET(struct thread, ipc_receive_ext_ptr)
    OFFSET(struct thread, ipc_list)
    OFFSET(struct thread, ipc_free_reply_handle)
    OFFSET(struct thread, ipc_info)
    OFFSET(struct thread, mmu_satp)

    static_assert(sizeof(((struct thread){0}).state) == sizeof(int32_t), "");
    OFFSET(struct thread, state)
    DEFINT(THREAD_STATE_WAIT_IPC)
    DEFINT(THREAD_STATE_FINE)

    static_assert(HANDLE_TYPE_INVALID == 0, "");
    DEFINT(HANDLE_TYPE_IPC_TARGET)
    DEFINT(HANDLE_TYPE_IPC_REPLY)
    DEFINT(HANDLE_TYPE_IPC_LISTENER)
    DEFINT(HANDLE_TABLE)
    DEFINT(HANDLE_SIZE_LOG)
    DEFINT(MAX_HANDLES_LOG)

    OFFSET(struct handle, type)
    OFFSET(struct handle, u.ipc_target.listener)
    OFFSET(struct handle, u.ipc_target.user_data)
    OFFSET(struct handle, u.ipc_reply.caller)
    OFFSET(struct handle, u.ipc_listener.listener)
    OFFSET(struct handle, u.invalid.next)

    OFFSET(struct ipc_listener, listeners)
    OFFSET(struct ipc_listener, waiters)

    DEFINT(ASM_EXCEPTION_TYPE_KERNEL_LOAD)
    DEFINT(ASM_EXCEPTION_TYPE_USER_LOAD)
    DEFINT(ASM_EXCEPTION_TYPE_USER_STORE)

    DEFINT(SYSCALL_COUNT)
}
