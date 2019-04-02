#pragma once

#include <stddef.h>
#include <stdint.h>

#include "memory.h"

#include <kernel/api.h>

struct ipc_listener {
    // List of threads currently listening. These can receive IPC directly from
    // HANDLE_TYPE_IPC_TARGET ports.
    // Threads are always in THREAD_STATE_WAIT_IPC_LISTEN.
    // Singly linked list through thread.ipc_list.
    struct thread *listeners;
    // List of threads currently waiting. This is used if listeners is NULL, and
    // a thread sending IPC to HANDLE_TYPE_IPC_TARGET has to wait.
    // Threads are always in THREAD_STATE_WAIT_IPC_SEND.
    // Note that listeners and waiters can never be both set.
    // Singly linked list through thread.ipc_list.
    struct thread *waiters;
    // Number of HANDLE_TYPE_IPC_LISTENER handles to this. If this becomes 0,
    // the handle is dead, and trying to use a target port which still might
    // reference this returns an error.
    size_t refcount_listeners;
    // Number of HANDLE_TYPE_IPC_TARGET handles to this.
    size_t refcount_targets;
};

extern struct slob ipc_listener_slob;

// Used to communicate with syscall asm stub. This is specifically for syscall
// exit. Syscall entry uses fields in this struct when possible, but passes
// entry-only values as ipc_entry() extra arguments.
// Stack-aligned to make stack allocation in the asm easier.
struct ipc_info {
    // Receive buffer flags from userspace.
    size_t recv_flags;
    // Send/receive buffer pointer from userspace.
    uintptr_t data_ptr;
    // IPC operation return values (used for syscall exit).
    int ret_code;
    kern_handle ret_handle;
    uintptr_t ret_userdata;
    // Registers directly transferred.
    size_t payload[8];
}  __attribute__((aligned(STACK_ALIGNMENT)));

// Called by ASM on IPC (unless the ASM fast path is taken). thread->ipc_info is
// set to a stack allocated struct with some syscall parameters; the rest is
// passed as function argument. Must update thread->ipc_info before return; the
// caller returns the ipc_info contents via the syscall.
void ipc_entry(kern_handle send, kern_handle recv, size_t send_flags);
