#pragma once

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

// Slow path storage for IPC payload.
struct ipc_info {
    size_t payload[7]; // a0-a6
};
