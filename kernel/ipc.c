#include "handle.h"

static bool ipc_listener_handle_ref(struct handle *new, struct handle *old)
{
    // - inc refcount_listeners
    return true;
}

static void ipc_listener_handle_unref(struct handle *h)
{
    // - dec refcount_listeners
    // - if refcount_listeners==0:
    //      - handle is "lost"
    //      - make all waiters return with an error
    //      - HANDLE_TYPE_IPC_TARGET will remain "invalidated" and return an
    //        error on use
    // - if refcount_listeners==refcount_targets==0:
    //      - ipc_listener totally unreferenced => free
    // - in all cases: wake up all current listeners and make them repeat the
    //   wait operation => make all threads that waited on the free'd handle
    //   return an error
}

static bool ipc_target_handle_ref(struct handle *new, struct handle *old)
{
    // - inc refcount_targets
    return true;
}

static void ipc_target_handle_unref(struct handle *h)
{
    // - dec refcount_targets
    // - see ipc_listener_handle_unref
    // - wake up all current listeners and make them repeat the wait operation
    //   => make all threads that waited on the free'd handle return an error
    // NB: it's ok not to interrupt threads which are waiting for a reply after
    //     having performed a send operation though this handle (interrupting
    //     them would require complicated bookkeeping)
}

static bool ipc_reply_handle_ref(struct handle *new, struct handle *old)
{
    // We don't support duplication of reply handles (would require complicated
    // tracking of all handles).
    return false;
}

static void ipc_target_handle_unref(struct handle *h)
{
    // - if ipc_reply.caller set:
    //      - unset caller
    //      - make caller return with an error
}

// HANDLE_TYPE_IPC_LISTENER
const struct handle_vtable handle_ipc_listener = {
    .name   = "ipc_listener",
    .ref    = ipc_listener_handle_ref,
    .unref  = ipc_listener_handle_unref,
};

// HANDLE_TYPE_IPC_TARGET
const struct handle_vtable handle_ipc_target = {
    .name   = "ipc_target",
    .ref    = ipc_target_handle_ref,
    .unref  = ipc_target_handle_unref,
};

// HANDLE_TYPE_IPC_REPLY
const struct handle_vtable handle_ipc_reply = {
    .name   = "ipc_reply",
    .ref    = ipc_reply_handle_ref,
    .unref  = ipc_reply_handle_unref,
};


/*
Thread destruction:
- THREAD_STATE_WAIT_IPC:
    - inspect thread.ipc_handle
        - HANDLE_TYPE_IPC_LISTENER:
            - read the ipc_listener, unlink
        - HANDLE_TYPE_IPC_REPLY:
            - invalidate reply handle (set .caller to NULL => valid, but stale
              reply handle)
- THREAD_STATE_WAIT_IPC_SEND:
    - who cares?
*/
