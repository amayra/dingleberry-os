#include "handle.h"
#include "ipc.h"
#include "slob.h"

struct slob ipc_listener_slob = SLOB_INITIALIZER(struct ipc_listener);

static void check_free(struct ipc_listener *l)
{
    if (!l->refcount_listeners && !l->refcount_targets)
        slob_free(&ipc_listener_slob, l);
}

static bool ipc_listener_handle_ref(struct handle *new, struct handle *old)
{
    *new = *old;
    new->u.ipc_listener.listener->refcount_listeners += 1;
    return true;
}

static void ipc_listener_handle_unref(struct handle *h)
{
    struct ipc_listener *l = h->u.ipc_listener.listener;
    l->refcount_listeners -= 1;
    if (l->refcount_listeners == 0) {
        // TODO: wake up all waiters (l->waiters), make them return with an error
        if (l->waiters)
            assert(0); // unimplemented
    }
    // TODO: iterate over all threads in the current address space (?) to wake
    //       up threads possibly waiting on this handle
    // ...
    check_free(l);
}

// HANDLE_TYPE_IPC_LISTENER
const struct handle_vtable handle_ipc_listener = {
    .name   = "ipc_listener",
    .ref    = ipc_listener_handle_ref,
    .unref  = ipc_listener_handle_unref,
};

static bool ipc_target_handle_ref(struct handle *new, struct handle *old)
{
    *new = *old;
    struct ipc_listener *l = new->u.ipc_target.listener;
    l->refcount_targets += 1;
    return true;
}

static void ipc_target_handle_unref(struct handle *h)
{
    struct ipc_listener *l = h->u.ipc_target.listener;
    l->refcount_targets -= 1;
    check_free(l);
}

// HANDLE_TYPE_IPC_TARGET
const struct handle_vtable handle_ipc_target = {
    .name   = "ipc_target",
    .ref    = ipc_target_handle_ref,
    .unref  = ipc_target_handle_unref,
};

static bool ipc_reply_handle_ref(struct handle *new, struct handle *old)
{
    // We don't support duplication of reply handles (would require complicated
    // tracking of all handles).
    return false;
}

static void ipc_reply_handle_unref(struct handle *h)
{
    struct thread *caller = h->u.ipc_reply.caller;
    if (caller) {
        // TODO: make the thread return from its wait reply sleep with an error
        assert(0); // unimplemented
    }
}

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
