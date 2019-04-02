#include "handle.h"
#include "ipc.h"
#include "kernel.h"
#include "slob.h"
#include "thread.h"
#include "thread_internal.h"

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
    if (l->listeners) {
        // TODO: wake up all waiting threads to wake up threads possibly waiting
        //       on this handle; alternatively find ID of the handle we just
        //       freed and wake up only threads using that handle
        assert(0); // unimplemented
    }
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
    if (l->waiters) {
        // TODO: unblock all waiters possibly waiting on this
        assert(0); // unimplemented
    }
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

void ipc_entry(kern_handle send, kern_handle recv, size_t send_flags)
{
    struct thread *t = thread_current();
    struct ipc_info *ipc = t->ipc_info;
    assert(ipc);

redo:

    printf("IPC send=%ld recv=%ld flags=%ld\n", send, recv, send_flags);

    if (send != KERN_HANDLE_INVALID) {
        struct handle *h = handle_lookup(t, send);
        struct thread *tt = NULL;
        uintptr_t reply_ud = 0;
        kern_handle reply_handle = 0;
        if (h && h->type == HANDLE_TYPE_IPC_TARGET) {
            struct ipc_listener *l = h->u.ipc_target.listener;
            if (!l->listeners) {
                t->ipc_list = l->waiters;
                l->waiters = t;
                thread_set_state(t, THREAD_STATE_WAIT_IPC_SEND);
                thread_reschedule();
                goto redo; // port may have been closed etc.
            }
            tt = l->listeners;
            struct handle *rh = handle_alloc(tt);
            if (!rh) {
                ipc->ret_code = -1; // OOM
                return;
            }
            reply_handle = handle_get_id(t, rh);
            rh->type = HANDLE_TYPE_IPC_REPLY;
            rh->u.ipc_reply.caller = t;
            reply_ud = h->u.ipc_target.user_data;
            // Now that we know it'll work, unlink.
            assert(tt->state == THREAD_STATE_WAIT_IPC);
            l->listeners = tt->ipc_list;
        } else if (h && h->type == HANDLE_TYPE_IPC_REPLY) {
            tt = h->u.ipc_reply.caller;
            if (!tt)
                panic("unimplemented: send to dead reply port\n");
            assert(tt->state == THREAD_STATE_WAIT_IPC);
            // Now that we know it'll work, unlink.
            h->u.ipc_reply.caller = NULL;
            handle_free(t, h);
        } else {
            ipc->ret_code = -1; // invalid send handle
            return;
        }
        assert(tt);
        assert(tt->ipc_info);
        // "Transfer"
        // TODO: if this fails, we must re-enqueue the listener. For replies,
        //       have to decide what should happen: caller has to retry, or
        //       error is propagated to reply-awaiter.
        //       Current, transfer can't fail.
        if (send_flags)
            panic("unimplemented: non-register transfers\n");
        for (size_t n = 0; n < 8; n++)
            tt->ipc_info->payload[n] = t->ipc_info->payload[n];
        tt->ipc_info->ret_code = 1;
        tt->ipc_info->ret_handle = reply_handle;
        tt->ipc_info->ret_userdata = reply_ud;
        thread_set_state(tt, THREAD_STATE_RUNNABLE);
        if (reply_handle) {
            // In theory, allows discarding the reply.
            if (recv != send)
                panic("unimplemented: send to target not waiting for reply\n");
            // Wait for reply.
            thread_set_state(t, THREAD_STATE_WAIT_IPC);
            thread_reschedule();
            return;
        }
    }

    if (recv != KERN_HANDLE_INVALID) {
        struct handle *h = handle_lookup_type(t, recv,
                                              HANDLE_TYPE_IPC_LISTENER);
        if (!h) {
            ipc->ret_code = -1; // invalid receive handle
            return;
        }
        struct ipc_listener *l = h->u.ipc_listener.listener;
        t->ipc_list = l->listeners;
        l->listeners = t;
        if (l->waiters) {
            struct thread *wake = l->waiters;
            assert(wake->state == THREAD_STATE_WAIT_IPC_SEND);
            l->waiters = wake->ipc_list;
            // TODO: what if the thread fails sending an IPC? then something
            //       must wakeup the next waiter (messy); or we could wake up
            //       all
            thread_set_state(wake, THREAD_STATE_RUNNABLE);
        }
        thread_set_state(t, THREAD_STATE_WAIT_IPC);
        // May not return; if it does, it will have updated ipc_info.
        thread_reschedule();
    }
}
