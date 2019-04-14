#include "handle.h"
#include "ipc.h"
#include "kernel.h"
#include "kmalloc.h"
#include "mmu.h"
#include "slob.h"
#include "thread.h"
#include "thread_internal.h"

struct slob ipc_listener_slob = SLOB_INITIALIZER(struct ipc_listener);

// Per CPU, or for full preemption would have to be dynamic.
static uint8_t ipc_buffer[4096];

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

static void close_handles(struct thread *t, kern_handle *handles,
                          size_t num_handles)
{
    for (size_t n = 0; n < num_handles; n++) {
        struct handle *h = handle_lookup(t, handles[n]);
        if (h) {
            handle_free(t, h);
        } else {
            // In theory, we could make the IPC transfer fully preemptible
            // and/or we could allow concurrency by adding SMP support. In that
            // case, it would be possible that a thread in the dst address space
            // guesses the kernel created handles and closes them, which is
            // rude, but should not make the kernel crash. So we would just
            // tolerate that the handle was apparently closed.
            // But currently, this situation is impossible.
            panic("?\n");
        }
    }
}

// Perform a transfer, according to the ipc_info fields. Returns an error code
// on failure. Note that it is assumed that if this returns success, the entire
// transfer succeeds (if not, you'd have to add additional code to undo changes
// like newly mapped handles).
// src is the current thread and address space at function entry and exit.
static int ipc_transfer(struct thread *dst, struct thread *src)
{
    assert(dst->ipc_info);
    assert(src->ipc_info);

    struct kern_ipc_args *d_args = &dst->ipc_info->args_copy;
    struct kern_ipc_args *s_args = &src->ipc_info->args_copy;
    // Write d_args back only if any receive fields are non-0.
    // Note that due to the API, this can be set to true only if dst actually
    // provides an args pointer.
    bool d_args_dirty = false;

    // Dynamic allocation for transferred handles (in target address space).
    kern_handle *handles = NULL;

    // Registers.
    for (size_t n = 0; n < KERN_IPC_REG_ARGS; n++)
        dst->ipc_info->payload[n] = src->ipc_info->payload[n];

    if (s_args->send_size) {
        if (s_args->send_size > d_args->recv_size_max)
            return -1; // sender error: receiver's buffer too small

        // Incrementally copy parts of the send string by copying it to a temp
        // buffer, switching address space, and then copying & switching back.
        // This very much sucks because copying twice and switching all the time
        // could half the performance, or worse.
        // For small send sizes, it'd be reasonable to copy everything to a temp
        // buffer before switching, and then copying it to the target after the
        // regular address space switch. But even this complicated the code,
        // because the regular address space switch is combined with the thread
        // switch, which is all over the place. I could just be put into the
        // receiving code, but that needs careful consideration of the desired
        // error semantics.
        // You could use that this kernel maps all physical memory into the
        // kernel address space. You could lookup the user target addresses (by
        // walking the page tables or VM structures, invoking fault handlers if
        // pages are not mapped, and then copying to the mirror page in the
        // kernel address space), but this is too complex for now.
        size_t pos = 0;
        while (pos < s_args->send_size) {
            size_t copy = MIN(sizeof(ipc_buffer), s_args->send_size - pos);

            if (!copy_from_user(ipc_buffer, (uintptr_t)s_args->send + pos, copy))
                return -1; // sender error: sender buffer fault
            mmu_switch_to(dst->mmu);
            bool r =
                copy_to_user((uintptr_t)d_args->recv + pos, ipc_buffer, copy);
            mmu_switch_to(src->mmu);
            if (!r)
                return -1; // sender (?) error: receiver buffer fault
            pos += copy;
        }

        d_args->recv_size = s_args->send_size;
        d_args_dirty = true;
    }

    if (s_args->send_num_handles) {
        if (s_args->send_num_handles >= (size_t)-1 / sizeof(kern_handle))
            return -1; // sender error: too many handles
        if (s_args->send_num_handles > d_args->recv_num_handles_max)
            return -1; // sender error: receiver's buffer too small
        handles = mallocz(s_args->send_num_handles * sizeof(kern_handle));
        if (!handles)
            return -1; // sender error: OOM

        if (!copy_from_user(handles, (uintptr_t)s_args->send_handles,
                            sizeof(kern_handle) * s_args->send_num_handles))
        {
            free(handles);
            return -1; // sender error: sender fault
        }

        // Duplicate handles into target address space.
        for (size_t n = 0; n < s_args->send_num_handles; n++) {
            struct handle *h = handle_lookup(src, handles[n]);
            bool err = false;
            if (h) {
                struct handle *new = handle_alloc(dst);
                if (handle_vtable[h->type]->ref(new, h)) {
                    handles[n] = handle_get_id(dst, new);
                } else {
                    handle_free(dst, new);
                    err = true;
                }
            } else {
                err = !!handles[n]; // duplicating the 0 handle is allowed
            }
            if (err) {
                // Rollback all handles created so far.
                close_handles(dst, handles, n);
                return -1; // sender error: handle could not be duplicated
                           // (invalid handle, unduplicatable handle, OOM)
            }
        }

        d_args->recv_num_handles = s_args->send_num_handles;
        d_args_dirty = true;
    }

    if (d_args_dirty) {
        // Same problem as with buffer-copying above: unacceptable, but for
        // now working temporary switch to access target address space.
        mmu_switch_to(dst->mmu);
        bool r = copy_to_user(dst->ipc_info->args, d_args, sizeof(*d_args));
        if (r && d_args->recv_num_handles) {
            r = copy_to_user((uintptr_t)d_args->recv_handles, handles,
                             sizeof(kern_handle) * d_args->recv_num_handles);
        }
        mmu_switch_to(src->mmu);
        if (!r) {
            // Before returning with an error, roll back transferred handles.
            close_handles(dst, handles, d_args->recv_num_handles);
            free(handles);
            return -1; // sender (?) error: receiver args fault
        }
        free(handles);
    }

    return 0;
}

void ipc_entry(kern_handle send, kern_handle recv)
{
retry: ;
    struct thread *t = thread_current();
    struct ipc_info *ipc_info = t->ipc_info;
    assert(ipc_info);
    // Target thread (if any). Note that we try to workaround the "scheduler",
    // which in theory reduces IPC overhead. So the code in this function needs
    // to care about switching to it if non-NULL.
    struct thread *tt = NULL;

    ipc_info->ret_code = 0;
    ipc_info->ret_handle = 0;
    ipc_info->ret_userdata = 0;

    printf("IPC send=%ld recv=%ld\n", send, recv);

    if (ipc_info->args) {
        if (!copy_from_user(&ipc_info->args_copy, ipc_info->args,
            sizeof(struct kern_ipc_args)))
        {
            ipc_info->ret_code = -1; // page fault
            return;
        }
    } else {
        ipc_info->args_copy = (struct kern_ipc_args){0};
    }

    if (send != KERN_HANDLE_INVALID) {
        struct handle *h = handle_lookup(t, send);
        bool is_send = false;
        uintptr_t reply_ud = 0;
        if (h && h->type == HANDLE_TYPE_IPC_TARGET) {
            is_send = true;
            reply_ud = h->u.ipc_target.user_data;
            struct ipc_listener *l = h->u.ipc_target.listener;
            if (!l->listeners) {
                t->ipc_list = l->waiters;
                l->waiters = t;
                thread_set_state(t, THREAD_STATE_WAIT_IPC_SEND);
                thread_reschedule();
                goto retry; // port may have been closed etc.
            }
            tt = l->listeners;
            if (!tt->ipc_free_handle) {
                struct handle *rh = handle_alloc(tt);
                if (!rh) {
                    ipc_info->ret_code = -1; // OOM
                    return;
                }
                tt->ipc_free_handle = handle_get_id(tt, rh);
                // Handle allocation may have invalidated h.
                h = handle_lookup(t, send);
            }
            // Unlink the listener to reserve it.
            assert(tt->state == THREAD_STATE_WAIT_IPC);
            l->listeners = tt->ipc_list;
        } else if (h && h->type == HANDLE_TYPE_IPC_REPLY) {
            tt = h->u.ipc_reply.caller;
            // Now that we know it'll work, unlink. On transfer error, we
            // generally propagate the error to the waiter, i.e. always remove
            // the reply handle.
            h->type = HANDLE_TYPE_RESERVED;
            if (t->ipc_free_handle) {
                struct handle *h2 = handle_lookup(t, t->ipc_free_handle);
                assert(h2);
                assert(h2->type == HANDLE_TYPE_RESERVED);
                handle_free(t, h2);
            }
            t->ipc_free_handle = send;
            if (!tt) {
                ipc_info->ret_code = -1; // dead reply port
                return;
            }
            assert(tt->state == THREAD_STATE_WAIT_IPC);
        } else {
            ipc_info->ret_code = -1; // invalid send handle
            return;
        }
        assert(tt);
        assert(tt->state == THREAD_STATE_WAIT_IPC);
        assert(tt->ipc_info);

        int r = ipc_transfer(tt, t);
        if (r < 0) {
            // Transfer error.
        }

        // TODO: if this fails, we must re-enqueue the listener. For replies,
        //       have to decide what should happen: caller has to retry, or
        //       error is propagated to reply-awaiter.
        //       Currently, transfers can't fail.

        tt->ipc_info->ret_code = 1;
        tt->ipc_info->ret_handle = 0;
        tt->ipc_info->ret_userdata = reply_ud;

        if (is_send) {
            // Allocate reply port.
            struct handle *rh =
                handle_lookup_type(tt, tt->ipc_free_handle, HANDLE_TYPE_RESERVED);
            assert(rh); // must have been reserved
            rh->type = HANDLE_TYPE_IPC_REPLY;
            tt->ipc_info->ret_handle = tt->ipc_free_handle;
            tt->ipc_free_handle = 0;
            if (recv == send) {
                // Combined send/wait (call).
                rh->u.ipc_reply.caller = t;
                thread_set_state(tt, THREAD_STATE_FINE);
                thread_set_state(t, THREAD_STATE_WAIT_IPC);
                // May not return (fast path).
                thread_switch_to(tt);
                return;
            } else {
                // Discard reply. (Unclear whether we should allow this.)
                rh->u.ipc_reply.caller = NULL;
            }
        }
    }

    if (recv != KERN_HANDLE_INVALID) {
        struct handle *h =
            handle_lookup_type(t, recv, HANDLE_TYPE_IPC_LISTENER);
        if (!h) {
            ipc_info->ret_code = -1; // invalid receive handle
            goto exit_wakeup;
        }
        struct ipc_listener *l = h->u.ipc_listener.listener;
        t->ipc_list = l->listeners;
        l->listeners = t;
        // If there were waiters, pick one and wake it up to start a transfer.
        if (l->waiters) {
            struct thread *wake = l->waiters;
            assert(wake->state == THREAD_STATE_WAIT_IPC_SEND);
            l->waiters = wake->ipc_list;
            // TODO: what if the thread fails sending an IPC? then something
            //       must wakeup the next waiter (messy); or we could wake up
            //       all
            //       => yep, error handler in the sender needs to ensure this
            thread_set_state(wake, THREAD_STATE_RUNNABLE);
        }
        thread_set_state(t, THREAD_STATE_WAIT_IPC);
        if (tt) {
            // Donate timeslice and switch directly.
            thread_set_state(tt, THREAD_STATE_FINE);
            // May not return (fast path).
            thread_switch_to(tt);
        } else {
            // May not return (fast path).
            thread_reschedule();
        }
        return;
    }

exit_wakeup:
    if (tt) {
        // Wakeup thread, donate timeslice.
        thread_set_state(tt, THREAD_STATE_FINE);
        thread_set_state(t, THREAD_STATE_RUNNABLE);
        thread_switch_to(tt);
    }
}
