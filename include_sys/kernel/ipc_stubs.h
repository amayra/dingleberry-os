#pragma once

/*
 * Helper inline functions to make IPC calls. This provides common variants,
 * with the intent that they are easier to use than the raw syscall.
 */

#include "stubs.h"

static inline void __copy_regs_in(struct kern_ipc_args *args, size_t *regs)
{
    memset(regs, 0, KERN_IPC_REG_ARGS_SIZE);
    if (args->send_size) {
        size_t copy = args->send_size;
        if (copy >= KERN_IPC_REG_ARGS_SIZE)
            copy = KERN_IPC_REG_ARGS_SIZE;
        memcpy(regs, args->send, copy);
        args->send = (char *)args->send + copy;
        args->send_size -= copy;
    }
}

static inline size_t __reserve_regs_out(struct kern_ipc_args *args)
{
    size_t r = args->recv_size_max;
    if (r) {
        if (r >= KERN_IPC_REG_ARGS_SIZE)
            r = KERN_IPC_REG_ARGS_SIZE;
        args->recv = (char *)args->recv + r;
        args->recv_size_max -= r;
    }
    return r;
}

// reserved = previous __reserve_regs_out return value.
// Returns total received bytes.
static size_t __copy_regs_out(struct kern_ipc_args *args, size_t *regs,
                            size_t reserved)
{
    if (reserved)
        memcpy((char *)args->recv - reserved, regs, reserved);
    return args->recv_size + reserved;
}

// "Slow" IPC stub variant for making a simple call to an IPC target. This uses
// the IPC transfer registers for the start of the message, and uses buffer
// transfer for the rest (or fills unused registers with 0).
// If the server reply is larger than the provided size, an error occurs.
// Further, this doesn't allow handle transfers.
// Returns number of bytes received on success, negative on error.
// Warning: this function specifically pretends the IPC transfers a byte string
// only, while it actually transfers registers too. Proper IPC stubs will put
// the first arguments into the register block, and this function tries to be
// compatible to this. So the first size_t*KERN_IPC_REG_ARGS bytes are
// transferred via registers. If recv_size is >= that size, the function will
// always return at least that size as transferred size, and if send_size is
// less than that size, the rest will be padded with 0.
static inline int kern_ipc_call(kern_handle port,
                                void *send_data, size_t send_size,
                                void *recv_data, size_t recv_size)

{
    struct kern_ipc_args args = {
        .send = send_data,
        .send_size = send_size,
        .recv = recv_data,
        .recv_size_max = recv_size,
    };
    size_t regs[KERN_IPC_REG_ARGS];
    __copy_regs_in(&args, regs);
    size_t resv = __reserve_regs_out(&args);
    int r = kern_ipc_full(port, port, &args, NULL, NULL, regs);
    if (r <= 0)
        return r < 0 ? r : -1; // (some generic error if there was no reply)
    return __copy_regs_out(&args, regs, resv);
}
