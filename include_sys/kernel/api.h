#pragma once

#include <stddef.h>
#include <stdint.h>

struct kern_thread_regs {
    // x0-x31 (x0 is ignored; included to avoid confusing register numbers)
    size_t regs[32];
    size_t pc;
};

struct kern_timespec {
    int64_t sec;
    uint32_t nsec;
};

// (Often used as magic value to refer to the calling thread.)
#define KERN_HANDLE_INVALID         0

#define KERN_IS_HANDLE_VALID(h) ((h) > KERN_HANDLE_INVALID)

// General syscall ABI:
//
//  - The C call ABI (RISC-V ELF psABI) is used as base.
//  - ecall is used for syscall entry
//  - Unlike the SBI and other kernels (such as Linux), this clobbers all
//    registers that are not explicitly callee-saved or immutable.
//    (Rationale: micro-optimizations for performance.)
//  - ra is changed from unsaved to callee-saved
//  - a0-a7 are used to pass arguments. a0 is used for the return value.
//  - t6 is used to pass the syscall number
//
// In addition, the IPC syscall uses a special ABI, that uses registers t0-t3
// for syscall arguments, and registers a0-a7 for IPC payload. t6 is always
// used for the syscall number, and controls which ABI is used.
//
// Summary:
//
// Preserved/immutable: zero, sp, gp, tp, s0-s11
// Syscall number (not preserved): t6
// Arguments (not preserved): a0-a7
// Other not preserved: ra, t0-t5

// Handles:
//
// Most user-accessible kernel objects are managed as handles. Whenever user-
// space performs an operation on a kernel object, the handle is passed to the
// syscall. Also, handles can be transferred via IPC to other processes.
//
// Since some syscall allow handles of any kind, all handles live in the same
// namespace. The namespace is per-process.
//
// Handles have the type int64_t. All valid handles have a value > 0 (1 is the
// first valid handle). KERN_INVALID_HANDLE has the value 0, though all other
// negative values are also invalid handles.
//
// Some syscalls accept KERN_INVALID_HANDLE if the handle is optional, or for
// special functions. For the sake of error checking, invalid handles other than
// KERN_INVALID_HANDLE will cause an error.


// IPC syscall. This can perform a send and a receive operation. The exact type
// of operation depends on the port handles passed in. It's also possible to
// only perform a send or receive, although these are generally not as useful.
// In most cases, a client-server communication model is required.
//
// If a target port is provided as send and receive handle, a "call" is
// performed, which sends an IPC to a target port, and waits for the reply. This
// is supported by a fast path, which continues execution directly in the
// kernel.
//
// Another idiom supported by a fast path is passing a reply port as send
// handle, and a listener port as receive handle. This puts the current thread
// on a listener list, and continues execution directly in the received-to
// thread.
//
// The send handle must always be a target port or a reply port. The receive
// handle must always be a target port or a listener port. If a target port is
// supplied as receive handle, it must also be supplied as send handle.
//
// Both send and receive parts can be blocking.
//
// The thread always gives up its current timeslice. If a send is performed, it
// is typically donated to the receiving thread.
//
// Design decisions:
//  - Like L4, send/receive are combined for efficiency and to avoid needing
//    multiple syscalls for a single RPC.
//  - IPC target ports are handles, which avoids having a global thread ID
//    address space and associated security and DoS problems; it's also more
//    convenient, because a handle can store userdata.
//  - Unlike L4, the blocking direction is always enforced by handles, which
//    probably simplifies things (doubt).
//  - "Migrating threads" were considered, but forced control flow is relatively
//    similar, without the weirdness that comes with it. (In the end, there
//    are only 2 differences: migrating threads have a "call stack", and
//    "activations" are essentially user threads without kernel threads.)
//  - Multiple client threads can make multiple requests through a single port,
//    that can be handled by multiple server threads. (Every requesting thread
//    gets blocked. It would be possible to make an orthogonal async-IPC
//    extension, that takes the slow path and prevents blocking.)
//    It's supposed to essentially allow server architectures that use thread
//    pools (multiple threads can communicate independently), as well as single
//    threaded servers (just create all target ports from a single listener
//    port).
//  - This requires dynamic allocation of reply ports. In particular, a server
//    can let a thread wait while servicing other threads.
//  - Some weirdness is due to trying to implement an asm-only fast path. This
//    is also why the ABI is modified: we can copy 7 user registers, and they
//    could be sourced directly from a C call without further copying.
//  - No timeouts, because this would require adding a waiting thread to a
//    timer queue even in the fast path case, which is "too slow". It's also
//    rarely needed. Instead, a way to interrupt a thread from another thread
//    shall be provided.
//  - There is no bulk copying mechanism and no scatter-gather copying (iovec).
//    I considered this useless, because the receive needs to provide an equally
//    large buffer for _every_ receiver, and then it needs to do something with
//    it (copy it somewhere else?). Especially if you assume write() syscalls
//    are implemented as IPC to a filesystem server, this idea becomes rather
//    questionable. Things to consider in the future:
//      - Add a page-aligned iovec that maps the associated pages as COW into
//        the target address space (as vm_mapping object).
//      - ...or do the same, but don't map the pages, but put the result into a
//        vm_object_ref handle.
//      - The above could also be done with non-aligned memory, in which case
//        the kernel would copy the data into newly allocated pages.
//      - ...or relax it further by COWing unaligned pages and "trusting" the
//        participants that the extra data visible due to it doesn't cause
//        security issues.
//      - Don't copy any pages at all, and instead make syscalls like write()
//        access a vm_object_ref memory object directly. The intention is to
//        emulate something similar to a monolithic kernel's page cache, and
//        hope that the FS doesn't need to immediately know that something was
//        written. Instead, the filesystem code gets active when data is flushed
//        back to disk.
//    The main goal is to provide efficient mechanisms to implement filesystems
//    outside of the kernel, in a somewhat POSIX-compatible way.
//  - Instead of the above, there's an option to copy a single string, which can
//    fit into a temporary kernel buffer. This is mostly so that we can do naive
//    implementations of read()/write() as IPC for now, and don't run out of
//    space for arguments for complicated RPCs in general.
//  - This includes a forced header, so that nobody tries to use it the "wrong"
//    way. Some L4 kernels put extra arguments in a "thread control block";
//    this is slightly more complex, but at least doesn't need extra cooperation
//    from the libc and kernel.
// TODO: this wall of text doesn't really belong here.
//
// This uses a different ABI from other syscalls. The reason for this is stub
// efficiency and freeing up registers for IPC transfer. The only common part is
// that the syscall number is passed in t6.
//
//  a0-a6: payload, i.e. user data transferred with IPC. All these registers are
//         always transferred, and the caller may need to clear unused registers
//         to avoid data leakage.
//
// Other registers:
//          <in>                            <out>
//  t0:     send port handle (or inv.)      new reply handle (or inv.)
//  t1:     receive port handle (or inv.)   port userdata (or 0)
//  t2:     send flags                      (clobbered)
//  t3:     receive flags                   updated receive flags
//  t4:     extra message data ptr.         (clobbered)
//  t5:     (clobbered)                     (clobbered)
//  t6:     KERN_FN_IPC                     0/1 on success, otherwise error code
//
// t6 is guaranteed to be 0 or 1 on success. Success is only wrt. the IPC
// operations. If a RPC call logically fails, it needs to do its own signaling
// within the payload. If a receive operation was performed, t6 is set to 1,
// if no receive operation was requested, it is set to 0.
//
// t0 must be either:
//  - a target port
//  - a reply port
//  - KERN_HANDLE_INVALID
// All other cases are errors.
//
// t1 must be either:
//  - a listener port
//  - a target port (the same value as t0)
//  - KERN_HANDLE_INVALID
// All other cases are errors.
//
// t2 and t3 are integers whose contents are reflected by struct kern_ipc_flags.
// Depending on these flags, t4 is a pointer that points to memory that is
// further involved with the IPC transfer (such as extra bytes to send/receive).
// This is called extra message data pointer/area, and its contents depends on
// the flags. It can be used for both sending and receiving (the syscall invoker
// decides what operations are possible).
//
// If t0 is a target port and t0==t1, a typical send-wait-reply operation is
// performed. As soon as a server thread waits on the connected listener handle,
// it is unblocked, receives the IPC payload, and a temporary reply port handle
// is created. The server thread can at a later point send a reply by passing
// the reply port handle as send handle.
// If t1 has other (valid) values, the reply port will be valid but "dangling",
// and behave as if the client thread died.
//
// If t0 is valid, the kernel reads extra IPC send arguments from t1. If t1 is
// valid, the kernel writes extra IPC receive arguments to t1.
//
// If success is returned, t0, t1, and t3 are always set. If t1 was a listener
// port, t0 is set a reply handle, and t1 is set to the userdata that was set on
// the target port that was used to send the IPC. The userdata is the only way
// to identify the sender. If t2 was something else, t0 is set to
// KERN_HANDLE_INVALID, and t1 to 0.
// If a receive operation was performed, t3 contains updated receive flags,
// which reflect how much was actually received, and also if something could
// not be received.
//
// If both t0 and t2 are set to KERN_HANDLE_INVALID, the syscall does nothing
// and returns with t6=0.
//
// Reply port handles cannot be duplicated. Closing a reply port handle makes
// the client IPC syscall return with an error.
#define KERN_FN_IPC                     0

// Arguments for extended IPC. This reflects the contents of the IPC flags
// registers. (All 0 is equivalent to no extra actions performed.)
struct kern_ipc_flags {
    // Number of register-sized words in the extra message data. This extends the
    // number of bytes that can be transferred per IPC to slightly above 64KB.
    // If the IPC transfers a non-aligned number of bytes, it needs to pad the
    // buffer to the next word boundary, and store the number of logical bytes
    // to transfer in the message itself.
    // For sending: this contains the exact amount of extra units that should be
    // read by the kernel and transferred to the receiver. If the receiver's
    // buffer is smaller, the transfer is cut short, but succeeds, and the
    // receiver is signaled by setting a flag.
    // For receiving: maximum amount of extra units the kernel should copy from
    // a sender. On syscall return, the field is set to the number of copied
    // units. If the sender's count was higher, KERN_FLAG_IPC_MSG_OVERFLOW is
    // set in the flags field.
    // The kernel may abort an IPC operation in the middle, and thus overwrite
    // some of the msg target buffer even on failure and without indication that
    // this happened.
    uint8_t msg_count;

    // Number of register-sized words that follow the message data within the
    // extra message data area. The IPC transfer can copy the handles into the
    // receiver's address space as if KERN_FN_COPY_HANDLE were called for them.
    // The receiver's handle values will change. Only up to 255 handles can be
    // transferred.
    // Invalid handles are not allowed and cause an error, except the special
    // value KERN_HANDLE_INVALID is allowed and copied as-is.
    // Otherwise, sending and receiving works like with msg_count. Overflows
    // are flagged with KERN_FLAG_IPC_H_OVERFLOW instead. Overflowing handles
    // are not added to the receiver's handle table.
    // For receiving: note that the first returned handle is written after the
    // last returned msg word, i.e. the start of the handles depends on the
    // number of words returned by the IPC.
    // Concurrency considerations: if the kernel allows other threads to run
    // during the copy (preemptive kernel and/or SMP), userspace may observe
    // handles coming into existence, or getting deleted again on failure. If,
    // in this case, another thread destroy a kernel-created handle, and another
    // handle is allocated in its place, and the IPC operations fails due to
    // another reason later, the kernel will delete this handle anyway while
    // attempting to roll back the IPC operation.
    uint8_t handle_count;

    // KERN_FLAG_IPC_* bits. This should be set to 0 by the user.
    uint8_t flags;

    // Padding to register size. Set to 0; future extensions may add new fields.
    uint8_t pad0[sizeof(size_t) - 3];
} __attribute__((aligned(sizeof(size_t))));

// Overflow flags; these are set in kern_ipc_flags.flags if an IPC receive
// operation successfully returns, but some sender-provided data could not be
// copied due to the receiver not providing enough space.
#define KERN_FLAG_IPC_MSG_OVERFLOW  (1 << 0)
#define KERN_FLAG_IPC_H_OVERFLOW    (1 << 1)

// Create a new listener port for IPC. The resulting handle can be passed as
// IPC receive handle, or to create new target ports with
// KERN_FN_IPC_CREATE_TARGET.
// Note: listener port handles cannot be duplicated.
//  returns: listener port handle, or error code on resource exhaustion
#define KERN_FN_IPC_LISTENER_CREATE 1

// Create a new target port for IPC. The resulting handle can be passed as
// IPC send handle. While only the server has the listener handle, the target
// handle is intended to be passed to client processes.
// Only IPC calls with the provided listener port as receive handle can receive
// IPCs send through the target port.
// Every target port can have its own attached userdata. This is an arbitrary
// register-sized value, that is not interpreted by the kernel, and which is
// returned on a IPC receive operations on the listener handle.
//  a0: listener port handle
//  a1: userdata
//  returns: target port handle, or error code on resource exhaustion
#define KERN_FN_IPC_TARGET_CREATE   2

// a0: handle
// returns: error code; can fail only on invalid handles
#define KERN_FN_CLOSE               3

// a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
// a1: if 1, ignore a0 and create a new address space
//     (rationale: processes maybe won't know their own thread handle? this
//      won't really work, so it'll be changed again)
// returns: thread handle, or error code on resource exhaustion
#define KERN_FN_THREAD_CREATE       4

// Parameters:
//  a0: thread handle
//  a1: pointer to sys_thread_regs
//  returns: error code
#define KERN_FN_THREAD_SET_CONTEXT  5

// Parameters:
//  a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
//  a1: addr, or -1
//      Providing -1 will make the kernel select an arbitrary address (where
//      it doesn't conflict with other current mappings). Otherwise, the
//      behavior is with UNIX MAP_FIXED. The value must be page aligned.
//  a2: length
//      Size of the mapping. Must be page aligned.
//  a3: flags (KERN_MAP_*)
//  a4: handle to object, or -1
//      -1 behaves as with UNIX MAP_ANONYMOUS.
//  a5: offset
//      Offset into the mapped object. Must be page aligned. Must be 0 for
//      anonymous mappings.
//  returns: pointer, invalid pointer on error (see KERN_MMAP_FAILED())
#define KERN_FN_MMAP                6

// Access permission bits. If a given combination cannot be provided by the
// hardware, effective permissions may be increased.
#define KERN_MAP_PERM_R             (1 << 0)
#define KERN_MAP_PERM_W             (1 << 1)
#define KERN_MAP_PERM_X             (1 << 2)
// If addr is given, and if it collides with an existing mapping, overwrite it,
// instead of failing. Similar to Linux MAP_FIXED_NOREPLACE (inverted).
// Has no effect if addr==-1.
#define KERN_MAP_OVERWRITE          (1 << 3)
// Mark the mapping as COW. Successful writes to mapping will allocate private
// pages, instead of propagating changes to the mapped object. If the mapped
// object is changed by 3rd parties, the changes are visible only to pages for
// which no private pages were created.
// Note: for anonymous mappings, setting this flag will return an error.
// Similar to UNIX MAP_PRIVATE.
#define KERN_MAP_COW                (1 << 4)
// Create a COW mapping on fork() (i.e. whatever calls KERN_FN_COPY_ASPACE).
// There is a subtle difference for mappings backed by an object vs. anonymous
// memory: the latter are essentially duplicated, while the former still
// references the same underlying object, but with a duplicated internal handle.
// Mappings without any KERN_MAP_FORK_* flags are not present in the child.
#define KERN_MAP_FORK_COPY          (1 << 5)
// Share the mapping on fork().
#define KERN_MAP_FORK_SHARE         (1 << 6)

#define KERN_MMAP_FAILED(ui) ((intptr_t)(ui) < 0)

// Performs a COW copy of all address space mappings. Returns failure if target
// address space is not empty.
// Note that a2 is a helper for implementing fork(). Strictly speaking, the
// parameter is redundant to existing mechanism, and could be implemented
// entirely in userspace. It's slightly simpler in kernel space though (no need
// to write asm that references the syscall ABI).
// Parameters:
//  a0: source address space (KERN_HANDLE_INVALID: calling thread)
//  a1: target address space
//  a2: 0 or 1; if set to 1, then set a1 to a copy of the caller thread register
//      context; the target thread will pretend to return with 1 as error code
//  returns: error code (always 0 on success)
#define KERN_FN_COPY_ASPACE         7

// More or less emulates parts of the Linux futex syscall.
//  a0: op
//  a1: struct kern_timespec*
//  a2: uaddr
//  a3: val
//  returns:
//      for WAIT: 1 woken up; 0 timeout; else error code
//      for WAKE: >= 0 num woken up; else error code
#define KERN_FN_FUTEX               8

#define KERN_FUTEX_WAIT             1
#define KERN_FUTEX_WAKE             2

// Change mapping flags, in particular protection flags.
// Parameters;
//  a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
//  a1: addr
//  a2: size
//  a3: remove flags
//  a4: add flags
// Only a subset of flag can be changed. All of KERN_MAP_PERM_* can be changed.
#define KERN_FN_MPROTECT            9

// Discard the current thread's time slice.
#define KERN_FN_YIELD               10

// Access user per-thread state. This was only added to appease musl userland,
// which would require more intrusive changes to avoid it (or more Linux
// emulation in the kernel). Normally, userland should keep these things in its
// normal thread control block. TLS values are initialized to 0.
// Parameters:
//  a0: thread handle (KERN_HANDLE_INVALID: calling thread)
//  a1: operation (KERN_TLS_GET/SET)
//  a2: index (0..KERN_TLS_NUM-1).
//  a3: KERN_TLS_SET: new TLS value, KERN_TLS_GET: error value to return
//  returns: KERN_TLS_GET: TLS value or a3 on error; KERN_TLS_SET: error code
#define KERN_FN_TLS                 11

#define KERN_TLS_GET                0
#define KERN_TLS_SET                1

// Number of available register-sized TLS slots per thread.
#define KERN_TLS_NUM                2

// Undo KERN_FN_MMAP.
//  a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
//  a1: addr
//  a2: length
//  returns: error code
#define KERN_FN_MUNMAP              12

// Create a new instance of an existing handle. Depending on the type of the
// handle, this might be a transparent new reference to an object, or behave
// like a (partial) copy.
//  a0: thread handle for target address space (KERN_HANDLE_INVALID: calling thread)
//  a1: handle (from current address space)
//  returns: handle, or error code
#define KERN_FN_COPY_HANDLE         13

// Create a memory object.
#define KERN_FN_MEMOBJ_CREATE       14

// Return time configuration and current monotonic time (CLOCK_MONOTONIC).
// Note: obviously, it would be better to enable userspace to compute this
// on its own (getting frequency/base from kernel at start + using rdtime),
// and obviously returning it via a pointer (instead of registers) is
// inefficient, but for now this means less mess.
// Parameters:
//  a0: struct kern_timespec *
//  returns: error code; can fail only on invalid arg. pointer
#define KERN_FN_GET_TIME            15

#define KERN_FN_DEBUG_WRITE_CHAR    16
#define KERN_FN_DEBUG_STOP          17
