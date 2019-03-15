#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kernel/api.h>

// Manages a list of virtual memory mappings in a user address space.
struct vm_aspace;

// Reference to a VM object. Userspace can have handles to these object, and
// mmap them into address spaces.
struct vm_object_ref;

struct vm_aspace *vm_aspace_create(void);
void vm_aspace_free(struct vm_aspace *as);

struct mmu;
struct mmu *vm_aspace_get_mmu(struct vm_aspace *as);

// For free use by struct thread. This is only part of struct vm_aspace for
// static memory allocation purposes, and is not accessed by the vm code.
struct vm_aspace_owners {
    struct thread *head, *tail;
};
struct vm_aspace_owners *vm_aspace_get_owners(struct vm_aspace *as);

// Mirrors classic mmap(). obj remains owned by the caller only.
//  addr: userspace desired address, or -1 if any
//  length: size of the mapping
//  flags: KERN_MAP_* flags
//  obj: source or NULL
//  offset: offset into obj
//  returns: userspace address, or (void *)err with err<0 on error
void *vm_mmap(struct vm_aspace *as, void *addr, size_t length, int flags,
              struct vm_object_ref *obj, uint64_t offset);

// Unmap the given range. Returns success. May fail if address range overflows,
// or if the call splits regions and not enough memory is available.
bool vm_munmap(struct vm_aspace *as, void *addr, size_t length);

// Tell vm_aspace that the given page aligned region is reserved, and that it
// should neither allow other mappings, nor change/access PTEs in it. This is
// for special kernel mappings.
// The kernel address space is already implicitly reserved.
// Returns success. Fails on OOM or if there are colliding existing mappings.
bool vm_reserve(struct vm_aspace *as, void *addr, size_t length);

// Copy all mappings with KERN_MAP_FORK_COPY to dst. Returns an error if dst
// already has at least one mapping.
bool vm_fork(struct vm_aspace *dst, struct vm_aspace *src);

enum {
    // Create by allocating a zero'd physical RAM page. If it already exists,
    // do nothing. This guarantees the page is resident (on success).
    VM_PAGE_CTRL_CREATE     = (1 << 0),
    // Remove access to the page from all vm_object_refs, except the master.
    // Fails if the page is not resident. Threads trying to access the page will
    // be trapped in the page fault handler and then wait until the page status
    // changes.
    // _CREATE and _LOCL_ actions can be combined.
    // TODO: define per-vm_object_ref permission flags so consumers cannot do it
    //       also let users which have this bit set access the memory despite
    //       the lock (would be one way to enable userspace read_page handling)
    VM_PAGE_CTRL_LOCK_FULL  = (1 << 1),
    // Same as VM_PAGE_CTRL_LOCK_FULL, but still allow read only access by other
    // vm_object_refs.
    VM_PAGE_CTRL_LOCK_RO    = (1 << 2),
    // Revert the previous lock operation. May unblock waiting threads trying to
    // access the page. Fails if the page is not resident.
    VM_PAGE_CTRL_UNLOCK     = (1 << 3),
    // Destroy a physical RAM page. Threads trying to access this page will
    // invoke vm_object_ops.read_page.
    // _DESTROY without _UNLOCK will implicitly unlock it.
    VM_PAGE_CTRL_DESTROY    = (1 << 4),
    // TODO: a concept to access PTE dirty and access bits?
};

// Manipulate a specific page.
//  offset: page-aligned byte offset
//  flags: VM_PAGE_CTRL_* flags
//  returns: success on >=0, error on <0
int vm_objref_page_ctrl(struct vm_object_ref *ref, uint64_t offset, int flags);

// Allocate (or retrieve if existing) a page at the given page-aligned offset.
// Return INVALID_PHY_ADDR on failure. On success, this is a writable page
// located in the object's RAM cache.
// Since there is no kernel concurrency, the address stays valid until you know
// when. This is a hack for bootstrap kernel VM interaction.
uint64_t vm_objref_page_create_phys(struct vm_object_ref *ref, uint64_t offset);

//TODO: operations for dropping permissions etc. (e.g. the idea is to have a
//      permission bit for calling privileged operations like
//      VM_PAGE_CTRL_LOCK_*, and drop it before returning it to a user)
//int vm_objref_ctrl(struct vm_object_ref *ref, int flags);

// Set the size of the underlying object. Prunes resident pages that go outside
// of the size, except possibly in certain COW'ed refs. If the ref has an offset
// set, the size is still set as observed in the root ref.
// TODO: define per-ref permission bits for changing this
void vm_objref_set_size(struct vm_object_ref *ref, uint64_t size);

struct vm_object_ops {
    // Called when a page needs to be read. Typically this happens when a thread
    // wants to read a non-resident page and gets trapped in the page fault
    // handler. The callee can use vm_objref_page_ctrl() to create a locked
    // page, fill it (while other users are waiting), and unlock it.
    // When this returns, the caller rechecks the state of the page. If the
    // page is locked, the thread adds itself to a per-vm_object wait list and
    // goes to sleep. Once the page is added (i.e. VM_PAGE_CTRL_CREATE followed
    // by VM_PAGE_CTRL_UNLOCK), waiting threads are woken up. Woken up threads
    // check whether the page is present.
    // Returns 0 on success, <0 on error.
    int (*read_page)(void *ud, uint64_t offset);
    // Called when the last reference to it is destroyed.
    // TODO: how is this supposed to work if the implementer may have to create
    //       a reference to maintain the object?
    void (*free)(void *ud);
};

// Create anonymous memory. This memory is sparse, and its virtual size can
// exceed system memory. The size is rounded up if not page aligned.
struct vm_object_ref *vm_objref_create_anon(uint64_t size);

// Copy anonymous memory. Will fail for refs not originating from
// vm_objref_create_anon().
struct vm_object_ref *vm_objref_copy_anon(struct vm_object_ref *ref);

// Create an object that can be mapped and cached in memory. ud is passed as
// first parameter to all vm_object_ops callbacks.
// The caller is expected to keep the ref for internal uses (by ops), and create
// another ref with some dropped permissions for the user.
struct vm_object_ref *vm_objref_create(const struct vm_object_ops *ops, void *ud);

// Create a new reference. This copies current permissions and restrictions.
struct vm_object_ref *vm_objref_dup(struct vm_object_ref *ref);

// Relinquish ownership. Note that vm_object_ref is both a "logical" reference
// to underlying VM objects, and refcounted on its own. Accessing ref after this
// call is undefined, but misuse is not detectable.
void vm_objref_unref(struct vm_object_ref *ref);

// Returns whether we think the page fault was handled. If it returns false,
// invoke a crash handler. If it returns true, retry.
// access is exactly one of KERN_MAP_PERM_R/KERN_MAP_PERM_W/KERN_MAP_PERM_X.
bool vm_aspace_handle_page_fault(struct vm_aspace *as, void *addr, int access);

// Resolve an access to the given address and return the physical address (or
// INVALID_PHY_ADDR on failure). This is a hack for the kernel and just goes
// though the page fault code.
uint64_t vm_aspace_get_phys(struct vm_aspace *as, void *addr, int access);
