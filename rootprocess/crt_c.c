// (parts taken from musl)
#include <features.h>
#include "libc.h"

int main();
weak void _init();
weak void _fini();
_Noreturn int __libc_start_main(int (*)(), int, char **,
        void (*)(), void(*)(), void(*)());

#include <elf.h>
#include <stdint.h>

int64_t __self_handle;

// Uses argument registers as setup by the creator, in this case the kernel.
void crt_init(int64_t self_handle)
{
    __self_handle = self_handle;

    // Build Linux-compatible stack, as expected by musl.
    uintptr_t info[64];
    size_t idx = 0;

    // Arguments: argc times char*, followed by NULL.
    int argc = 0;
    info[argc++] = (uintptr_t)"rootprocess";
    idx += argc;
    info[idx++] = 0; // argv[argc]
    // Environment: char* entries in the format "name=value", followed by NULL.
    info[idx++] = (uintptr_t)"PATH=/bin";
    info[idx++] = 0;
    // AUX vector: pointer sized type/value pairs, followed by 0/0
    info[idx++] = AT_EXECFN;
    info[idx++] = (uintptr_t)"/rootprocess";
    info[idx++] = AT_PAGESZ;
    info[idx++] = 4096;
    info[idx++] = 0;
    info[idx++] = 0;

    __libc_start_main(main, argc, (char **)info /* UB but whatever */, _init, _fini, 0);
}
