#ifndef LIN_PRINTF_H_
#define LIN_PRINTF_H_

#include <stdarg.h>
#include <stddef.h>

// snprintf()-like function. Should be mostly C11 compliant, except:
//  - Does not support the following conversion specifiers: n
//  - No L length modifier (for long double)
//  - No l length modifier for the following conversion specifiers: c s
//    (for wchar_t and related, which is highly unportable anyway)
//  - No glibc extensions (e.g. %m)
//  - On some systems, <inttypes.h> format macros might break, if they use
//    unsupported extensions (consider systems where int64_t maps to no C
//    standard type, such as Microsoft Windows).
// The compiler's format checker won't warn against these.
//
// It supports the following extensions or guarantees:
//  - Locale independent (always uses "C" locale).
//  - Supports the conversion specifier 'b' for binary number output.
//  - str is _always_ 0-terminated (unless size==0).
//  - Length modifier for explicitly sized integer types:
//      I64u => uint64_t
//      I64d =>  int64_t
//      I32u => uint32_t
//      I32d =>  int32_t
//      I16u => uint16_t
//      I16d =>  int16_t
//      I8u  => uint8_t
//      I8d  =>  int8_t
//      Iu   => size_t
//      Id   => ptrdiff_t
//    (I32, I64 and I are compatible with Microsoft extensions)
//  - Limited support for %r. %r works like a recursive, inline vsnprintf().
//    it takes two arguments: const char* (format), LIN_VA_LIST (args).
//    LIN_VA_LIST is a wrapped va_list (because va_list can be an array type).
//     %r will insert the result of vsnprintf(..., ..., format, args).
//    Always use LIN_VA_LIST() to wrap the va_list; if %r is ever standardized,
//    it may be possible to remove struct lin_va_list and pass va_list directly.
//    The underlying va_list is copied with va_copy and is not modified.
//    Using this format introduces recursion; be careful of the nesting depth.
//    The main use of this feature is that you can avoid having to provide v*
//    functions (that take va_list directly) to printf-like functions.
__attribute__((format(printf, 3, 4)))
int lin_snprintf(char *str, size_t size, const char *format, ...);

// See lin_snprintf().
int lin_vsnprintf(char *str, size_t size, const char *format, va_list ap);

// Like lin_snprintf(), this formats to a buffer. However, it is designed to
// not require a buffer to hold the entire result. Instead, a callback is
// invoked when the buffer is full, and then formatting is continued. The
// callback must make new space, e.g. by either processing the current buffer
// and resetting it, or allocating and setting a new buffer.
// The user passes a buffer with dst/end to the function. The function will
// append output characters by writing to *dst and incrementing it. the end of
// the buffer is given by *end. If *dst == *end, get_space() is called. The
// callback is expected to make free space by changing *dst or *end or both.
// Unlike lin_snprintf(), this never writes a terminating \0.
// Rules for dst/end:
//  - The values in both must point to the same buffer, with *dst <= *end.
//  - *dst == *end == NULL is also allowed.
//  - As long as *dst < * end, the function may write output by writing a
//    character to **dst and then incrementing *dst (*dst += 1).
//  - The caller knows how much output the function wrote (either when it
//    returns, or get_space() is called) by comparing *dst to the original
//    value when control was passed to the function.
// get_space() rules:
//  - It's not called as long as the buffer has space. If there is enough space
//    for all output, get_space() is never called.
//  - It can freely change the values pointed to by dst and end. The simplest
//    implementation would just reset *dst to the start of the buffer, but it
//    may e.g. set *dst and *end to an entirely new buffer.
//  - Of course changing *dst and *end concurrently or from signal handlers is
//    not allowed.
//  - If a call does not result in any free space, an error code is returned.
//    get_space==NULL is allowed, and behaves like an implementation which never
//    frees space.
//  - It's always called with cb_ctx as argument, and lin_bprintf() does not
//    use cb_ctx for anything else.
// This function returns 0 on success, and a negative value on error. The error
// return value is the same as the equivalent lin_snprintf() call will return.
int lin_bprintf(char **dst, char **end, void (*get_space)(void *cb_ctx),
                void *cb_ctx, const char *format, va_list ap);

// Internal helper for %r. Do not use directly.
struct lin_va_list {
    va_list *ap;
};

// Helper for %r. Use this to pass va_list as format arguments.
#define LIN_VA_LIST(x) ((struct lin_va_list){&(x)})

#endif
