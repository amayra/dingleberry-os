// (c) Marco Paland (info@paland.com)
//     2014-2018, PALANDesign Hannover, Germany
//
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Originally retrieved from:
//  https://github.com/mpaland/printf
//  be3047911075b2e917d73451068e0b84373eefb9
//
// Float formatting code from: musl, 2de29bc994029b903a366b8a4a9f8c3c3ee2be90
//  vfprintf.c
//
// Modified for use in libinsanity.
//

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <math.h>
#include <float.h>

#include "minmax.h"
#include "printf.h"

// internal flag definitions
#define FLAGS_ZEROPAD   (1U <<  0U)
#define FLAGS_LEFT      (1U <<  1U)
#define FLAGS_PLUS      (1U <<  2U)
#define FLAGS_SPACE     (1U <<  3U)
#define FLAGS_HASH      (1U <<  4U)
#define FLAGS_UPPERCASE (1U <<  5U)
#define FLAGS_CHAR      (1U <<  6U)
#define FLAGS_SHORT     (1U <<  7U)
#define FLAGS_LONG      (1U <<  8U)
#define FLAGS_LONG_LONG (1U <<  9U)
#define FLAGS_WIDTH     (1U << 11U)

struct buf {
    char *dst;
    char *end;
    size_t idx;
};

static void outc(struct buf *buf, char c)
{
    if (buf->dst < buf->end)
        *buf->dst++ = c;
    buf->idx++;
}

static void out(struct buf *buf, const char *s, size_t l)
{
    while (l--)
        outc(buf, *s++);
}

static void out_pad(struct buf *buf, char c, size_t l)
{
    while (l--)
        outc(buf, c);
}

// internal ASCII string to unsigned int conversion
// return 0 if there is no valid digit
static inline unsigned int fmt_atoi(const char **str)
{
    unsigned int i = 0U;
    while (**str >= '0' && **str <= '9')
        i = i * 10U + (unsigned int)(*((*str)++) - '0');
    return i;
}

// internal itoa format
static void ntoa_format(struct buf *buffer, char *buf, int len,
                        bool negative, unsigned int base, int prec,
                        int width, unsigned int flags)
{
    bool is_zero = len == 1 && buf[0] == '0';

    // If precision is forced to 0, don't output anything. Unless it's the
    // crazy corner case of "%#.0o", which must output a single "0".
    if (prec == 0 && is_zero && !(base == 8 && (flags & FLAGS_HASH)))
        len = 0;

    char prefix[3];
    int prefix_len = 0;

    if (negative) {
        prefix[prefix_len++] = '-';
    } else if (flags & FLAGS_PLUS) {
        prefix[prefix_len++] = '+'; // ignore the space if the '+' exists
    } else if (flags & FLAGS_SPACE) {
        prefix[prefix_len++] = ' ';
    }

    // (0 values never include a prefix)
    if ((flags & FLAGS_HASH) && !is_zero) {
        if (base == 16) {
            prefix[prefix_len++] = '0';
            prefix[prefix_len++] = flags & FLAGS_UPPERCASE ? 'X' : 'x';
        } else if (base == 8 && prec <= len) {
            prefix[prefix_len++] = '0';
        }
    }

    // If zeropad is given, precision is unset. Make it pad to the given width,
    // which means we need to include prefixes into the pad amount.
    if (flags & FLAGS_ZEROPAD) {
        prec = width >= prefix_len ? width - prefix_len : 0;
        width = 0;
    }

    size_t zero_pad = 0;
    if (!(flags & FLAGS_LEFT) && prec > len)
        zero_pad = prec - len;

    size_t total_len = prefix_len + zero_pad + len;
    size_t space_pad = width > total_len ? width - total_len : 0;

    if (!(flags & FLAGS_LEFT))
        out_pad(buffer, ' ', space_pad);

    out(buffer, prefix, prefix_len);
    out_pad(buffer, '0', zero_pad);
    out(buffer, buf, len);

    if ((flags & FLAGS_LEFT))
        out_pad(buffer, ' ', space_pad);
}

static char convert_digit(unsigned int flags, unsigned int digit)
{
    return digit < 10 ? '0' + digit
                      : (flags & FLAGS_UPPERCASE ? 'A' : 'a') + (digit - 10);
}

// internal itoa for 'long' type
static void ntoa_long(struct buf *buffer, unsigned long value,
                      bool negative, unsigned int base,
                      int prec, int width, unsigned int flags)
{
    // Worst case: base 2, plus terminating \0
    char buf[sizeof(value) * 8 + 1];
    int pos = sizeof(buf);

    buf[--pos] = '\0';

    do {
        assert(pos > 0);
        buf[--pos] = convert_digit(flags, value % base);
        value /= base;
    } while (value);

    ntoa_format(buffer, buf + pos, sizeof(buf) - pos - 1, negative, base,
                prec, width, flags);
}

// internal itoa for 'long long' type
// the only difference to ntoa_long is that the latter uses 32 bit arithmetic,
// which will be faster on many platforms
static void ntoa_long_long(struct buf *buffer, unsigned long long value,
                           bool negative, unsigned int base,
                           int prec, int width, unsigned int flags)
{
    // Worst case: base 2, plus terminating \0
    char buf[sizeof(value) * 8 + 1];
    int pos = sizeof(buf);

    buf[--pos] = '\0';

    do {
        assert(pos > 0);
        buf[--pos] = convert_digit(flags, value % base);
        value /= base;
    } while (value);

    ntoa_format(buffer, buf + pos, sizeof(buf) - pos - 1, negative, base,
                prec, width, flags);
}

static void pad(struct buf *f, char c, int w, int l, int fl)
{
    char pad[256];
    if (fl & (FLAGS_LEFT | FLAGS_ZEROPAD) || l >= w)
        return;
    l = w - l;
    memset(pad, c, l > sizeof pad ? sizeof pad : l);
    for (; l >= sizeof pad; l -= sizeof pad)
        out(f, pad, sizeof pad);
    out(f, pad, l);
}

static const char xdigits[16] = "0123456789ABCDEF";

static char *fmt_u(uintmax_t x, char *s)
{
    unsigned long y;
    for (; x > ULONG_MAX; x /= 10)
        *--s = '0' + x % 10;
    for (y = x; y; y /= 10)
        *--s = '0' + y % 10;
    return s;
}

/* Do not override this check. The floating point printing code below
 * depends on the float.h constants being right. If they are wrong, it
 * may overflow the stack. */
#if LDBL_MANT_DIG == 53
typedef char compiler_defines_long_double_incorrectly[9 - (int) sizeof(long double)];
#endif

static int fmt_fp(struct buf *f, long double y, int w, int p, int fl, int t)
{
    uint32_t big[(LDBL_MANT_DIG + 28) / 29 + 1          // mantissa expansion
                 + (LDBL_MAX_EXP + LDBL_MANT_DIG + 28 + 8) / 9]; // exponent expansion
    uint32_t *a, *d, *r, *z;
    int e2 = 0, e, i, j, l;
    char buf[9 + LDBL_MANT_DIG / 4], *s;
    const char *prefix = "-0X+0X 0X-0x+0x 0x";
    int pl;
    char ebuf0[3 * sizeof(int)], *ebuf = &ebuf0[3 * sizeof(int)], *estr;

    pl = 1;
    if (signbit(y)) {
        y = -y;
    } else if (fl & FLAGS_PLUS) {
        prefix += 3;
    } else if (fl & FLAGS_SPACE) {
        prefix += 6;
    } else {
        prefix++, pl = 0;
    }

    if (!isfinite(y)) {
        char *s = (t & 32) ? "inf" : "INF";
        if (y != y)
            s = (t & 32) ? "nan" : "NAN";
        pad(f, ' ', w, 3 + pl, fl & ~FLAGS_ZEROPAD);
        out(f, prefix, pl);
        out(f, s, 3);
        pad(f, ' ', w, 3 + pl, fl ^ FLAGS_LEFT);
        return MAX(w, 3 + pl);
    }

    y = frexpl(y, &e2) * 2;
    if (y)
        e2--;

    if ((t | 32) == 'a') {
        long double round = 8.0;
        int re;

        if (t & 32)
            prefix += 9;
        pl += 2;

        if (p < 0 || p >= LDBL_MANT_DIG / 4 - 1)
            re = 0;
        else
            re = LDBL_MANT_DIG / 4 - 1 - p;

        if (re) {
            round *= 1 << (LDBL_MANT_DIG % 4);
            while (re--)
                round *= 16;
            if (*prefix == '-') {
                y = -y;
                y -= round;
                y += round;
                y = -y;
            } else {
                y += round;
                y -= round;
            }
        }

        estr = fmt_u(e2 < 0 ? -e2 : e2, ebuf);
        if (estr == ebuf)
            *--estr = '0';
        *--estr = (e2 < 0 ? '-' : '+');
        *--estr = t + ('p' - 'a');

        s = buf;
        do {
            int x = y;
            *s++ = xdigits[x] | (t & 32);
            y = 16 * (y - x);
            if (s - buf == 1 && (y || p > 0 || (fl & FLAGS_HASH)))
                *s++ = '.';
        } while (y);

        if (p > INT_MAX - 2 - (ebuf - estr) - pl)
            return -1;
        if (p && s - buf - 2 < p)
            l = (p + 2) + (ebuf - estr);
        else
            l = (s - buf) + (ebuf - estr);

        pad(f, ' ', w, pl + l, fl);
        out(f, prefix, pl);
        pad(f, '0', w, pl + l, fl ^ FLAGS_ZEROPAD);
        out(f, buf, s - buf);
        pad(f, '0', l - (ebuf - estr) - (s - buf), 0, 0);
        out(f, estr, ebuf - estr);
        pad(f, ' ', w, pl + l, fl ^ FLAGS_LEFT);
        return MAX(w, pl + l);
    }
    if (p < 0)
        p = 6;

    if (y)
        y *= 0x1p28, e2 -= 28;

    if (e2 < 0) {
        a = r = z = big;
    } else {
        a = r = z = big + sizeof(big) / sizeof(*big) - LDBL_MANT_DIG - 1;
    }

    do {
        *z = y;
        y = 1000000000 * (y - *z++);
    } while (y);

    while (e2 > 0) {
        uint32_t carry = 0;
        int sh = MIN(29, e2);
        for (d = z - 1; d >= a; d--) {
            uint64_t x = ((uint64_t)*d << sh) + carry;
            *d = x % 1000000000;
            carry = x / 1000000000;
        }
        if (carry)
            *--a = carry;
        while (z > a && !z[-1])
            z--;
        e2 -= sh;
    }

    while (e2 < 0) {
        uint32_t carry = 0, *b;
        int sh = MIN(9, -e2), need = 1 + (p + LDBL_MANT_DIG / 3U + 8) / 9;
        for (d = a; d < z; d++) {
            uint32_t rm = *d & ((1 << sh) - 1);
            *d = (*d >> sh) + carry;
            carry = (1000000000 >> sh) * rm;
        }
        if (!*a)
            a++;
        if (carry)
            *z++ = carry;
        /* Avoid (slow!) computation past requested precision */
        b = (t | 32) == 'f' ? r : a;
        if (z - b > need)
            z = b + need;
        e2 += sh;
    }

    if (a < z) {
        for (i = 10, e = 9 * (r - a); *a >= i; i *= 10, e++) {
        }
    } else {
        e = 0;
    }

    /* Perform rounding: j is precision after the radix (possibly neg) */
    j = p - ((t | 32) != 'f') * e - ((t | 32) == 'g' && p);
    if (j < 9 * (z - r - 1)) {
        uint32_t x;
        /* We avoid C's broken division of negative numbers */
        d = r + 1 + ((j + 9 * LDBL_MAX_EXP) / 9 - LDBL_MAX_EXP);
        j += 9 * LDBL_MAX_EXP;
        j %= 9;
        for (i = 10, j++; j < 9; i *= 10, j++) {
        }
        x = *d % i;
        /* Are there any significant digits past j? */
        if (x || d + 1 != z) {
            long double round = 2 / LDBL_EPSILON;
            long double small;
            if ((*d / i & 1) || (i == 1000000000 && d > a && (d[-1] & 1)))
                round += 2;
            if (x < i / 2) {
                small = 0x0.8p0;
            } else if (x == i / 2 && d + 1 == z) {
                small = 0x1.0p0;
            } else {
                small = 0x1.8p0;
            }
            if (pl && *prefix == '-')
                round *= -1, small *= -1;
            *d -= x;
            /* Decide whether to round by probing round+small */
            if (round + small != round) {
                *d = *d + i;
                while (*d > 999999999) {
                    *d-- = 0;
                    if (d < a)
                        *--a = 0;
                    (*d)++;
                }
                for (i = 10, e = 9 * (r - a); *a >= i; i *= 10, e++) {
                }
            }
        }
        if (z > d + 1)
            z = d + 1;
    }
    for (; z > a && !z[-1]; z--) {
    }

    if ((t | 32) == 'g') {
        if (!p)
            p++;
        if (p > e && e >= -4) {
            t--;
            p -= e + 1;
        } else {
            t -= 2;
            p--;
        }
        if (!(fl & FLAGS_HASH)) {
            /* Count trailing zeros in last place */
            if (z > a && z[-1]) {
                for (i = 10, j = 0; z[-1] % i == 0; i *= 10, j++);
            } else {
                j = 9;
            }
            if ((t | 32) == 'f') {
                p = MIN(p, MAX(0, 9 * (z - r - 1) - j));
            } else {
                p = MIN(p, MAX(0, 9 * (z - r - 1) + e - j));
            }
        }
    }
    if (p > INT_MAX - 1 - (p || (fl & FLAGS_HASH)))
        return -1;
    l = 1 + p + (p || (fl & FLAGS_HASH));
    if ((t | 32) == 'f') {
        if (e > INT_MAX - l)
            return -1;
        if (e > 0)
            l += e;
    } else {
        estr = fmt_u(e < 0 ? -e : e, ebuf);
        while (ebuf - estr < 2)
            *--estr = '0';
        *--estr = (e < 0 ? '-' : '+');
        *--estr = t;
        if (ebuf - estr > INT_MAX - l)
            return -1;
        l += ebuf - estr;
    }

    if (l > INT_MAX - pl)
        return -1;
    pad(f, ' ', w, pl + l, fl);
    out(f, prefix, pl);
    pad(f, '0', w, pl + l, fl ^ FLAGS_ZEROPAD);

    if ((t | 32) == 'f') {
        if (a > r)
            a = r;
        for (d = a; d <= r; d++) {
            char *s = fmt_u(*d, buf + 9);
            if (d != a) {
                while (s > buf)
                    *--s = '0';
            } else if (s == buf + 9) {
                *--s = '0';
            }
            out(f, s, buf + 9 - s);
        }
        if (p || (fl & FLAGS_HASH))
            out(f, ".", 1);
        for (; d < z && p > 0; d++, p -= 9) {
            char *s = fmt_u(*d, buf + 9);
            while (s > buf)
                *--s = '0';
            out(f, s, MIN(9, p));
        }
        pad(f, '0', p + 9, 9, 0);
    } else {
        if (z <= a)
            z = a + 1;
        for (d = a; d < z && p >= 0; d++) {
            char *s = fmt_u(*d, buf + 9);
            if (s == buf + 9)
                *--s = '0';
            if (d != a) {
                while (s > buf)
                    *--s = '0';
            } else {
                out(f, s++, 1);
                if (p > 0 || (fl & FLAGS_HASH))
                    out(f, ".", 1);
            }
            out(f, s, MIN(buf + 9 - s, p));
            p -= buf + 9 - s;
        }
        pad(f, '0', p + 18, 18, 0);
        out(f, estr, ebuf - estr);
    }

    pad(f, ' ', w, pl + l, fl ^ FLAGS_LEFT);

    return MAX(w, pl + l);
}

// internal vsnprintf
static int vsnprintf_(struct buf *buffer, const char *format, va_list va)
{
    while (*format) {
        // format specifier?  %[flags][width][.precision][length]
        if (*format != '%') {
            outc(buffer, *format++);
            continue;
        }

        format++;

        // evaluate flags
        unsigned int flags = 0U;
        while (1) {
            bool done = false;
            switch (*format) {
            case '0':
                flags |= FLAGS_ZEROPAD;
                break;
            case '-':
                flags |= FLAGS_LEFT;
                break;
            case '+':
                flags |= FLAGS_PLUS;
                break;
            case ' ':
                flags |= FLAGS_SPACE;
                break;
            case '#':
                flags |= FLAGS_HASH;
                break;
            default:
                done = true;
                break;
            }
            if (done)
                break;
            format++;
        }

        // evaluate width field
        int width = 0;
        if (*format == '*') {
            width = va_arg(va, int);
            if (width < 0) {
                flags |= FLAGS_LEFT; // reverse padding
                width = width == INT_MIN ? INT_MAX : -width;
            }
            format++;
        } else {
            width = fmt_atoi(&format);
        }

        // evaluate precision field
        int precision = -1;
        if (*format == '.') {
            format++;
            if (*format == '*') {
                precision = va_arg(va, int);
                format++;
            } else {
                precision = fmt_atoi(&format);
            }
        }

        // "A - overrides a 0 if both are given."
        if (flags & FLAGS_LEFT)
            flags &= ~FLAGS_ZEROPAD;

        // evaluate length field
        switch (*format) {
        case 'l':
            flags |= FLAGS_LONG;
            format++;
            if (*format == 'l') {
                flags |= FLAGS_LONG_LONG;
                format++;
            }
            break;
        case 'h':
            flags |= FLAGS_SHORT;
            format++;
            if (*format == 'h') {
                flags |= FLAGS_CHAR;
                format++;
            }
            break;
        case 't':
            flags |= sizeof(ptrdiff_t) == sizeof(long)
                     ? FLAGS_LONG : FLAGS_LONG_LONG;
            format++;
            break;
        case 'j':
            flags |= sizeof(intmax_t) == sizeof(long)
                     ? FLAGS_LONG : FLAGS_LONG_LONG;
            format++;
            break;
        case 'z':
            flags |= sizeof(size_t) == sizeof(long)
                     ? FLAGS_LONG : FLAGS_LONG_LONG;
            format++;
            break;
        default:
            break;
        }

        // evaluate specifier
        char fmt = *format++;
        switch (fmt) {
        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'X':
        case 'o':
        case 'b': {
            // set the base
            unsigned int base = 10U;
            if (fmt == 'x' || fmt == 'X')
                base = 16U;
            else if (fmt == 'o')
                base =  8U;
            else if (fmt == 'b') {
                base =  2U;
            }

            // uppercase
            if (fmt == 'X')
                flags |= FLAGS_UPPERCASE;

            // no plus or space flag for u, x, X, o, b
            if (fmt != 'i' && fmt != 'd')
                flags &= ~(FLAGS_PLUS | FLAGS_SPACE);

            // if a precision is specified, the 0 flags is ignored
            if (precision >= 0)
                flags &= ~FLAGS_ZEROPAD;

            // convert the integer
            if (fmt == 'i' || fmt == 'd') {
                // signed
                if (flags & FLAGS_LONG_LONG) {
                    long long value = va_arg(va, long long);
                    ntoa_long_long(buffer,
                        (unsigned long long)(value > 0 ? value : 0 - value),
                        value < 0, base, precision, width, flags);
                } else if (flags & FLAGS_LONG) {
                    long value = va_arg(va, long);
                    ntoa_long(buffer,
                        (unsigned long)(value > 0 ? value : 0 - value),
                        value < 0, base, precision, width, flags);
                } else {
                    int value = flags & FLAGS_CHAR
                              ? (char)va_arg(va, int)
                              : (flags & FLAGS_SHORT)
                              ? (short int)va_arg(va, int)
                              : va_arg(va, int);
                    ntoa_long(buffer,
                               (unsigned int)(value > 0 ? value : 0 - value),
                               value < 0, base, precision, width, flags);
                }
            } else {
                // unsigned
                if (flags & FLAGS_LONG_LONG) {
                    ntoa_long_long(buffer, va_arg(va, unsigned long long),
                                    false, base, precision, width, flags);
                } else if (flags & FLAGS_LONG) {
                    ntoa_long(buffer, va_arg(va, unsigned long),
                               false, base, precision, width, flags);
                } else {
                    unsigned int value = flags & FLAGS_CHAR
                            ? (unsigned char)va_arg(va, unsigned int)
                            : (flags & FLAGS_SHORT)
                            ? (unsigned short int)va_arg(va, unsigned int)
                            : va_arg(va, unsigned int);
                    ntoa_long(buffer, value, false, base, precision, width,
                               flags);
                }
            }
            break;
        }
        case 'f':
        case 'F':
        case 'g':
        case 'G':
        case 'e':
        case 'E':
        case 'a':
        case 'A': {
            if (fmt_fp(buffer, va_arg(va, double), width, precision, flags, fmt) < 0)
                out(buffer, "<error>", 7);
            break;
        }
        case 'c': {
            // pre padding
            if (!(flags & FLAGS_LEFT) && width > 1)
                out_pad(buffer, ' ', width - 1);
            // char output
            outc(buffer, (char)va_arg(va, int));
            // post padding
            if ((flags & FLAGS_LEFT) && width > 1)
                out_pad(buffer, ' ', width - 1);
            break;
        }

        case 's': {
            char *p = va_arg(va, char *);
            size_t l = strlen(p);
            if (precision >= 0)
                l = l < precision ? l : precision;
            // pre padding
            if (!(flags & FLAGS_LEFT) && width > l)
                out_pad(buffer, ' ', width - l);
            // string output
            out(buffer, p, l);
            // post padding
            if ((flags & FLAGS_LEFT) && width > l)
                out_pad(buffer, ' ', width - l);
            break;
        }

        case 'p': {
            width = sizeof(void *) * 2U;
            flags |= FLAGS_ZEROPAD | FLAGS_UPPERCASE;
            if (sizeof(uintptr_t) == sizeof(long long)) {
                ntoa_long_long(buffer, (uintptr_t)va_arg(va, void *), false,
                                16U, precision, width, flags);
            } else {
                ntoa_long(buffer, (unsigned long)((uintptr_t)va_arg(va, void *)),
                           false, 16U, precision, width, flags);
            }
            break;
        }

        case '%':
            outc(buffer, '%');
            break;

        default:
            outc(buffer, fmt);
            break;
        }
    }

    // return total number of chars, including the amount outside of the buffer
    return buffer->idx <= INT_MAX ? buffer->idx : -1;
}

int lin_snprintf(char *buffer, size_t count, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    int ret = lin_vsnprintf(buffer, count, format, va);
    va_end(va);
    return ret;
}

int lin_vsnprintf(char *buffer, size_t count, const char *format, va_list va)
{
    struct buf buf = {
        .dst = buffer,
        // (Always reserve 1 byte for the \0 if there's space.)
        .end = count ? buffer + count - 1 : buffer,
    };

    int res = vsnprintf_(&buf, format, va);

    // termination
    if (count)
        buf.dst[0] = '\0';

    return res;
}
