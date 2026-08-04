/*
 * rt_snprintf.c — minimal printf-family for zialfi. No CRT.
 *
 * Supports the format set used across the codebase:
 *   %s %.Ns %c %d %u %ld %lu %lld %llu %x %X %lx %llx %zu %p
 *   width + zero-padding (%02d %04d %08x), %%, left-justify.
 * Returns the number of characters that would have been written
 * (excluding the terminator), matching standard snprintf semantics.
 */
#include "rt.h"

size_t strlen(const char *s);

/* MinGW ANSI-stdio aliases intentionally omit the header attributes. */
#pragma GCC diagnostic ignored "-Wmissing-attributes"
#pragma GCC diagnostic ignored "-Wformat-truncation"

static void append(char *buf, size_t size, size_t *off, char c) {
    if (*off + 1 < size)
        buf[*off] = c;
    (*off)++;
}

static void append_str(char *buf, size_t size, size_t *off,
                       const char *s, size_t len) {
    for (size_t i = 0; i < len; i++)
        append(buf, size, off, s[i]);
}

/* Convert unsigned value to digits in buffer. Returns digit count. */
static void udigits(unsigned long long v, unsigned base, int upper, char *out) {
    char tmp[24];
    unsigned i = 0;
    if (v == 0)
        tmp[i++] = '0';
    while (v) {
        unsigned d = (unsigned)(v % base);
        tmp[i++] = (char)((d < 10) ? ('0' + d)
                                   : (upper ? ('A' + d - 10) : ('a' + d - 10)));
        v /= base;
    }
    for (unsigned j = 0; j < i; j++)
        out[j] = tmp[i - 1 - j];
    out[i] = 0;
}

static void emit_num(char *buf, size_t size, size_t *off,
                     int neg, unsigned long long val, unsigned base,
                     int upper, int left, int zero, unsigned width) {
    char digits[24];
    udigits(val, base, upper, digits);
    unsigned dlen = (unsigned)strlen(digits);
    unsigned signlen = neg ? 1 : 0;
    unsigned total = dlen + signlen;
    unsigned pad = (width > total) ? (width - total) : 0;

    if (!left && !zero) {
        while (pad--)
            append(buf, size, off, ' ');
        pad = 0;
    }
    if (neg)
        append(buf, size, off, '-');
    if (zero) {
        while (pad--)
            append(buf, size, off, '0');
        pad = 0;
    }
    append_str(buf, size, off, digits, dlen);
    if (left) {
        while (pad--)
            append(buf, size, off, ' ');
    }
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap) {
    size_t off = 0;
    if (size == 0) {
        /* just count; buf may be NULL */
        size = (size_t)-1;
    }
    if (buf && size > 0)
        buf[0] = 0;

    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            append(buf, size, &off, *fmt);
            continue;
        }
        fmt++;

        /* flags */
        int left = 0, zero = 0;
        for (;;) {
            if (*fmt == '-') { left = 1; fmt++; }
            else if (*fmt == '0') { zero = 1; fmt++; }
            else break;
        }

        /* width */
        unsigned width = 0;
        if (*fmt == '*') {
            int w = va_arg(ap, int);
            if (w < 0) { left = 1; w = -w; }
            width = (unsigned)w;
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (unsigned)(*fmt - '0');
                fmt++;
            }
        }

        /* precision */
        int prec = -1;
        if (*fmt == '.') {
            fmt++;
            prec = 0;
            if (*fmt == '*') {
                prec = va_arg(ap, int);
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9') {
                    prec = prec * 10 + (*fmt - '0');
                    fmt++;
                }
            }
        }

        /* length */
        int len = 0;
        if (*fmt == 'h') { len = 'h'; fmt++; if (*fmt == 'h') { len = 'H'; fmt++; } }
        else if (*fmt == 'l') { len = 'l'; fmt++; if (*fmt == 'l') { len = 'L'; fmt++; } }
        else if (*fmt == 'z') { len = 'z'; fmt++; }

        char spec = *fmt;
        if (!spec)
            break;

        if (spec == '%') {
            append(buf, size, &off, '%');
            continue;
        }

        if (spec == 'c') {
            char c = (char)va_arg(ap, int);
            unsigned pad = (width > 1) ? (width - 1) : 0;
            if (!left) while (pad--) append(buf, size, &off, ' ');
            append(buf, size, &off, c);
            if (left) while (pad--) append(buf, size, &off, ' ');
            continue;
        }

        if (spec == 's') {
            const char *s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            size_t slen = strlen(s);
            if (prec >= 0 && (size_t)prec < slen)
                slen = (size_t)prec;
            unsigned pad = (width > slen) ? (unsigned)(width - slen) : 0;
            if (!left) while (pad--) append(buf, size, &off, ' ');
            append_str(buf, size, &off, s, slen);
            if (left) while (pad--) append(buf, size, &off, ' ');
            continue;
        }

        if (spec == 'p') {
            uintptr_t v = (uintptr_t)va_arg(ap, void *);
            char digits[24];
            udigits((unsigned long long)v, 16, 0, digits);
            append(buf, size, &off, '0');
            append(buf, size, &off, 'x');
            append_str(buf, size, &off, digits, (size_t)strlen(digits));
            continue;
        }

        /* integer conversions */
        int is_signed = 0;
        unsigned base = 10;
        int upper = 0;

        switch (spec) {
        case 'd': case 'i': is_signed = 1; break;
        case 'u': break;
        case 'x': base = 16; break;
        case 'X': base = 16; upper = 1; break;
        case 'o': base = 8; break;
        default:
            append(buf, size, &off, spec);
            continue;
        }

        unsigned long long val;
        int neg = 0;

        if (is_signed) {
            if (len == 'L') {
                long long v = va_arg(ap, long long);
                if (v < 0) { neg = 1; v = -v; }
                val = (unsigned long long)v;
            } else if (len == 'l') {
                long v = va_arg(ap, long);
                if (v < 0) { neg = 1; v = -v; }
                val = (unsigned long long)v;
            } else if (len == 'h' || len == 'H') {
                int v = va_arg(ap, int);
                if (len == 'h') v = (short)v;
                if (v < 0) { neg = 1; v = -v; }
                val = (unsigned long long)(unsigned)v;
            } else {
                int v = va_arg(ap, int);
                if (v < 0) { neg = 1; v = -v; }
                val = (unsigned long long)(unsigned)v;
            }
        } else {
            if (len == 'L')
                val = va_arg(ap, unsigned long long);
            else if (len == 'l')
                val = (unsigned long long)va_arg(ap, unsigned long);
            else if (len == 'z')
                val = (unsigned long long)va_arg(ap, size_t);
            else if (len == 'h' || len == 'H')
                val = (unsigned long long)(unsigned short)va_arg(ap, unsigned int);
            else
                val = (unsigned long long)va_arg(ap, unsigned int);
        }

        emit_num(buf, size, &off, neg, val, base, upper, left, zero, width);
    }

    if (off < size)
        buf[off] = 0;
    else if (size > 0)
        buf[size - 1] = 0;
    return (int)off;
}

int vsprintf(char *buf, const char *fmt, va_list ap) {
    return vsnprintf(buf, (size_t)-1, fmt, ap);
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

int sprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, (size_t)-1, fmt, ap);
    va_end(ap);
    return n;
}

/* MinGW ANSI stdio renames (msvcrt.dll fallbacks removed by -nostdlib). */
int __mingw_snprintf(char *buf, size_t size, const char *fmt, ...)
    __attribute__((alias("snprintf")));
int __mingw_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
    __attribute__((alias("vsnprintf")));

/* fprintf/fputs/puts — needed by cdp_grabber.c and main.c */
#include "rt.h"

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f);

int fprintf(FILE *f, const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) fwrite(buf, 1, (size_t)n, f);
    return n;
}


