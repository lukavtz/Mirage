/*
 * rt_mem.c — heap allocation + memory operations via Win32.
 * No CRT. Uses process heap.
 */
#include "rt.h"

static HANDLE g_heap = NULL;

static HANDLE heap(void) {
    if (!g_heap)
        g_heap = GetProcessHeap();
    return g_heap;
}

void *malloc(size_t n) {
    if (n == 0)
        n = 1;
    return HeapAlloc(heap(), 0, n);
}

void free(void *p) {
    if (p)
        HeapFree(heap(), 0, p);
}

void *calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0)
        return malloc(1);
    if (nmemb > (size_t)-1 / size)
        return NULL;
    size_t total = nmemb * size;
    void *p = malloc(total);
    if (p)
        memset(p, 0, total);
    return p;
}

void *realloc(void *p, size_t n) {
    if (!p)
        return malloc(n);
    if (n == 0) {
        free(p);
        return NULL;
    }
    return HeapReAlloc(heap(), 0, p, n);
}

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--)
            *d++ = *s++;
    } else if (d > s) {
        d += n;
        s += n;
        while (n--)
            *--d = *--s;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y)
            return (int)*x - (int)*y;
        x++;
        y++;
    }
    return 0;
}

void *memchr(const void *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    while (n--) {
        if (*p == (unsigned char)c)
            return (void *)p;
        p++;
    }
    return NULL;
}
