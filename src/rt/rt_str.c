/*
 * rt_str.c — string functions, no CRT.
 */
#include <stddef.h>

void *malloc(size_t n);
void free(void *p);
void *memcpy(void *dst, const void *src, size_t n);

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++)
        n++;
    return n;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n-- && *a && *a == *b) {
        a++;
        b++;
    }
    if (n == (size_t)-1)
        return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

int _stricmp(const char *a, const char *b) {
    unsigned char ca, cb;
    for (;;) {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z')
            ca += 32;
        if (cb >= 'A' && cb <= 'Z')
            cb += 32;
        if (ca != cb || ca == 0)
            return (int)ca - (int)cb;
    }
}

char *strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    return (c == 0) ? (char *)s : NULL;
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;
    while (*s) {
        if (*s == (char)c)
            last = s;
        s++;
    }
    if (c == 0)
        return (char *)s;
    return (char *)last;
}

char *strstr(const char *hay, const char *needle) {
    if (!*needle)
        return (char *)hay;
    while (*hay) {
        const char *h = hay;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n)
            return (char *)hay;
        hay++;
    }
    return NULL;
}

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++))
        ;
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
    size_t i = 0;
    while (i < n && src[i]) {
        dst[i] = src[i];
        i++;
    }
    while (i < n)
        dst[i++] = 0;
    return dst;
}

char *strcat(char *dst, const char *src) {
    char *d = dst + strlen(dst);
    while ((*d++ = *src++))
        ;
    return dst;
}

char *strncat(char *dst, const char *src, size_t n) {
    char *d = dst + strlen(dst);
    size_t i = 0;
    while (i < n && src[i]) {
        *d++ = src[i++];
    }
    *d = 0;
    return dst;
}

char *mi_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p)
        memcpy(p, s, n);
    return p;
}

int isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '\f' || c == '\v';
}

int isdigit(int c) {
    return c >= '0' && c <= '9';
}

int isalpha(int c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int isalnum(int c) {
    return isalpha(c) || isdigit(c);
}

int tolower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

int toupper(int c) {
    return (c >= 'a' && c <= 'z') ? c - 32 : c;
}

char *strtok_r(char *str, const char *delim, char **saveptr) {
    char *start;
    if (str)
        *saveptr = str;
    if (!*saveptr)
        return NULL;
    start = *saveptr;
    while (*start && strchr(delim, *start))
        start++;
    if (!*start) {
        *saveptr = NULL;
        return NULL;
    }
    char *end = start;
    while (*end && !strchr(delim, *end))
        end++;
    if (*end) {
        *end = 0;
        *saveptr = end + 1;
    } else {
        *saveptr = NULL;
    }
    return start;
}

size_t wcslen(const unsigned short *s) {
    size_t n = 0;
    while (*s++)
        n++;
    return n;
}

/* dllimport thunks referenced by MinGW headers (msvcrt.dll removed). */
int (*__imp_isspace)(int) = isspace;
int (*__imp__stricmp)(const char *, const char *) = _stricmp;
int (*__imp_tolower)(int) = tolower;

/* Wide-string functions for no-CRT build */

int _wcsicmp(const unsigned short *a, const unsigned short *b) {
    while (*a && *b) {
        unsigned short ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)*a - (int)*b;
}

int _wcsnicmp(const unsigned short *a, const unsigned short *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned short ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

errno_t wcscat_s(unsigned short *dst, size_t dstsz, const unsigned short *src) {
    if (!dst || !src || dstsz == 0) return 22; /* EINVAL */
    size_t dlen = wcslen(dst);
    size_t slen = wcslen(src);
    if (dlen + slen + 1 > dstsz) return 34; /* ERANGE */
    memcpy(dst + dlen, src, (slen + 1) * sizeof(unsigned short));
    return 0;
}

/* dllimport thunks for wide functions */
int (*__imp__wcsicmp)(const unsigned short *, const unsigned short *) = _wcsicmp;
int (*__imp__wcsnicmp)(const unsigned short *, const unsigned short *, size_t) = _wcsnicmp;
errno_t (*__imp_wcscat_s)(unsigned short *, size_t, const unsigned short *) = wcscat_s;
