/*
 * rt_conv.c — numeric conversion, PRNG, environment access. No CRT.
 */
#include <windows.h>
#include <stddef.h>
#include <ctype.h>

static unsigned long g_rng_state = 0x61472f96;

void srand(unsigned int seed) {
    g_rng_state = seed ? seed : 1;
}

int rand(void) {
    g_rng_state = g_rng_state * 1103515245u + 12345u;
    return (int)((g_rng_state >> 16) & 0x7FFF);
}

long strtol(const char *s, char **endptr, int base) {
    long val = 0;
    int neg = 0;
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '+' || *s == '-') {
        neg = (*s == '-');
        s++;
    }
    if (base == 0) {
        if (*s == '0') {
            base = 8;
            s++;
            if (*s == 'x' || *s == 'X') {
                base = 16;
                s++;
            }
        } else {
            base = 10;
        }
    }
    while (*s) {
        int d;
        if (isdigit((unsigned char)*s))
            d = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            d = *s - 'A' + 10;
        else
            break;
        if (d >= base)
            break;
        val = val * base + d;
        s++;
    }
    if (endptr)
        *endptr = (char *)s;
    return neg ? -val : val;
}

int atoi(const char *s) {
    return (int)strtol(s, NULL, 10);
}

/* getenv via Win32 — rotating double-buffer so two calls don't clobber. */
static char g_env_bufs[2][1024];
static int g_env_idx = 0;

char *getenv(const char *name) {
    char *buf = g_env_bufs[g_env_idx & 1];
    g_env_idx++;
    DWORD n = GetEnvironmentVariableA(name, buf, 1024);
    if (n == 0 || n >= 1024)
        return NULL;
    return buf;
}
