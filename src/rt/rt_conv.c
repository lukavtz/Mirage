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

/* Single-threaded getenv via Win32 (returns static buffer). */
static char g_env_buf[1024];

char *getenv(const char *name) {
    DWORD n = GetEnvironmentVariableA(name, g_env_buf, sizeof(g_env_buf));
    if (n == 0 || n >= sizeof(g_env_buf))
        return NULL;
    return g_env_buf;
}
