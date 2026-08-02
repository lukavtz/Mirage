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

double strtod(const char *s, char **endptr) {
    double result = 0.0;
    double frac = 0.0;
    double divisor = 1.0;
    int neg = 0;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        result = result * 10.0 + (*s - '0');
        s++;
    }
    if (*s == '.') {
        s++;
        while (*s >= '0' && *s <= '9') {
            frac = frac * 10.0 + (*s - '0');
            divisor *= 10.0;
            s++;
        }
        result += frac / divisor;
    }
    if (*s == 'e' || *s == 'E') {
        s++;
        int eneg = 0;
        if (*s == '-') { eneg = 1; s++; }
        else if (*s == '+') { s++; }
        int eval = 0;
        while (*s >= '0' && *s <= '9') {
            eval = eval * 10 + (*s - '0');
            s++;
        }
        double emul = 1.0;
        for (int i = 0; i < eval; i++) emul *= 10.0;
        if (eneg) result /= emul;
        else result *= emul;
    }
    if (endptr) *endptr = (char *)s;
    return neg ? -result : result;
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
