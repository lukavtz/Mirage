/*
 * test_rt.c — Tests for rt_str.c, rt_mem.c, rt_conv.c, rt_snprintf.c pure functions.
 *
 * Build: make test-rt
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <windows.h>

/* ── Config for stub hash computation ───────────────────── */
#include "config.h"

/* ── Override malloc/free with CRT-safe versions ────────── */
/* rt_mem.c's malloc uses lazy PEB resolution which crashes during CRT   */
/* startup. We provide our own that call GetProcessHeap directly.         */
#undef malloc
#undef free
#undef calloc
#undef realloc
void *malloc(size_t n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
void free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
void *calloc(size_t n, size_t s) { size_t t = n * s; return HeapAlloc(GetProcessHeap(), 8, t ? t : 1); }
void *realloc(void *p, size_t n) {
    if (!p) return HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
    if (n == 0) { HeapFree(GetProcessHeap(), 0, p); return NULL; }
    return HeapReAlloc(GetProcessHeap(), 0, p, n);
}

/* ── Stubs for PEB/hash externals (rt_mem.c, rt_conv.c) ── */
/* These mirror the real hash algorithms so mirage_get_*_by_hash
   can match function names and return real Win32 pointers,
   making malloc/free/getenv work in the test binary.          */

static uint32_t s_rotl32(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

static uint32_t s_hash_exact(const uint8_t *str, size_t len, uint32_t it) {
    uint32_t h = MIRAGE_SEED;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = str[i];
        for (uint32_t j = 0; j < it; j++) {
            h = s_rotl32(h, 5); h ^= c;
            h = h * 0x1B873593u + 0x85EBCA6Bu;
        }
    }
    return h;
}

static uint32_t s_hash_ci(const uint8_t *str, size_t len, uint32_t it) {
    uint32_t h = MIRAGE_SEED;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = str[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        for (uint32_t j = 0; j < it; j++) {
            h = s_rotl32(h, 5); h ^= c;
            h = h * 0x1B873593u + 0x85EBCA6Bu;
        }
    }
    return h;
}

static uint32_t s_enc_func(const char *str) {
    size_t len = 0; while (str[len]) len++;
    uint8_t buf[256];
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)str[i] ^ MIRAGE_STRING_KEY_ENC[i % 16];
    return s_hash_exact(buf, len, 27);
}

static uint32_t s_enc_module(const char *str) {
    size_t len = 0; while (str[len]) len++;
    uint8_t buf[256];
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)str[i] ^ MIRAGE_STRING_KEY_ENC[i % 16];
    return s_hash_ci(buf, len, 28);
}

uint32_t mirage_encrypted_hash_func(const char *s)   { return s_enc_func(s); }
uint32_t mirage_encrypted_hash_module(const char *s)  { return s_enc_module(s); }
uint32_t mirage_hash_string(const uint8_t *s, size_t n, uint32_t it) { return s_hash_ci(s, n, it); }
uint32_t mirage_hash_string_exact(const uint8_t *s, size_t n, uint32_t it) { return s_hash_exact(s, n, it); }
void mirage_xor_encrypt(const uint8_t *in, uint8_t *out, size_t len)
    { for (size_t i = 0; i < len; i++) out[i] = in[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]; }
void mirage_xor_decrypt(const uint8_t *in, uint8_t *out, size_t len)
    { for (size_t i = 0; i < len; i++) out[i] = in[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]; }
int mirage_init_native_resolver(void *b) { (void)b; return 0; }

void *mirage_get_module_by_hash(uint32_t h) {
    const char *n[] = { "kernel32.dll", "ntdll.dll", NULL };
    for (int i = 0; n[i]; i++)
        if (s_enc_module(n[i]) == h) return (void *)GetModuleHandleA(n[i]);
    return NULL;
}

void *mirage_get_function_by_hash(void *mod, uint32_t h) {
    const char *n[] = {
        "GetProcessHeap", "HeapAlloc", "HeapReAlloc", "HeapFree",
        "GetEnvironmentVariableA", NULL
    };
    for (int i = 0; n[i]; i++)
        if (s_enc_func(n[i]) == h)
            return (void *)GetProcAddress((HMODULE)mod, n[i]);
    return NULL;
}

/* ── Test harness ───────────────────────────────────────── */
static int tests_run = 0, tests_passed = 0;

#define RUN(fn) do { tests_run++; printf("  %-45s ", #fn); fn(); } while (0)
#define ASSERT(c) do { if (!(c)) { printf("FAIL (%d: %s)\n", __LINE__, #c); return; } } while (0)

/* ═══ rt_str.c ═══════════════════════════════════════════ */

static void test_strlen(void) {
    ASSERT(strlen("") == 0);
    ASSERT(strlen("a") == 1);
    ASSERT(strlen("hello") == 5);
    /* embedded null */
    char buf[] = { 'h', 'i', '\0', 'x' };
    ASSERT(strlen(buf) == 2);
    /* moderate length */
    char ls[257];
    memset(ls, 'A', 256);
    ls[256] = '\0';
    ASSERT(strlen(ls) == 256);
    tests_passed++; printf("PASS\n");
}

static void test_strcmp(void) {
    ASSERT(strcmp("abc", "abc") == 0);
    ASSERT(strcmp("abc", "abd") < 0);
    ASSERT(strcmp("abd", "abc") > 0);
    ASSERT(strcmp("", "") == 0);
    ASSERT(strcmp("a", "") > 0);
    ASSERT(strcmp("", "a") < 0);
    /* unsigned comparison: 0xFF > 0xFE */
    ASSERT(strcmp("\xFF", "\xFE") > 0);
    tests_passed++; printf("PASS\n");
}

static void test_strncmp(void) {
    ASSERT(strncmp("abc", "abc", 3) == 0);
    ASSERT(strncmp("abc", "abd", 2) == 0);   /* first 2 match */
    ASSERT(strncmp("abc", "abd", 3) < 0);
    ASSERT(strncmp("abc", "abd", 0) == 0);   /* n=0 → equal */
    ASSERT(strncmp("ab", "abc", 3) < 0);     /* shorter first arg */
    tests_passed++; printf("PASS\n");
}

static void test_stricmp(void) {
    ASSERT(_stricmp("abc", "ABC") == 0);
    ASSERT(_stricmp("Hello", "hELLO") == 0);
    ASSERT(_stricmp("abc", "ABD") < 0);
    ASSERT(_stricmp("", "") == 0);
    ASSERT(_stricmp("a", "B") < 0);
    tests_passed++; printf("PASS\n");
}

static void test_strchr_fn(void) {
    const char *s = "hello";
    ASSERT(strchr(s, 'l') == s + 2);    /* first 'l' */
    ASSERT(strchr(s, 'z') == NULL);
    ASSERT(strchr(s, 'h') == s);
    ASSERT(strchr(s, '\0') == s + 5);   /* null terminator */
    ASSERT(strchr("", 'a') == NULL);
    ASSERT(strchr("", '\0') != NULL);    /* empty: points to terminator */
    tests_passed++; printf("PASS\n");
}

static void test_strrchr_fn(void) {
    const char *s = "hello";
    ASSERT(strrchr(s, 'l') == s + 3);   /* last 'l' */
    ASSERT(strrchr(s, 'z') == NULL);
    ASSERT(strrchr(s, 'h') == s);
    ASSERT(strrchr(s, '\0') == s + 5);
    tests_passed++; printf("PASS\n");
}

static void test_strstr_fn(void) {
    const char *s = "hello world";
    ASSERT(strstr(s, "world") == s + 6);
    ASSERT(strstr(s, "xyz") == NULL);
    ASSERT(strstr("hello", "hello") != NULL);
    ASSERT(strstr("hello", "") != NULL);     /* empty needle */
    ASSERT(strstr("hello", "helloo") == NULL);
    ASSERT(strstr("", "") != NULL);          /* both empty */
    ASSERT(strstr("", "a") == NULL);
    tests_passed++; printf("PASS\n");
}

static void test_strcpy_fn(void) {
    char buf[32];
    ASSERT(strcpy(buf, "hello") == buf);
    ASSERT(strcmp(buf, "hello") == 0);
    strcpy(buf, "");
    ASSERT(strcmp(buf, "") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_strncpy_fn(void) {
    char buf[16];
    /* exact fit */
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hello", 5);
    ASSERT(memcmp(buf, "hello", 5) == 0);
    /* n > strlen(src): zero-padded */
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hi", 5);
    ASSERT(buf[0] == 'h' && buf[1] == 'i');
    ASSERT(buf[2] == 0 && buf[3] == 0 && buf[4] == 0);
    /* n < strlen(src): truncated, not null-terminated */
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hello", 3);
    ASSERT(buf[0] == 'h' && buf[1] == 'e' && buf[2] == 'l');
    ASSERT(buf[3] == 'X');  /* not zeroed */
    /* n=0: no-op */
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hello", 0);
    ASSERT(buf[0] == 'X');
    tests_passed++; printf("PASS\n");
}

static void test_strcat_fn(void) {
    char buf[32];
    strcpy(buf, "hello");
    ASSERT(strcat(buf, " world") == buf);
    ASSERT(strcmp(buf, "hello world") == 0);
    /* append to empty */
    buf[0] = '\0';
    strcat(buf, "test");
    ASSERT(strcmp(buf, "test") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_strncat_fn(void) {
    char buf[32];
    strcpy(buf, "hello");
    strncat(buf, " world!!!", 6);
    ASSERT(strcmp(buf, "hello world") == 0);
    /* n=0: no change */
    strcpy(buf, "hi");
    strncat(buf, "there", 0);
    ASSERT(strcmp(buf, "hi") == 0);
    /* n > src len: full append */
    strcpy(buf, "x");
    strncat(buf, "ab", 10);
    ASSERT(strcmp(buf, "xab") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_strdup_fn(void) {
    char *p = strdup("hello");
    ASSERT(p != NULL && strcmp(p, "hello") == 0);
    free(p);
    p = strdup("");
    ASSERT(p != NULL && strcmp(p, "") == 0);
    free(p);
    /* verify it's a distinct copy */
    const char *s = "test";
    p = strdup(s);
    ASSERT(p != s && strcmp(p, s) == 0);
    free(p);
    tests_passed++; printf("PASS\n");
}

/* ═══ rt_mem.c ═══════════════════════════════════════════ */

static void test_memcpy_fn(void) {
    char src[] = "hello world";
    char dst[32];
    memset(dst, 0, sizeof(dst));
    ASSERT(memcpy(dst, src, 12) == dst);
    ASSERT(memcmp(dst, src, 12) == 0);
    /* zero bytes */
    memset(dst, 'X', sizeof(dst));
    memcpy(dst, src, 0);
    ASSERT(dst[0] == 'X');
    /* byte-by-byte */
    unsigned char a[] = { 1, 2, 3, 4, 5 }, b[5];
    memcpy(b, a, 5);
    for (int i = 0; i < 5; i++)
        ASSERT(b[i] == (unsigned char)(i + 1));
    tests_passed++; printf("PASS\n");
}

static void test_memmove_fn(void) {
    /* non-overlapping */
    char buf[] = "hello world";
    char dst[32];
    memmove(dst, buf, 12);
    ASSERT(memcmp(dst, buf, 12) == 0);
    /* overlapping: dst < src (forward copy) */
    char d1[] = "abcdef";
    memmove(d1, d1 + 2, 4);
    ASSERT(d1[0] == 'c' && d1[1] == 'd' && d1[2] == 'e' && d1[3] == 'f');
    /* overlapping: dst > src (backward copy) */
    char d2[] = "abcdef";
    memmove(d2 + 2, d2, 4);
    ASSERT(d2[0] == 'a' && d2[1] == 'b');
    ASSERT(d2[2] == 'a' && d2[3] == 'b' && d2[4] == 'c' && d2[5] == 'd');
    /* zero bytes */
    char x = 'X';
    memmove(&x, &x, 0);
    ASSERT(x == 'X');
    tests_passed++; printf("PASS\n");
}

static void test_memset_fn(void) {
    char buf[16];
    ASSERT(memset(buf, 0xAA, 16) == buf);
    for (int i = 0; i < 16; i++)
        ASSERT((unsigned char)buf[i] == 0xAA);
    /* zero-length: no-op */
    buf[0] = 'X';
    memset(buf, 0, 0);
    ASSERT(buf[0] == 'X');
    /* fill with 0 */
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < 16; i++)
        ASSERT(buf[i] == 0);
    tests_passed++; printf("PASS\n");
}

static void test_memcmp_fn(void) {
    ASSERT(memcmp("abc", "abc", 3) == 0);
    ASSERT(memcmp("abc", "abd", 3) < 0);
    ASSERT(memcmp("abd", "abc", 3) > 0);
    ASSERT(memcmp("abc", "abc", 0) == 0);   /* zero bytes */
    /* single-byte difference at position 2 */
    unsigned char a[] = { 0, 0, 0xFF, 0 }, b[] = { 0, 0, 0xFE, 0 };
    ASSERT(memcmp(a, b, 2) == 0);
    ASSERT(memcmp(a, b, 3) > 0);
    tests_passed++; printf("PASS\n");
}

static void test_memchr_fn(void) {
    const char *s = "hello world";
    ASSERT(memchr(s, 'w', 11) == s + 6);
    ASSERT(memchr(s, 'z', 11) == NULL);
    ASSERT(memchr(s, 'o', 5) == s + 4);    /* within range */
    ASSERT(memchr(s, 'o', 4) == NULL);     /* 'o' at index 4, n=4 */
    ASSERT(memchr(s, 'x', 0) == NULL);     /* zero length */
    /* binary search */
    unsigned char data[] = { 0, 0, 0xFF, 0 };
    ASSERT(memchr(data, 0xFF, 4) == &data[2]);
    tests_passed++; printf("PASS\n");
}

/* ═══ rt_conv.c ═══════════════════════════════════════════ */

static void test_srand_rand(void) {
    /* determinism: same seed → same sequence */
    srand(42);
    int a1 = rand(), a2 = rand(), a3 = rand();
    srand(42);
    int b1 = rand(), b2 = rand(), b3 = rand();
    ASSERT(a1 == b1 && a2 == b2 && a3 == b3);
    /* different seed → different sequence */
    srand(1); int c1 = rand();
    srand(2); int d1 = rand();
    ASSERT(c1 != d1);
    /* seed 0 treated as 1 */
    srand(0); int e1 = rand();
    srand(1); int f1 = rand();
    ASSERT(e1 == f1);
    /* range: 0..0x7FFF */
    srand(12345);
    for (int i = 0; i < 100; i++) {
        int r = rand();
        ASSERT(r >= 0 && r <= 0x7FFF);
    }
    tests_passed++; printf("PASS\n");
}

static void test_strtol_fn(void) {
    char *end;
    /* decimal */
    ASSERT(strtol("123", NULL, 10) == 123);
    ASSERT(strtol("-42", NULL, 10) == -42);
    ASSERT(strtol("0", NULL, 10) == 0);
    /* hexadecimal */
    ASSERT(strtol("FF", NULL, 16) == 255);
    /* impl note: explicit base=16 does not strip 0x prefix; use base=0 for that */
    ASSERT(strtol("0xff", NULL, 0) == 255);
    /* octal */
    ASSERT(strtol("77", NULL, 8) == 63);
    /* auto-detect base (base=0) */
    ASSERT(strtol("123", NULL, 0) == 123);       /* decimal */
    ASSERT(strtol("0xFF", NULL, 0) == 255);      /* hex via 0x prefix */
    ASSERT(strtol("077", NULL, 0) == 63);        /* octal via 0 prefix */
    ASSERT(strtol("0x10", NULL, 0) == 16);
    /* leading whitespace */
    ASSERT(strtol("  42", NULL, 10) == 42);
    ASSERT(strtol("\t\n 99", NULL, 10) == 99);
    /* leading + */
    ASSERT(strtol("+42", NULL, 10) == 42);
    /* endptr */
    ASSERT(strtol("123abc", &end, 10) == 123);
    ASSERT(*end == 'a');
    ASSERT(strtol("0xFFrest", &end, 0) == 255);
    ASSERT(*end == 'r');
    tests_passed++; printf("PASS\n");
}

static void test_atoi_fn(void) {
    ASSERT(atoi("123") == 123);
    ASSERT(atoi("-42") == -42);
    ASSERT(atoi("0") == 0);
    ASSERT(atoi("  42") == 42);
    ASSERT(atoi("") == 0);
    ASSERT(atoi("abc") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_strtod_fn(void) {
    char *end;
    double e = 1e-9;
    ASSERT(fabs(strtod("42", NULL) - 42.0) < e);
    ASSERT(fabs(strtod("3.14", NULL) - 3.14) < e);
    ASSERT(fabs(strtod("-2.5", NULL) + 2.5) < e);
    ASSERT(fabs(strtod("1.5e2", NULL) - 150.0) < e);
    ASSERT(fabs(strtod("1.5e-2", NULL) - 0.015) < e);
    ASSERT(fabs(strtod("1E3", NULL) - 1000.0) < e);
    ASSERT(fabs(strtod("  3.14", NULL) - 3.14) < e);
    ASSERT(fabs(strtod("+42", NULL) - 42.0) < e);
    ASSERT(fabs(strtod("3.14rest", &end) - 3.14) < e);
    ASSERT(*end == 'r');
    ASSERT(fabs(strtod("0", NULL)) < e);
    tests_passed++; printf("PASS\n");
}

/* ═══ rt_snprintf.c ═══════════════════════════════════════ */

static void test_snprintf_basic(void) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "hello %s %d", "world", 42);
    ASSERT(n == 14 && strcmp(buf, "hello world 42") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_truncation(void) {
    char buf[8];
    int n = snprintf(buf, sizeof(buf), "hello world %d", 42);
    ASSERT(n == 14);                       /* would-have-written count */
    ASSERT(strlen(buf) == 7);
    ASSERT(strcmp(buf, "hello w") == 0);   /* truncated + null */
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_size1(void) {
    char buf[16];
    memset(buf, 'X', sizeof(buf));
    int n = snprintf(buf, 1, "hello");
    ASSERT(n == 5);       /* would-have-written */
    ASSERT(buf[0] == '\0');
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_int(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", 42);    ASSERT(strcmp(buf, "42") == 0);
    snprintf(buf, sizeof(buf), "%d", -42);   ASSERT(strcmp(buf, "-42") == 0);
    snprintf(buf, sizeof(buf), "%d", 0);     ASSERT(strcmp(buf, "0") == 0);
    snprintf(buf, sizeof(buf), "%u", 42u);   ASSERT(strcmp(buf, "42") == 0);
    snprintf(buf, sizeof(buf), "%02d", 5);   ASSERT(strcmp(buf, "05") == 0);
    snprintf(buf, sizeof(buf), "%04d", 42);  ASSERT(strcmp(buf, "0042") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_hex(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%x", 0xDEAD);        ASSERT(strcmp(buf, "dead") == 0);
    snprintf(buf, sizeof(buf), "%X", 0xDEAD);        ASSERT(strcmp(buf, "DEAD") == 0);
    snprintf(buf, sizeof(buf), "%08x", 0xDEADBEEF);  ASSERT(strcmp(buf, "deadbeef") == 0);
    snprintf(buf, sizeof(buf), "%04x", 0xA);         ASSERT(strcmp(buf, "000a") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_string(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", "hello");    ASSERT(strcmp(buf, "hello") == 0);
    snprintf(buf, sizeof(buf), "%.3s", "hello");  ASSERT(strcmp(buf, "hel") == 0);
    snprintf(buf, sizeof(buf), "%10s", "hi");     ASSERT(strcmp(buf, "        hi") == 0);
    snprintf(buf, sizeof(buf), "%-10s!", "hi");   ASSERT(strcmp(buf, "hi        !") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_char(void) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%c", 'A');     ASSERT(strcmp(buf, "A") == 0);
    snprintf(buf, sizeof(buf), "%5c", 'X');    ASSERT(strcmp(buf, "    X") == 0);
    snprintf(buf, sizeof(buf), "%-5c!", 'X');  ASSERT(strcmp(buf, "X    !") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_percent(void) {
    char buf[16];
    snprintf(buf, sizeof(buf), "100%%");
    ASSERT(strcmp(buf, "100%") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_long(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%ld", 1234567890L);    ASSERT(strcmp(buf, "1234567890") == 0);
    snprintf(buf, sizeof(buf), "%lu", 4000000000UL);   ASSERT(strcmp(buf, "4000000000") == 0);
    snprintf(buf, sizeof(buf), "%lx", 0xDEADBEEFL);    ASSERT(strcmp(buf, "deadbeef") == 0);
    snprintf(buf, sizeof(buf), "%ld", -12345L);        ASSERT(strcmp(buf, "-12345") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_snprintf_left_zero(void) {
    char buf[32];
    /* left-justify → spaces on right */
    snprintf(buf, sizeof(buf), "%-8x!", 0xAB);
    ASSERT(strcmp(buf, "ab      !") == 0);
    /* zero-pad */
    snprintf(buf, sizeof(buf), "%08x", 0xAB);
    ASSERT(strcmp(buf, "000000ab") == 0);
    tests_passed++; printf("PASS\n");
}

static void test_sprintf_fn(void) {
    char buf[64];
    int n = sprintf(buf, "hello %s %d", "world", 42);
    ASSERT(n == 14 && strcmp(buf, "hello world 42") == 0);
    tests_passed++; printf("PASS\n");
}

/* ═══ main ════════════════════════════════════════════════ */

int main(void) {
    printf("=== test_rt: rt_str + rt_mem + rt_conv + rt_snprintf ===\n");

    printf("[rt_str.c]\n");
    RUN(test_strlen);
    RUN(test_strcmp);
    RUN(test_strncmp);
    RUN(test_stricmp);
    RUN(test_strchr_fn);
    RUN(test_strrchr_fn);
    RUN(test_strstr_fn);
    RUN(test_strcpy_fn);
    RUN(test_strncpy_fn);
    RUN(test_strcat_fn);
    RUN(test_strncat_fn);
    RUN(test_strdup_fn);

    printf("[rt_mem.c]\n");
    RUN(test_memcpy_fn);
    RUN(test_memmove_fn);
    RUN(test_memset_fn);
    RUN(test_memcmp_fn);
    RUN(test_memchr_fn);

    printf("[rt_conv.c]\n");
    RUN(test_srand_rand);
    RUN(test_strtol_fn);
    RUN(test_atoi_fn);
    RUN(test_strtod_fn);

    printf("[rt_snprintf.c]\n");
    RUN(test_snprintf_basic);
    RUN(test_snprintf_truncation);
    RUN(test_snprintf_size1);
    RUN(test_snprintf_int);
    RUN(test_snprintf_hex);
    RUN(test_snprintf_string);
    RUN(test_snprintf_char);
    RUN(test_snprintf_percent);
    RUN(test_snprintf_long);
    RUN(test_snprintf_left_zero);
    RUN(test_sprintf_fn);

    printf("=== %d/%d PASSED ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
