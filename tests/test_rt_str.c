/*
 * test_rt_str.c — Runtime string function tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc/rt -std=c11 -o tests/test_rt_str.exe tests/test_rt_str.c src/rt/rt_str.c src/rt/rt_mem.c src/rt/rt_snprintf.c src/rt/rt_conv.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

/* Pull in rt_str declarations */
size_t rt_strlen(const char *s);
char *rt_strcpy(char *dst, const char *src);
int rt_strcmp(const char *a, const char *b);
char *rt_strstr(const char *haystack, const char *needle);
char *rt_strchr(const char *s, int c);
char *rt_strrchr(const char *s, int c);
size_t rt_strlcpy(char *dst, const char *src, size_t dstsize);
char *rt_strcat(char *dst, const char *src);
size_t wcslen(const unsigned short *s);
int _wcsicmp(const unsigned short *a, const unsigned short *b);
int _wcsnicmp(const unsigned short *a, const unsigned short *b, size_t n);
int rt_snprintf(char *buf, size_t size, const char *fmt, ...);

static void test_strlen(void) {
    assert(rt_strlen("") == 0);
    assert(rt_strlen("a") == 1);
    assert(rt_strlen("hello") == 5);
    printf("  PASS: test_strlen\n");
}

static void test_strcmp(void) {
    assert(rt_strcmp("abc", "abc") == 0);
    assert(rt_strcmp("abc", "abd") < 0);
    assert(rt_strcmp("abd", "abc") > 0);
    assert(rt_strcmp("", "") == 0);
    assert(rt_strcmp("a", "") > 0);
    printf("  PASS: test_strcmp\n");
}

static void test_strstr(void) {
    assert(rt_strstr("hello world", "world") != NULL);
    assert(rt_strstr("hello world", "xyz") == NULL);
    assert(rt_strstr("hello", "hello") != NULL);
    printf("  PASS: test_strstr\n");
}

static void test_strchr(void) {
    const char *s = "hello world";
    assert(rt_strchr(s, 'w') == s + 6);
    assert(rt_strchr(s, 'z') == NULL);
    assert(rt_strchr(s, 'h') == s);
    printf("  PASS: test_strchr\n");
}

static void test_strrchr(void) {
    assert(rt_strrchr("hello", 'l') == "hello" + 3);
    assert(rt_strrchr("hello", 'z') == NULL);
    printf("  PASS: test_strrchr\n");
}

static void test_strcpy_strcat(void) {
    char buf[64];
    rt_strcpy(buf, "hello");
    assert(strcmp(buf, "hello") == 0);
    rt_strcat(buf, " world");
    assert(strcmp(buf, "hello world") == 0);
    printf("  PASS: test_strcpy_strcat\n");
}

static void test_strlcpy(void) {
    char buf[10];
    size_t n = rt_strlcpy(buf, "hello", sizeof(buf));
    assert(strcmp(buf, "hello") == 0);
    assert(n == 5);
    n = rt_strlcpy(buf, "hello world long", 6);
    assert(n == 16);
    assert(strlen(buf) == 5);
    printf("  PASS: test_strlcpy\n");
}

static void test_wcslen(void) {
    unsigned short ws[] = { 'h','e','l','l','o', 0 };
    assert(wcslen(ws) == 5);
    unsigned short ws2[] = { 0 };
    assert(wcslen(ws2) == 0);
    printf("  PASS: test_wcslen\n");
}

static void test_wcsicmp(void) {
    unsigned short a[] = { 'H','e','l','l','o', 0 };
    unsigned short b[] = { 'h','E','L','L','O', 0 };
    unsigned short c[] = { 'W','o','r','l','d', 0 };
    assert(_wcsicmp(a, b) == 0);
    assert(_wcsicmp(a, c) != 0);
    printf("  PASS: test_wcsicmp\n");
}

static void test_wcsnicmp(void) {
    unsigned short a[] = { 'H','e','l','l','o', 0 };
    unsigned short b[] = { 'h','E','L','X','X', 0 };
    assert(_wcsnicmp(a, b, 3) == 0);
    assert(_wcsnicmp(a, b, 4) != 0);
    printf("  PASS: test_wcsnicmp\n");
}

static void test_snprintf_basic(void) {
    char buf[64];
    int n = rt_snprintf(buf, sizeof(buf), "hello %s %d", "world", 42);
    assert(n > 0);
    assert(strcmp(buf, "hello world 42") == 0);
    printf("  PASS: test_snprintf_basic\n");
}

static void test_snprintf_truncation(void) {
    char buf[8];
    rt_snprintf(buf, sizeof(buf), "hello world %d", 42);
    assert(strlen(buf) <= 7);
    printf("  PASS: test_snprintf_truncation\n");
}

static void test_snprintf_hex(void) {
    char buf[32];
    rt_snprintf(buf, sizeof(buf), "%08x", 0xDEADBEEF);
    assert(strcmp(buf, "deadbeef") == 0);
    printf("  PASS: test_snprintf_hex\n");
}

static void test_snprintf_negative(void) {
    char buf[32];
    rt_snprintf(buf, sizeof(buf), "%d", -42);
    assert(strcmp(buf, "-42") == 0);
    printf("  PASS: test_snprintf_negative\n");
}

int main(void) {
    printf("=== test_rt_str: runtime string functions ===\n");
    test_strlen();
    test_strcmp();
    test_strstr();
    test_strchr();
    test_strrchr();
    test_strcpy_strcat();
    test_strlcpy();
    test_wcslen();
    test_wcsicmp();
    test_wcsnicmp();
    test_snprintf_basic();
    test_snprintf_truncation();
    test_snprintf_hex();
    test_snprintf_negative();
    printf("=== test_rt_str: ALL PASSED ===\n");
    return 0;
}
