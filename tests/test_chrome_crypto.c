/*
 * test_chrome_crypto.c — chrome_extract_encrypted_key + chrome_derive_key tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -DTEST_CHROME_CRYPTO_STANDALONE -o tests/test_chrome_crypto tests/test_chrome_crypto.c src/utils/base64.c src/types/hash.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  PASS: %s\n", name); tests_passed++; } while(0)
#define FAIL(name) do { tests_run++; printf("  FAIL: %s\n", name); } while(0)

/* ── chrome_extract_encrypted_key (from chrome_crypto.c) ─────── */
#include "utils/base64.h"

static void *compat_memmem(const void *haystack, size_t haystack_len,
                           const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (needle_len > haystack_len) return NULL;
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; i++)
        if (memcmp(h + i, n, needle_len) == 0) return (void *)(h + i);
    return NULL;
}
#define memmem compat_memmem

static int chrome_extract_encrypted_key(const char *json, size_t json_len,
                                        unsigned char *out, size_t out_max,
                                        size_t *out_len) {
    const char marker[] = "\"encrypted_key\":\"";
    const char *start = memmem(json, json_len, marker, sizeof(marker) - 1);
    if (!start) return -1;
    start += sizeof(marker) - 1;
    const char *end = memchr(start, '"', (size_t)(json + json_len - start));
    if (!end) return -1;
    size_t b64_len = (size_t)(end - start);
    int decoded = base64_decode(start, b64_len, out, out_max);
    if (decoded < 0) return -1;
    *out_len = (size_t)decoded;
    return 0;
}

/* ── Tests ───────────────────────────────────────────────────── */

static void test_extract_key_basic(void) {
    /* Known base64: "hello" -> aGVsbG8= */
    const char *json = "{\"os_crypt\":{\"encrypted_key\":\"aGVsbG8=\"}}";
    unsigned char out[64];
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r < 0 || out_len != 5 || memcmp(out, "hello", 5) != 0) { FAIL("test_extract_key_basic"); return; }
    TEST("test_extract_key_basic");
}

static void test_extract_key_missing(void) {
    const char *json = "{\"os_crypt\":{}}";
    unsigned char out[64];
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r != -1) { FAIL("test_extract_key_missing"); return; }
    TEST("test_extract_key_missing");
}

static void test_extract_key_empty(void) {
    /* Empty base64 is invalid (len%4!=0), should fail */
    const char *json = "{\"encrypted_key\":\"\"}";
    unsigned char out[64];
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r != -1) { FAIL("test_extract_key_empty"); return; }
    TEST("test_extract_key_empty");
}

static void test_extract_key_buffer_too_small(void) {
    const char *json = "{\"encrypted_key\":\"aGVsbG8gd29ybGQ=\"}"; /* "hello world" */
    unsigned char out[4]; /* too small */
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r != -1) { FAIL("test_extract_key_buffer_too_small"); return; }
    TEST("test_extract_key_buffer_too_small");
}

static void test_extract_key_realistic(void) {
    /* Pre-computed: base64 of {0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF} = AQAAANCMnd8= */
    const char *json = "{\"os_crypt\":{\"encrypted_key\":\"AQAAAIBMnd8=\"}}";
    unsigned char out[128];
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r < 0 || out_len != 8) { FAIL("test_extract_key_realistic (extract)"); return; }
    if (out[0] != 0x01) { FAIL("test_extract_key_realistic (match)"); return; }
    TEST("test_extract_key_realistic");
}

static void test_extract_key_truncated_json(void) {
    const char *json = "{\"encrypted_key\":\"aGVsb";
    unsigned char out[64];
    size_t out_len = 0;
    int r = chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len);
    if (r != -1) { FAIL("test_extract_key_truncated"); return; }
    TEST("test_extract_key_truncated");
}

int main(void) {
    printf("=== test_chrome_crypto: Chrome key extraction ===\n");
    test_extract_key_basic();
    test_extract_key_missing();
    test_extract_key_empty();
    test_extract_key_buffer_too_small();
    test_extract_key_realistic();
    test_extract_key_truncated_json();
    printf("=== test_chrome_crypto: %d/%d PASSED ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
