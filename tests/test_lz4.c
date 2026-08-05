/*
 * test_lz4.c - LZ4 block format roundtrip tests
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lz4.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  PASS: %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name) do { tests_run++; printf("  FAIL: %s\n", name); } while(0)

static void test_roundtrip_literal(void) {
    const char *src = "Hello, World! This is a test of LZ4 compression.";
    int src_len = (int)strlen(src);
    char comp[256]; char decomp[256];
    int comp_len = lz4_compress(src, comp, src_len, sizeof(comp));
    if (comp_len <= 0) { TEST_FAIL("test_roundtrip_literal (compress)"); return; }
    int decomp_len = lz4_decompress_safe(comp, decomp, comp_len, sizeof(decomp));
    if (decomp_len != src_len || memcmp(decomp, src, src_len) != 0) { TEST_FAIL("test_roundtrip_literal (mismatch)"); return; }
    TEST("test_roundtrip_literal");
}

static void test_roundtrip_repeated(void) {
    char src[1024]; memset(src, 'A', sizeof(src));
    char comp[1024]; char decomp[1024];
    int comp_len = lz4_compress(src, comp, sizeof(src), sizeof(comp));
    if (comp_len <= 0) { TEST_FAIL("test_roundtrip_repeated (compress)"); return; }
    if (comp_len >= (int)sizeof(src) / 2) { TEST_FAIL("test_roundtrip_repeated (ratio)"); return; }
    int decomp_len = lz4_decompress_safe(comp, decomp, comp_len, sizeof(decomp));
    if (decomp_len != (int)sizeof(src) || memcmp(decomp, src, sizeof(src)) != 0) { TEST_FAIL("test_roundtrip_repeated (mismatch)"); return; }
    TEST("test_roundtrip_repeated");
}

static void test_roundtrip_random(void) {
    unsigned char src[256]; int i; unsigned int seed = 0x12345678;
    for (i = 0; i < 256; i++) { seed = seed * 1103515245 + 12345; src[i] = (unsigned char)(seed >> 16); }
    char comp[512]; char decomp[512];
    int comp_len = lz4_compress((const char *)src, comp, 256, sizeof(comp));
    if (comp_len <= 0) { TEST_FAIL("test_roundtrip_random (compress)"); return; }
    int decomp_len = lz4_decompress_safe(comp, decomp, comp_len, sizeof(decomp));
    if (decomp_len != 256 || memcmp(decomp, src, 256) != 0) { TEST_FAIL("test_roundtrip_random (mismatch)"); return; }
    TEST("test_roundtrip_random");
}

static void test_empty(void) {
    if (lz4_compress_bound(0) != 0) { TEST_FAIL("test_empty"); return; }
    TEST("test_empty");
}

static void test_single_byte(void) {
    char src[1] = {'X'}; char comp[32]; char decomp[32];
    int comp_len = lz4_compress(src, comp, 1, sizeof(comp));
    if (comp_len <= 0) { TEST_FAIL("test_single_byte (compress)"); return; }
    int decomp_len = lz4_decompress_safe(comp, decomp, comp_len, sizeof(decomp));
    if (decomp_len != 1 || decomp[0] != 'X') { TEST_FAIL("test_single_byte (mismatch)"); return; }
    TEST("test_single_byte");
}

static void test_large_data(void) {
    int src_size = 65536;
    char *src = (char *)malloc(src_size);
    char *comp = (char *)malloc(lz4_compress_bound(src_size));
    char *decomp = (char *)malloc(src_size);
    if (!src || !comp || !decomp) { free(src); free(comp); free(decomp); TEST_FAIL("test_large_data (malloc)"); return; }
    int i;
    for (i = 0; i < src_size; i++) src[i] = (char)(i % 26 + 'A');
    int comp_len = lz4_compress(src, comp, src_size, lz4_compress_bound(src_size));
    if (comp_len <= 0) { TEST_FAIL("test_large_data (compress)"); free(src); free(comp); free(decomp); return; }
    int decomp_len = lz4_decompress_safe(comp, decomp, comp_len, src_size);
    if (decomp_len != src_size || memcmp(decomp, src, src_size) != 0) { TEST_FAIL("test_large_data (mismatch)"); free(src); free(comp); free(decomp); return; }
    TEST("test_large_data");
    free(src); free(comp); free(decomp);
}

static void test_compress_bound(void) {
    int sizes[] = {1, 16, 255, 256, 1024, 65536}; int i;
    for (i = 0; i < 6; i++) { if (lz4_compress_bound(sizes[i]) < sizes[i]) { TEST_FAIL("test_compress_bound"); return; } }
    TEST("test_compress_bound");
}

int main(void) {
    printf("=== test_lz4: LZ4 compression roundtrip ===\n");
    test_roundtrip_literal();
    test_roundtrip_repeated();
    test_roundtrip_random();
    test_empty();
    test_single_byte();
    test_large_data();
    test_compress_bound();
    printf("=== test_lz4: %d/%d PASSED ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
