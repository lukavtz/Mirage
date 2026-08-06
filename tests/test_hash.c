/*
 * test_hash.c — Comprehensive tests for hash.c
 *
 * Covers: mirage_hash_string, mirage_hash_string_exact,
 *         mirage_xor_encrypt/decrypt, mirage_encrypted_hash_module,
 *         mirage_encrypted_hash_func, edge cases.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "hash.h"
#include "config.h"

/* ── hash_string: case-insensitive ───────────────────────── */

static void test_hash_string_consistency(void) {
    const uint8_t s[] = "test";
    assert(mirage_hash_string(s, 4, 28) == mirage_hash_string(s, 4, 28));
    printf("  PASS: hash_string consistency\n");
}

static void test_hash_string_case_insensitive(void) {
    const uint8_t lo[] = "kernel32.dll";
    const uint8_t up[] = "KERNEL32.DLL";
    assert(mirage_hash_string(lo, 12, 28) == mirage_hash_string(up, 12, 28));
    printf("  PASS: hash_string case insensitive\n");
}

static void test_hash_string_different(void) {
    assert(mirage_hash_string((const uint8_t*)"ntdll.dll", 9, 28)
        != mirage_hash_string((const uint8_t*)"kernel32.dll", 12, 28));
    printf("  PASS: hash_string different\n");
}

static void test_hash_string_empty(void) {
    assert(mirage_hash_string((const uint8_t*)"", 0, 28) == MIRAGE_SEED);
    printf("  PASS: hash_string empty\n");
}

static void test_hash_string_single_char(void) {
    uint32_t ha = mirage_hash_string((const uint8_t*)"a", 1, 28);
    uint32_t hb = mirage_hash_string((const uint8_t*)"b", 1, 28);
    assert(ha != hb);
    assert(ha != MIRAGE_SEED);
    printf("  PASS: hash_string single char\n");
}

static void test_hash_string_iterations(void) {
    const uint8_t s[] = "test";
    assert(mirage_hash_string(s, 4, 1) != mirage_hash_string(s, 4, 28));
    printf("  PASS: hash_string iterations\n");
}

/* ── hash_string_exact: case-sensitive ───────────────────── */

static void test_hash_string_exact_case_sensitive(void) {
    assert(mirage_hash_string_exact((const uint8_t*)"GetProc", 7, 27)
        != mirage_hash_string_exact((const uint8_t*)"GETPROC", 7, 27));
    printf("  PASS: hash_string_exact case sensitive\n");
}

static void test_hash_string_exact_consistency(void) {
    const uint8_t s[] = "GetProcAddress";
    assert(mirage_hash_string_exact(s, 14, 27)
        == mirage_hash_string_exact(s, 14, 27));
    printf("  PASS: hash_string_exact consistency\n");
}

static void test_hash_string_exact_empty(void) {
    assert(mirage_hash_string_exact((const uint8_t*)"", 0, 27) == MIRAGE_SEED);
    printf("  PASS: hash_string_exact empty\n");
}

/* ── XOR encrypt/decrypt ─────────────────────────────────── */

static void test_xor_roundtrip(void) {
    const uint8_t in[] = "Hello, World!";
    size_t len = 13;
    uint8_t enc[64], dec[64];
    mirage_xor_encrypt(in, enc, len);
    assert(memcmp(in, enc, len) != 0);
    mirage_xor_decrypt(enc, dec, len);
    assert(memcmp(in, dec, len) == 0);
    printf("  PASS: xor roundtrip\n");
}

static void test_xor_symmetric(void) {
    const uint8_t data[] = "test data 1234567890";
    size_t len = 20;
    uint8_t buf1[64], buf2[64];
    mirage_xor_encrypt(data, buf1, len);
    mirage_xor_decrypt(data, buf2, len);
    assert(memcmp(buf1, buf2, len) == 0);
    printf("  PASS: xor symmetric\n");
}

static void test_xor_empty(void) {
    uint8_t out[1];
    mirage_xor_encrypt((const uint8_t*)"", out, 0);
    mirage_xor_decrypt((const uint8_t*)"", out, 0);
    printf("  PASS: xor empty\n");
}

/* ── encrypted_hash_module ───────────────────────────────── */

static void test_encrypted_hash_module_deterministic(void) {
    assert(mirage_encrypted_hash_module("kernel32.dll")
        == mirage_encrypted_hash_module("kernel32.dll"));
    printf("  PASS: encrypted_hash_module deterministic\n");
}

static void test_encrypted_hash_module_different(void) {
    uint32_t h1 = mirage_encrypted_hash_module("ntdll.dll");
    uint32_t h2 = mirage_encrypted_hash_module("kernel32.dll");
    uint32_t h3 = mirage_encrypted_hash_module("user32.dll");
    assert(h1 != h2 && h2 != h3 && h1 != h3);
    printf("  PASS: encrypted_hash_module different\n");
}

static void test_encrypted_hash_module_nonzero(void) {
    assert(mirage_encrypted_hash_module("ntdll.dll") != 0);
    printf("  PASS: encrypted_hash_module nonzero\n");
}

/* ── encrypted_hash_func ─────────────────────────────────── */

static void test_encrypted_hash_func_deterministic(void) {
    assert(mirage_encrypted_hash_func("GetProcAddress")
        == mirage_encrypted_hash_func("GetProcAddress"));
    printf("  PASS: encrypted_hash_func deterministic\n");
}

static void test_encrypted_hash_func_different(void) {
    assert(mirage_encrypted_hash_func("GetProcAddress")
        != mirage_encrypted_hash_func("LoadLibraryA"));
    printf("  PASS: encrypted_hash_func different\n");
}

static void test_encrypted_hash_func_case_sensitive(void) {
    assert(mirage_encrypted_hash_func("GetProcAddress")
        != mirage_encrypted_hash_func("GETPROCADDRESS"));
    printf("  PASS: encrypted_hash_func case sensitive\n");
}

static void test_encrypted_hash_func_nonzero(void) {
    assert(mirage_encrypted_hash_func("GetProcAddress") != 0);
    printf("  PASS: encrypted_hash_func nonzero\n");
}

static void test_module_vs_func_hash(void) {
    /* Same plaintext -> different hash (28 iters+casefold vs 27+exact) */
    assert(mirage_encrypted_hash_module("ntdll.dll")
        != mirage_encrypted_hash_func("ntdll.dll"));
    printf("  PASS: module vs func hash different\n");
}

/* ── config ──────────────────────────────────────────────── */

static void test_config(void) {
    assert(MIRAGE_SEED != 0);
    assert(MIRAGE_SSN_XOR_KEY != 0);
    printf("  PASS: config\n");
}

/* ── main ────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_hash ===\n");
    test_hash_string_consistency();
    test_hash_string_case_insensitive();
    test_hash_string_different();
    test_hash_string_empty();
    test_hash_string_single_char();
    test_hash_string_iterations();
    test_hash_string_exact_case_sensitive();
    test_hash_string_exact_consistency();
    test_hash_string_exact_empty();
    test_xor_roundtrip();
    test_xor_symmetric();
    test_xor_empty();
    test_encrypted_hash_module_deterministic();
    test_encrypted_hash_module_different();
    test_encrypted_hash_module_nonzero();
    test_encrypted_hash_func_deterministic();
    test_encrypted_hash_func_different();
    test_encrypted_hash_func_case_sensitive();
    test_encrypted_hash_func_nonzero();
    test_module_vs_func_hash();
    test_config();
    printf("=== test_hash: ALL PASSED ===\n");
    return 0;
}
