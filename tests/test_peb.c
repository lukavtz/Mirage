/*
 * test_peb.c — PEB walk and module resolution tests
 *
 * Uses ZIALFI_TEST_MODE for mock API + synthetic PEB structures
 * to exercise the real PEB walk code path.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "config.h"
#include "hash.h"
#include "peb.h"

/* ── Synthetic PEB for testing the walk code ─────────────── */

static PEB             g_fake_peb;
static PEB_LDR_DATA    g_fake_ldr;
static LDR_DATA_TABLE_ENTRY g_fake_entry;
static WCHAR           g_name_buf[64];

/* getPeb returns our synthetic PEB or NULL depending on mode */
static int g_use_real_peb = 0;

void *getPeb(void) {
    return g_use_real_peb ? (void *)&g_fake_peb : NULL;
}

static void setup_fake_module(const char *name, void *base) {
    /* Convert name to wide string */
    size_t len = strlen(name);
    for (size_t i = 0; i <= len; i++)
        g_name_buf[i] = (WCHAR)name[i];

    memset(&g_fake_peb, 0, sizeof(g_fake_peb));
    memset(&g_fake_ldr, 0, sizeof(g_fake_ldr));
    memset(&g_fake_entry, 0, sizeof(g_fake_entry));

    /* PEB -> LDR */
    g_fake_peb.Ldr = &g_fake_ldr;

    /* LDR InMemoryOrderModuleList -> entry (single-element circular list) */
    g_fake_ldr.InMemoryOrderModuleList.Flink = &g_fake_entry.InMemoryOrderLinks;
    g_fake_ldr.InMemoryOrderModuleList.Blink = &g_fake_entry.InMemoryOrderLinks;

    /* Entry links back to list head */
    g_fake_entry.InMemoryOrderLinks.Flink = &g_fake_ldr.InMemoryOrderModuleList;
    g_fake_entry.InMemoryOrderLinks.Blink = &g_fake_ldr.InMemoryOrderModuleList;

    /* Entry module info */
    g_fake_entry.DllBase = base;
    g_fake_entry.BaseDllName.Buffer = g_name_buf;
    g_fake_entry.BaseDllName.Length = (USHORT)(len * 2);
    g_fake_entry.BaseDllName.MaximumLength = (USHORT)((len + 1) * 2);

    g_use_real_peb = 1;
}

/* ── Hash pipeline tests ─────────────────────────────────── */

static void test_hash_deterministic(void) {
    assert(mirage_encrypted_hash_module("ntdll.dll")
        == mirage_encrypted_hash_module("ntdll.dll"));
    printf("  PASS: hash_deterministic\n");
}

static void test_hash_case_insensitive(void) {
    const uint8_t lo[] = "ntdll.dll";
    const uint8_t up[] = "NTDLL.DLL";
    assert(mirage_hash_string(lo, 9, 28) == mirage_hash_string(up, 9, 28));
    printf("  PASS: hash_case_insensitive\n");
}

static void test_hash_different_modules(void) {
    uint32_t h1 = mirage_encrypted_hash_module("ntdll.dll");
    uint32_t h2 = mirage_encrypted_hash_module("kernel32.dll");
    uint32_t h3 = mirage_encrypted_hash_module("user32.dll");
    assert(h1 != h2 && h2 != h3 && h1 != h3);
    printf("  PASS: hash_different_modules\n");
}

static void test_hash_nonzero(void) {
    assert(mirage_encrypted_hash_module("ntdll.dll") != 0);
    printf("  PASS: hash_nonzero\n");
}

static void test_hash_empty(void) {
    assert(mirage_encrypted_hash_module("") == MIRAGE_SEED);
    printf("  PASS: hash_empty\n");
}

static void test_xor_roundtrip(void) {
    const uint8_t in[] = "test data";
    uint8_t enc[32], dec[32];
    mirage_xor_encrypt(in, enc, 9);
    assert(memcmp(in, enc, 9) != 0);
    mirage_xor_decrypt(enc, dec, 9);
    assert(memcmp(in, dec, 9) == 0);
    printf("  PASS: xor_roundtrip\n");
}

static void test_hash_iteration_diff(void) {
    const uint8_t s[] = "test";
    assert(mirage_hash_string(s, 4, 1) != mirage_hash_string(s, 4, 28));
    printf("  PASS: hash_iteration_diff\n");
}

/* ── Mock PEB tests (ZIALFI_TEST_MODE) ──────────────────── */

static void test_mock_register_and_find(void) {
    g_use_real_peb = 0; /* use NULL PEB, so mock path is used */
    mirage_peb_mock_clear();
    void *base = (void *)(uintptr_t)0x10000000;
    uint32_t h = mirage_encrypted_hash_module("kernel32.dll");
    mirage_peb_mock_module(h, base);
    assert(mirage_get_module_by_hash(h) == base);
    printf("  PASS: mock_register_and_find\n");
}

static void test_mock_not_found(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();
    assert(mirage_get_module_by_hash(
        mirage_encrypted_hash_module("nonexistent.dll")) == NULL);
    printf("  PASS: mock_not_found\n");
}

static void test_mock_clear(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_module(
        mirage_encrypted_hash_module("test.dll"),
        (void *)(uintptr_t)0x20000000);
    mirage_peb_mock_clear();
    assert(mirage_get_module_by_hash(
        mirage_encrypted_hash_module("test.dll")) == NULL);
    printf("  PASS: mock_clear\n");
}

static void test_mock_multiple(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();
    void *b1 = (void *)(uintptr_t)0x70000000;
    void *b2 = (void *)(uintptr_t)0x71000000;
    void *b3 = (void *)(uintptr_t)0x72000000;
    uint32_t h1 = mirage_encrypted_hash_module("ntdll.dll");
    uint32_t h2 = mirage_encrypted_hash_module("kernel32.dll");
    uint32_t h3 = mirage_encrypted_hash_module("user32.dll");
    mirage_peb_mock_module(h1, b1);
    mirage_peb_mock_module(h2, b2);
    mirage_peb_mock_module(h3, b3);
    assert(mirage_get_module_by_hash(h1) == b1);
    assert(mirage_get_module_by_hash(h2) == b2);
    assert(mirage_get_module_by_hash(h3) == b3);
    printf("  PASS: mock_multiple\n");
}

static void test_mock_overflow(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();
    for (int i = 0; i < 40; i++) {
        char name[32];
        sprintf(name, "mod_%d.dll", i);
        mirage_peb_mock_module(
            mirage_encrypted_hash_module(name),
            (void *)(uintptr_t)(0x30000000 + i * 0x1000));
    }
    assert(mirage_get_module_by_hash(mirage_encrypted_hash_module("mod_0.dll"))
        == (void *)(uintptr_t)0x30000000);
    assert(mirage_get_module_by_hash(
        mirage_encrypted_hash_module("mod_31.dll")) != NULL);
    assert(mirage_get_module_by_hash(
        mirage_encrypted_hash_module("mod_32.dll")) == NULL);
    printf("  PASS: mock_overflow\n");
}

static void test_get_module_no_mock_null_peb(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();
    assert(mirage_get_module_by_hash(0x12345678) == NULL);
    printf("  PASS: get_module_no_mock_null_peb\n");
}

/* ── Synthetic PEB walk tests ────────────────────────────── */

static void test_peb_walk_find_module(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();

    void *base = (void *)(uintptr_t)0xDEAD0000;
    setup_fake_module("test_mod.dll", base);

    uint32_t h = mirage_encrypted_hash_module("test_mod.dll");
    void *found = mirage_get_module_by_hash(h);
    assert(found == base);
    printf("  PASS: peb_walk_find_module\n");
}

static void test_peb_walk_second_module(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();

    void *base = (void *)(uintptr_t)0xCAFE0000;
    setup_fake_module("kernel32.dll", base);

    /* Compute hash with uppercase */
    uint32_t h = mirage_encrypted_hash_module("kernel32.dll");
    void *found = mirage_get_module_by_hash(h);
    assert(found == base);
    printf("  PASS: peb_walk_second_module\n");
}

static void test_peb_walk_not_found(void) {
    g_use_real_peb = 0;
    mirage_peb_mock_clear();

    setup_fake_module("kernel32.dll", (void *)(uintptr_t)0x12340000);

    uint32_t h = mirage_encrypted_hash_module("user32.dll");
    void *found = mirage_get_module_by_hash(h);
    assert(found == NULL);
    printf("  PASS: peb_walk_not_found\n");
}

static void test_peb_null_ldr(void) {
    memset(&g_fake_peb, 0, sizeof(g_fake_peb));
    g_fake_peb.Ldr = NULL;
    g_use_real_peb = 1;
    mirage_peb_mock_clear();

    assert(mirage_get_module_by_hash(0x12345678) == NULL);
    printf("  PASS: peb_null_ldr\n");
}

/* ── main ────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_peb ===\n");
    test_hash_deterministic();
    test_hash_case_insensitive();
    test_hash_different_modules();
    test_hash_nonzero();
    test_hash_empty();
    test_xor_roundtrip();
    test_hash_iteration_diff();
    test_mock_register_and_find();
    test_mock_not_found();
    test_mock_clear();
    test_mock_multiple();
    test_mock_overflow();
    test_get_module_no_mock_null_peb();
    test_peb_walk_find_module();
    test_peb_walk_second_module();
    test_peb_walk_not_found();
    test_peb_null_ldr();
    printf("=== test_peb: ALL PASSED ===\n");
    return 0;
}
