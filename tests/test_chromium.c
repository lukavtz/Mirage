/*
 * test_chromium.c — Browser path enumeration tests
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "browser_paths.h"
void* getPeb(void) { return NULL; }


static void test_chromium_table(void) {
    size_t count = 0;
    const BrowserPath *b = get_chromium_browsers(&count);
    assert(b != NULL);
    assert(count >= 50);
    /* First entry should be Chrome */
    assert(b[0].name != NULL);
    assert(strlen(b[0].name) > 0);
    /* All entries should have names */
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
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            assert(strcmp(b[i].name, b[j].name) != 0);
        }
    }
    printf("  PASS: chromium names unique\n");
}

static void test_gecko_unique_names(void) {
    size_t count = 0;
    const BrowserPath *b = get_gecko_browsers(&count);
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            assert(strcmp(b[i].name, b[j].name) != 0);
        }
    }
    printf("  PASS: gecko names unique\n");
}

static void test_fs_discover_chromium(void) {
    BrowserPath out[64];
    size_t count = 0;
    int rc = discover_chromium_browsers_fs(out, 64, &count);
    if (rc == 0 && count > 0) {
        for (size_t i = 0; i < count; i++) {
            assert(out[i].name != NULL);
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
        printf("  PASS: Registry chromium found %zu\n", count);
    } else {
        printf("  SKIP: Registry chromium (rc=%d)\n", rc);
    }
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

int main(void) {
    printf("=== test_chromium ===\n");
    test_chromium_table();
    test_gecko_table();
    test_chromium_unique_names();
    test_gecko_unique_names();
    test_fs_discover_chromium();
    test_fs_discover_gecko();
    test_registry_discover();
    test_kill_null();
    test_kill_nonexistent();
    printf("=== test_chromium: ALL PASSED ===\n");
    return 0;
}
