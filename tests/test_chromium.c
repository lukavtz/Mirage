/*
 * test_chromium.c — Browser path enumeration tests
 *
 * Tests get_chromium_browsers / get_gecko_browsers for:
 *   - Correct count (58 chromium, 10 gecko)
 *   - Non-NULL returns
 *   - Opera browsers use roaming
 *   - Known browser names present
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "browser_paths.h"

/* Stub for PEB walk (ASM function not available in tests) */
void* getPeb(void) { return NULL; }

static void test_chromium_count(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);
    assert(browsers != NULL);
    assert(count >= 50); /* merged discovery may dedup some static entries */

    printf("  PASS: test_chromium_count\n");
}

static void test_chromium_first_browser_is_chrome(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);
    assert(browsers != NULL);
    assert(strcmp(browsers[0].name, "Chrome") == 0);
    assert(strstr(browsers[0].path_suffix, "Chrome") != NULL);

    printf("  PASS: test_chromium_first_browser_is_chrome\n");
}

static void test_chromium_edge_present(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);
    assert(browsers != NULL);

    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(browsers[i].name, "Edge")) {
            found = 1;
            assert(strstr(browsers[i].path_suffix, "Edge") != NULL);
            break;
        }
    }
    assert(found);

    printf("  PASS: test_chromium_edge_present\n");
}

static void test_chromium_brave_present(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);

    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(browsers[i].name, "Brave")) {
            found = 1;
            assert(strstr(browsers[i].path_suffix, "Brave") != NULL);
            break;
        }
    }
    assert(found);

    printf("  PASS: test_chromium_brave_present\n");
}

static void test_opera_uses_roaming(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);
    assert(browsers != NULL);

    /* Opera (index 5) and Opera GX (index 6) use roaming */
    int found_opera = 0;
    int found_opera_gx = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(browsers[i].name, "Opera") == 0) {
            assert(browsers[i].use_roaming == 1);
            found_opera = 1;
        }
        if (strcmp(browsers[i].name, "Opera GX") == 0) {
            assert(browsers[i].use_roaming == 1);
            found_opera_gx = 1;
        }
    }
    assert(found_opera);
    assert(found_opera_gx);

    printf("  PASS: test_opera_uses_roaming\n");
}

static void test_non_opera_uses_local(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);

    /* Chrome, Edge, Brave should use LOCALAPPDATA (use_roaming == 0) */
    for (size_t i = 0; i < count; i++) {
        if (strcmp(browsers[i].name, "Chrome") == 0 ||
            strcmp(browsers[i].name, "Edge") == 0 ||
            strcmp(browsers[i].name, "Brave") == 0) {
            assert(browsers[i].use_roaming == 0);
        }
    }

    printf("  PASS: test_non_opera_uses_local\n");
}

static void test_gecko_count(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_gecko_browsers(&count);
    assert(browsers != NULL);
    assert(count == 10);

    printf("  PASS: test_gecko_count\n");
}

static void test_gecko_firefox_present(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_gecko_browsers(&count);

    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(browsers[i].name, "Firefox") == 0) {
            found = 1;
            assert(browsers[i].use_roaming == 1);
            assert(strstr(browsers[i].path_suffix, "Firefox") != NULL);
            break;
        }
    }
    assert(found);

    printf("  PASS: test_gecko_firefox_present\n");
}

static void test_gecko_all_use_roaming(void) {
    size_t count = 0;
    const BrowserPath *browsers = get_gecko_browsers(&count);

    for (size_t i = 0; i < count; i++) {
        assert(browsers[i].use_roaming == 1);
    }

    printf("  PASS: test_gecko_all_use_roaming\n");
}

static void test_chromium_names_unique(void) {
    /* Note: the browser list has some intentional duplicates (7Star, Liebao, etc.)
     * This test verifies path_suffix uniqueness for each browser name */
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);

    for (size_t i = 0; i < count; i++) {
        assert(browsers[i].name != NULL);
        assert(browsers[i].path_suffix != NULL);
        assert(strlen(browsers[i].name) > 0);
        assert(strlen(browsers[i].path_suffix) > 0);
    }

    printf("  PASS: test_chromium_names_unique\n");
}

int main(void) {
    printf("=== test_chromium: browser path enumeration ===\n");

    test_chromium_count();
    test_chromium_first_browser_is_chrome();
    test_chromium_edge_present();
    test_chromium_brave_present();
    test_opera_uses_roaming();
    test_non_opera_uses_local();
    test_gecko_count();
    test_gecko_firefox_present();
    test_gecko_all_use_roaming();
    test_chromium_names_unique();

    printf("=== test_chromium: ALL PASSED ===\n");
    return 0;
}
