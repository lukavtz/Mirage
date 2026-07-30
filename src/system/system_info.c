#include "system_info.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>

/* Get OS version string */
int mirage_get_os_version(char *buf, size_t buflen) {
    OSVERSIONINFOW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    
    typedef LONG (WINAPI *RtlGetVersion_fn)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return -1;
    
    RtlGetVersion_fn RtlGetVersion = (RtlGetVersion_fn)GetProcAddress(ntdll, "RtlGetVersion");
    if (!RtlGetVersion) return -1;
    
    if (RtlGetVersion(&vi) != 0) return -1;
    
    snprintf(buf, buflen, "Windows %lu.%lu (Build %lu)",
             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return 0;
}

/* Get computer name */
int mirage_get_computer_name(char *buf, size_t buflen) {
    DWORD size = (DWORD)buflen;
    if (!GetComputerNameW((LPWSTR)buf, &size)) return -1;
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
