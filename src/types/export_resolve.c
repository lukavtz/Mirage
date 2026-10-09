/*
 * export_resolve.c — PE export table resolver for Mirage-C
 *
 * Exact translation of Zig src/types/export_resolve.zig
 *
 * Two operations:
 * 1. initNativeResolver — find LdrGetProcedureAddress in ntdll
 * 2. getFunctionByHash — resolve any function by name hash
 *
 * Hash pipeline for export names:
 *   XOR each byte with STRING_KEY_ENC[i % 16]
 *   Hash with rotl32(5) XOR mul, 27 iterations (exact case)
 */

#include <windows.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "config.h"
#include <string.h>
#include <stddef.h>
#include "enc_strings.h"

/* ── Inline helpers for encrypted PEB-walk resolution ──────── */
static inline void *resolve_fn_enc(void *mod, const uint8_t *enc, size_t len) {
    char buf[32]; enc_decrypt(enc, len, buf);
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(buf));
}


/* ── Rotl32 ───────────────────────────────────────────────── */
static inline uint32_t rotl32(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

/* ── Cached LdrGetProcedureAddress pointer ─────────────────── */
typedef NTSTATUS (*LdrGetProcedureAddressFn)(
    PVOID BaseAddress,
    const char* Name,
    ULONG NameLength,  /* 0 = ordinal lookup */
    PVOID* ProcedureAddress
);

static LdrGetProcedureAddressFn g_ldr_get_procedure_address = NULL;

/* ── Internal: walk export table by hash ───────────────────── */
static void* walk_exports(void* module_base, uint32_t target_hash)
{
    uint8_t* base_bytes = (uint8_t*)module_base;

    /* Validate DOS header */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    /* Navigate to NT headers */
    uint32_t nt_offset = (uint32_t)dos->e_lfanew;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base_bytes + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    /* Export directory (DataDirectory[0]) */
    DWORD export_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (export_rva == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY export_dir =
        (PIMAGE_EXPORT_DIRECTORY)(base_bytes + export_rva);

    DWORD names_rva  = export_dir->AddressOfNames;
    DWORD funcs_rva  = export_dir->AddressOfFunctions;
    DWORD ords_rva   = export_dir->AddressOfNameOrdinals;

    if (names_rva == 0 || funcs_rva == 0 || ords_rva == 0)
        return NULL;

    uint32_t num_names = export_dir->NumberOfNames;
    uint32_t* names    = (uint32_t*)(base_bytes + names_rva);
    uint32_t* funcs    = (uint32_t*)(base_bytes + funcs_rva);
    uint16_t* ords     = (uint16_t*)(base_bytes + ords_rva);

    /* Iterate export names, compute hash, compare */
    for (uint32_t i = 0; i < num_names; i++) {
        const uint8_t* name_ptr = base_bytes + names[i];

        /* Find name length (null-terminated) */
        size_t name_len = 0;
        while (name_ptr[name_len] != 0)
            name_len++;

        /* XOR + hash: exact case, 27 iterations */
        uint32_t h = MIRAGE_SEED;
        for (size_t j = 0; j < name_len; j++) {
            uint8_t c = name_ptr[j];
            c ^= MIRAGE_STRING_KEY_ENC[j % 16];

            for (uint32_t k = 0; k < 27; k++) {
                h = rotl32(h, 5);
                h ^= c;
                h = h * 0x1B873593u + 0x85EBCA6Bu;
            }
        }

        if (h == target_hash) {
            uint16_t ordinal = ords[i];
            uint32_t func_rva = funcs[ordinal];

            /* Forwarded export (e.g. advapi32!SystemFunction036 →
             * CRYPTBASE.SystemFunction036): the RVA points into the
             * export directory at a "DllName.FuncName" string, not at
             * executable code. Calling such an address crashes. Resolve
             * the forwarder target by PEB-walking the target DLL. */
            if (func_rva >= export_rva &&
                func_rva <  export_rva +
                            nt->OptionalHeader.DataDirectory[0].Size) {
                const char *fwd = (const char*)(base_bytes + func_rva);
                const char *dot = fwd;
                while (*dot && *dot != '.') dot++;
                if (*dot == '.') {
                    char dll_name[64];
                    size_t dll_len = (size_t)(dot - fwd);
                    if (dll_len < sizeof(dll_name) - 5) {
                        /* forwarder strings are typically UPPERCASE
                         * ("CRYPTBASE.SystemFunction036"); the PEB walk
                         * hashes the real module name lowercase */
                        for (size_t q = 0; q < dll_len; q++) {
                            char ch = fwd[q];
                            dll_name[q] = (ch >= 'A' && ch <= 'Z')
                                        ? (char)(ch - 'A' + 'a') : ch;
                        }
                        strcpy(dll_name + dll_len, ".dll");
                        /* find the .dll in PEB (case-insensitive
                         * module hash walk) */
                        uint32_t mod_hash =
                            mirage_encrypted_hash_module(dll_name);
                        void *target_mod =
                            mirage_get_module_by_hash(mod_hash);
                        if (target_mod) {
                            uint32_t tgt_hash =
                                mirage_encrypted_hash_func(dot + 1);
                            return walk_exports(target_mod, tgt_hash);
                        }
                    }
                }
                return NULL;  /* unresolvable forwarder */
            }
            return (void*)(base_bytes + func_rva);
        }
    }

    return NULL;
}

/* ── initNativeResolver ────────────────────────────────────── */
int mirage_init_native_resolver(void* ntdll_base)
{
    if (!ntdll_base)
        return 0;

    char ldr_name[32]; enc_decrypt(enc_LdrGetProcedureAddress, ENC_LDRGETPROCEDUREADDRESS_LEN, ldr_name);
    uint32_t ldr_hash = mirage_encrypted_hash_func(ldr_name);
    void* func = walk_exports(ntdll_base, ldr_hash);

    if (func) {
        g_ldr_get_procedure_address = (LdrGetProcedureAddressFn)func;
        return 1;
    }

    return 0;
}

/* ── getFunctionByHash ─────────────────────────────────────── */
void* mirage_get_function_by_hash(void* module_base, uint32_t func_hash)
{
    if (!module_base)
        return NULL;

    return walk_exports(module_base, func_hash);
}
