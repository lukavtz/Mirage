/*
 * export_resolve.h — PE export table resolver for Mirage-C
 *
 * Resolves function addresses from module export tables using
 * XOR-encrypted name hashes (27 iterations, exact case).
 */

#ifndef MIRAGE_EXPORT_RESOLVE_H
#define MIRAGE_EXPORT_RESOLVE_H

#include "nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * initNativeResolver — Resolve LdrGetProcedureAddress from ntdll's
 * export table by hash. Stores the function pointer for later use.
 *
 * Returns 1 on success, 0 on failure.
 */
int mirage_init_native_resolver(void* ntdll_base);

/*
 * getFunctionByHash — Walk a module's export table and return
 * the function address whose name hashes to funcHash.
 *
 * Hash pipeline: XOR each byte with STRING_KEY_ENC[i % 16],
 * then hash with rotl32(5) XOR mul, 27 iterations.
 *
 * Returns function pointer, or NULL if not found.
 */
void* mirage_get_function_by_hash(void* module_base, uint32_t func_hash);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_EXPORT_RESOLVE_H */
