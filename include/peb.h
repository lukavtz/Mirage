/*
 * peb.h — PEB walk for Mirage-C
 *
 * Finds loaded modules by walking PEB->Ldr->InMemoryOrderModuleList.
 * Module names are XOR-encrypted before hashing (matching Zig version).
 */

#ifndef MIRAGE_PEB_H
#define MIRAGE_PEB_H

#include "nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * getModuleByHash — Walk InMemoryOrderModuleList, hash each BaseDllName
 * with XOR encryption + case-insensitive hash (28 iterations), compare
 * against moduleHash.
 *
 * Returns DllBase pointer if found, NULL otherwise.
 *
 * The XOR + hash pipeline matches Zig peb_walk.getModuleByHash():
 *   1. Read BaseDllName.Buffer (WCHAR[])
 *   2. Truncate to ASCII byte, XOR with STRING_KEY_ENC[i % 16]
 *   3. Lowercase if A-Z
 *   4. Hash with rotl32 XOR mul, 28 iterations per byte
 */
void* mirage_get_module_by_hash(uint32_t moduleHash);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_PEB_H */
