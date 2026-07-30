/*
 * peb.c — PEB walk implementation for Mirage-C
 *
 * Exact translation of Zig src/types/peb_walk.zig
 *
 * The PEB pointer is read from GS:[0x60] via NASM stub (getPeb).
 * We then walk PEB->Ldr->InMemoryOrderModuleList, XOR-encrypting
 * each BaseDllName byte before hashing (28 iterations, case-insensitive).
 */

#include "peb.h"
#include "hash.h"
#include "config.h"
#include "mirage_asm.h"
#include <stddef.h>
#include <windows.h>

/* ── Rotl32 (local copy for hot path) ─────────────────────── */
static inline uint32_t rotl32(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

/* ── mirage_get_module_by_hash ────────────────────────────── */
void* mirage_get_module_by_hash(uint32_t moduleHash)
{
    /* Read PEB from GS:[0x60] via NASM stub */
    PPEB peb = (PPEB)getPeb();
    if (!peb || !peb->Ldr)
        return NULL;

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    /* Walk the doubly-linked list */
    while (current != head) {
        /*
         * InMemoryOrderLinks is offset 0x10 into LDR_DATA_TABLE_ENTRY.
         * To get the full entry, subtract 0x10 from the list link address.
         */
        PLDR_DATA_TABLE_ENTRY entry =
            (PLDR_DATA_TABLE_ENTRY)((uint8_t*)current - 0x10);

        PWSTR name_buf = entry->BaseDllName.Buffer;
        size_t name_len = entry->BaseDllName.Length / 2;  /* WCHAR → count */

        /*
         * Hash the module name:
         *   1. Read each WCHAR as a byte (truncate low byte)
         *   2. XOR with STRING_KEY_ENC[i % 16]
         *   3. Lowercase if A-Z
         *   4. Hash with rotl32(5) XOR mul, 28 iterations
         *
         * This matches Zig peb_walk.getModuleByHash() exactly.
         */
        uint32_t h = MIRAGE_SEED;

        for (size_t i = 0; i < name_len; i++) {
            uint8_t c = (uint8_t)(name_buf[i] & 0xFF);

            /* XOR-encrypt this byte */
            c ^= MIRAGE_STRING_KEY_ENC[i % 16];

            /* Lowercase */
            if (c >= 'A' && c <= 'Z')
                c += 32;

            /* 28 iterations of Rotl-XOR-Mul */
            for (uint32_t j = 0; j < 28; j++) {
                h = rotl32(h, 5);
                h ^= c;
                h = h * 0x1B873593u + 0x85EBCA6Bu;
            }
        }

        if (h == moduleHash) {
            return entry->DllBase;
        }

        current = current->Flink;
    }

    return NULL;
}
