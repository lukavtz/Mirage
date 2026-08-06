/*
 * test_export_resolve.c — Tests for export_resolve.c
 *
 * Tests PE export table walker via synthetic in-memory PE images.
 * Covers: NULL checks, bad DOS/NT signatures, missing exports,
 *         single export lookup, multi-export lookup.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <windows.h>
#include "config.h"
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"

/* Stub for NASM getPeb */
void *getPeb(void) { return NULL; }

/* ── NULL / error handling ───────────────────────────────── */

static void test_null_module(void) {
    assert(mirage_get_function_by_hash(NULL, 0x12345678) == NULL);
    printf("  PASS: null_module\n");
}

static void test_init_null(void) {
    assert(mirage_init_native_resolver(NULL) == 0);
    printf("  PASS: init_null\n");
}

static void test_bad_dos_magic(void) {
    uint8_t fake[512];
    memset(fake, 0, sizeof(fake));
    fake[0] = 'X'; fake[1] = 'Y';
    assert(mirage_get_function_by_hash(fake, 0x12345678) == NULL);
    printf("  PASS: bad_dos_magic\n");
}

static void test_bad_nt_signature(void) {
    uint8_t fake[512];
    memset(fake, 0, sizeof(fake));
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fake;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 64;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(fake + 64);
    nt->Signature = 0xDEADBEEF;
    assert(mirage_get_function_by_hash(fake, 0x12345678) == NULL);
    printf("  PASS: bad_nt_signature\n");
}

static void test_no_export_table(void) {
    uint8_t fake[512];
    memset(fake, 0, sizeof(fake));
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fake;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 64;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(fake + 64);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.Magic = 0x20B;
    /* DataDirectory[0].VirtualAddress = 0 -> no exports */
    assert(mirage_get_function_by_hash(fake, 0x12345678) == NULL);
    printf("  PASS: no_export_table\n");
}

/* ── Synthetic PE builder ────────────────────────────────── */

/*
 * Build a minimal PE image with named exports in memory.
 *
 * Layout:
 *   0x000: IMAGE_DOS_HEADER (64 bytes)
 *   0x040: IMAGE_NT_HEADERS64
 *   0x100: IMAGE_EXPORT_DIRECTORY
 *   0x200: Name pointer table (RVAs)
 *   0x210: Ordinal table
 *   0x220: Function RVA table
 *   0x240+: Name strings
 *   0x300+: Function bodies
 */
#define PE_SIZE 0x500

static uint8_t *build_pe(void) {
    uint8_t *img = (uint8_t *)calloc(PE_SIZE, 1);
    assert(img != NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)img;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(img + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.Magic = 0x20B; /* PE32+ */
    nt->OptionalHeader.DataDirectory[0].VirtualAddress = 0x100;
    nt->OptionalHeader.DataDirectory[0].Size = sizeof(IMAGE_EXPORT_DIRECTORY);

    return img;
}

static void set_export_dir(uint8_t *img, uint32_t num_funcs, uint32_t num_names) {
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(img + 0x100);
    exp->NumberOfFunctions = num_funcs;
    exp->NumberOfNames = num_names;
    exp->AddressOfNames = 0x200;
    exp->AddressOfNameOrdinals = 0x210;
    exp->AddressOfFunctions = 0x220;
}

/* ── Single export ───────────────────────────────────────── */

static void test_find_single_export(void) {
    uint8_t *img = build_pe();
    set_export_dir(img, 2, 1);

    /* Name pointers */
    uint32_t *nptr = (uint32_t *)(img + 0x200);
    nptr[0] = 0x240;

    /* Name string "TestFunc" at 0x240 */
    memcpy(img + 0x240, "TestFunc", 9);

    /* Ordinals */
    uint16_t *ords = (uint16_t *)(img + 0x210);
    ords[0] = 0;

    /* Function RVAs */
    uint32_t *funcs = (uint32_t *)(img + 0x220);
    funcs[0] = 0x300;
    funcs[1] = 0;
    img[0x300] = 0xC3; /* ret */

    /* Lookup by hash */
    uint32_t hash = mirage_encrypted_hash_func("TestFunc");
    void *found = mirage_get_function_by_hash(img, hash);
    assert(found == (void *)(img + 0x300));

    free(img);
    printf("  PASS: find_single_export\n");
}

static void test_wrong_hash_not_found(void) {
    uint8_t *img = build_pe();
    set_export_dir(img, 2, 1);

    uint32_t *nptr = (uint32_t *)(img + 0x200);
    nptr[0] = 0x240;
    memcpy(img + 0x240, "TestFunc", 9);

    uint16_t *ords = (uint16_t *)(img + 0x210);
    ords[0] = 0;

    uint32_t *funcs = (uint32_t *)(img + 0x220);
    funcs[0] = 0x300;
    funcs[1] = 0;

    assert(mirage_get_function_by_hash(img, 0xDEADBEEF) == NULL);
    free(img);
    printf("  PASS: wrong_hash_not_found\n");
}

/* ── Two exports ─────────────────────────────────────────── */

static void test_find_two_exports(void) {
    uint8_t *img = build_pe();
    set_export_dir(img, 3, 2);

    uint32_t *nptr = (uint32_t *)(img + 0x200);
    nptr[0] = 0x250; /* "Alpha" */
    nptr[1] = 0x260; /* "Beta"  */

    memcpy(img + 0x250, "Alpha\0", 6);
    memcpy(img + 0x260, "Beta\0", 5);

    uint16_t *ords = (uint16_t *)(img + 0x210);
    ords[0] = 0;
    ords[1] = 1;

    uint32_t *funcs = (uint32_t *)(img + 0x220);
    funcs[0] = 0x300;
    funcs[1] = 0x310;
    funcs[2] = 0;
    img[0x300] = 0xC3;
    img[0x310] = 0xC3;

    uint32_t h_alpha = mirage_encrypted_hash_func("Alpha");
    uint32_t h_beta  = mirage_encrypted_hash_func("Beta");

    assert(mirage_get_function_by_hash(img, h_alpha) == (void *)(img + 0x300));
    assert(mirage_get_function_by_hash(img, h_beta)  == (void *)(img + 0x310));

    free(img);
    printf("  PASS: find_two_exports\n");
}

/* ── Long export name ────────────────────────────────────── */

static void test_long_export_name(void) {
    uint8_t *img = build_pe();
    set_export_dir(img, 2, 1);

    /* A 30-char function name */
    const char *long_name = "SomeVeryLongFunctionName123456";
    size_t name_len = strlen(long_name) + 1;

    uint32_t *nptr = (uint32_t *)(img + 0x200);
    nptr[0] = 0x240;
    memcpy(img + 0x240, long_name, name_len);

    uint16_t *ords = (uint16_t *)(img + 0x210);
    ords[0] = 0;

    uint32_t *funcs = (uint32_t *)(img + 0x220);
    funcs[0] = 0x300;
    funcs[1] = 0;
    img[0x300] = 0xC3;

    uint32_t hash = mirage_encrypted_hash_func(long_name);
    assert(mirage_get_function_by_hash(img, hash) == (void *)(img + 0x300));

    free(img);
    printf("  PASS: long_export_name\n");
}

/* ── main ────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_export_resolve ===\n");
    test_null_module();
    test_init_null();
    test_bad_dos_magic();
    test_bad_nt_signature();
    test_no_export_table();
    test_find_single_export();
    test_wrong_hash_not_found();
    test_find_two_exports();
    test_long_export_name();
    printf("=== test_export_resolve: ALL PASSED ===\n");
    return 0;
}
