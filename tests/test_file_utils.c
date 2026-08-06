/*
 * test_file_utils.c - Tests for file_utils.c
 *
 * Covers: path_join, basename_of, read_file, dir_exists, file_exists.
 * Uses synthetic PEB + PE image with VirtualProtect for executable stubs.
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
#include "file_utils.h"
#include "enc_strings.h"

/* Mock GetFileAttributesA: returns 0x10 for ".", 0x80 for "Makefile" */
static DWORD WINAPI mock_GetFileAttributesA(LPCSTR path) {
    if (!path) return INVALID_FILE_ATTRIBUTES;
    if (strcmp(path, ".") == 0) return FILE_ATTRIBUTE_DIRECTORY;
    if (strcmp(path, "Makefile") == 0) return FILE_ATTRIBUTE_NORMAL;
    return INVALID_FILE_ATTRIBUTES;
}

/* Synthetic PE image for kernel32 with GetFileAttributesA export.
 * We make the page executable and put a JMP to our mock at the function RVA. */
#define PE_IMG_SIZE 0x400
static uint8_t g_pe_image[PE_IMG_SIZE];
static int g_pe_made_exec = 0;

static void build_kernel32_pe(void) {
    memset(g_pe_image, 0, PE_IMG_SIZE);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_pe_image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(g_pe_image + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.Magic = 0x20B;
    nt->OptionalHeader.DataDirectory[0].VirtualAddress = 0x100;
    nt->OptionalHeader.DataDirectory[0].Size = sizeof(IMAGE_EXPORT_DIRECTORY);

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(g_pe_image + 0x100);
    exp->NumberOfFunctions = 2;
    exp->NumberOfNames = 1;
    exp->AddressOfNames = 0x200;
    exp->AddressOfNameOrdinals = 0x210;
    exp->AddressOfFunctions = 0x220;

    uint32_t *nptr = (uint32_t *)(g_pe_image + 0x200);
    nptr[0] = 0x240;
    uint16_t *ords = (uint16_t *)(g_pe_image + 0x210);
    ords[0] = 0;
    uint32_t *funcs = (uint32_t *)(g_pe_image + 0x220);
    funcs[0] = 0x300;
    funcs[1] = 0;

    const char *name = "GetFileAttributesA";
    memcpy(g_pe_image + 0x240, name, strlen(name) + 1);

    /* At offset 0x300, write a JMP to our mock function.
     * x86_64 RIP-relative JMP: E9 <rel32>
     * rel32 = target - (instruction + 5) */
    if (!g_pe_made_exec) {
        DWORD old_protect;
        VirtualProtect(g_pe_image, PE_IMG_SIZE, PAGE_EXECUTE_READWRITE, &old_protect);
        g_pe_made_exec = 1;
    }

    /* Write a simple stub: mov rax, <mock_fn>; jmp rax
     * Alternatively, use a near JMP. For simplicity, write:
     *   mov rax, imm64  (48 B8 <8 bytes>)
     *   jmp rax          (FF E0)
     * Total: 12 bytes at offset 0x300 */
    uint8_t *stub = g_pe_image + 0x300;
    uintptr_t mock_addr = (uintptr_t)mock_GetFileAttributesA;
    stub[0] = 0x48; stub[1] = 0xB8; /* mov rax, imm64 */
    memcpy(&stub[2], &mock_addr, 8);
    stub[10] = 0xFF; stub[11] = 0xE0; /* jmp rax */
}

/* Synthetic PEB */
static PEB             g_fake_peb;
static PEB_LDR_DATA    g_fake_ldr;
static LDR_DATA_TABLE_ENTRY g_fake_entry;
static WCHAR           g_name_buf[64];

void *getPeb(void) {
    return (void *)&g_fake_peb;
}

static void setup_kernel32_in_peb(void) {
    char dll_name[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll_name);
    size_t len = strlen(dll_name);
    for (size_t i = 0; i <= len; i++)
        g_name_buf[i] = (WCHAR)dll_name[i];

    memset(&g_fake_peb, 0, sizeof(g_fake_peb));
    memset(&g_fake_ldr, 0, sizeof(g_fake_ldr));
    memset(&g_fake_entry, 0, sizeof(g_fake_entry));

    g_fake_peb.Ldr = &g_fake_ldr;
    g_fake_ldr.InMemoryOrderModuleList.Flink = &g_fake_entry.InMemoryOrderLinks;
    g_fake_ldr.InMemoryOrderModuleList.Blink = &g_fake_entry.InMemoryOrderLinks;
    g_fake_entry.InMemoryOrderLinks.Flink = &g_fake_ldr.InMemoryOrderModuleList;
    g_fake_entry.InMemoryOrderLinks.Blink = &g_fake_ldr.InMemoryOrderModuleList;
    g_fake_entry.DllBase = g_pe_image;
    g_fake_entry.BaseDllName.Buffer = g_name_buf;
    g_fake_entry.BaseDllName.Length = (USHORT)(len * 2);
    g_fake_entry.BaseDllName.MaximumLength = (USHORT)((len + 1) * 2);
}

/* path_join tests */
static void test_path_join_basic(void) {
    char *r = path_join("foo", "bar");
    assert(r != NULL);
    assert(strcmp(r, "foo" PATH_SEP "bar") == 0);
    free(r);
    printf("  PASS: path_join_basic\n");
}
static void test_path_join_null_a(void) { assert(path_join(NULL, "bar") == NULL); printf("  PASS: path_join_null_a\n"); }
static void test_path_join_null_b(void) { assert(path_join("foo", NULL) == NULL); printf("  PASS: path_join_null_b\n"); }
static void test_path_join_both_null(void) { assert(path_join(NULL, NULL) == NULL); printf("  PASS: path_join_both_null\n"); }
static void test_path_join_empty_a(void) {
    char *r = path_join("", "bar"); assert(r != NULL);
    assert(strcmp(r, PATH_SEP "bar") == 0); free(r);
    printf("  PASS: path_join_empty_a\n");
}
static void test_path_join_empty_b(void) {
    char *r = path_join("foo", ""); assert(r != NULL);
    assert(strcmp(r, "foo" PATH_SEP) == 0); free(r);
    printf("  PASS: path_join_empty_b\n");
}
static void test_path_join_long(void) {
    char a[128], b[128];
    memset(a, 'a', 127); a[127] = '\0';
    memset(b, 'b', 127); b[127] = '\0';
    char *r = path_join(a, b); assert(r != NULL);
    assert(strlen(r) == 127 + 1 + 127); free(r);
    printf("  PASS: path_join_long\n");
}

/* basename_of tests */
static void test_basename_with_sep(void) { assert(strcmp(basename_of("dir" PATH_SEP "file.txt"), "file.txt") == 0); printf("  PASS: basename_with_sep\n"); }
static void test_basename_no_sep(void) { assert(strcmp(basename_of("file.txt"), "file.txt") == 0); printf("  PASS: basename_no_sep\n"); }
static void test_basename_nested(void) { assert(strcmp(basename_of("a" PATH_SEP "b" PATH_SEP "c.txt"), "c.txt") == 0); printf("  PASS: basename_nested\n"); }
static void test_basename_just_sep(void) { assert(strcmp(basename_of(PATH_SEP), "") == 0); printf("  PASS: basename_just_sep\n"); }

/* read_file tests */
static void test_read_file_real(void) {
    const char *path = "test_fu_tmp.txt";
    const char *data = "Hello, Mirage!"; size_t len = strlen(data);
    FILE *f = fopen(path, "wb"); assert(f);
    fwrite(data, 1, len, f); fclose(f);
    size_t out_len = 0;
    unsigned char *buf = read_file(path, &out_len);
    assert(buf != NULL); assert(out_len == len); assert(memcmp(buf, data, len) == 0);
    free(buf); remove(path);
    printf("  PASS: read_file_real\n");
}
static void test_read_file_missing(void) {
    size_t out_len = 999;
    assert(read_file("no_such_file_xyz.tmp", &out_len) == NULL);
    printf("  PASS: read_file_missing\n");
}
static void test_read_file_empty(void) {
    const char *path = "test_fu_empty.txt";
    FILE *f = fopen(path, "wb"); assert(f); fclose(f);
    size_t out_len = 999;
    assert(read_file(path, &out_len) == NULL);
    remove(path);
    printf("  PASS: read_file_empty\n");
}
static void test_read_file_binary(void) {
    const char *path = "test_fu_bin.dat";
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
    FILE *f = fopen(path, "wb"); assert(f);
    fwrite(data, 1, 256, f); fclose(f);
    size_t out_len = 0;
    unsigned char *buf = read_file(path, &out_len);
    assert(buf != NULL); assert(out_len == 256); assert(memcmp(buf, data, 256) == 0);
    free(buf); remove(path);
    printf("  PASS: read_file_binary\n");
}

/* dir_exists/file_exists with synthetic PEB + PE (executable stub) */
static void test_dir_exists_with_peb(void) {
    build_kernel32_pe();
    setup_kernel32_in_peb();
    /* dir_exists -> fu_ensure_k32 resolves kernel32 -> GetFileAttributesA
     * -> mock returns FILE_ATTRIBUTE_DIRECTORY for "." */
    assert(dir_exists(".") == 1);
    printf("  PASS: dir_exists_with_peb\n");
}
static void test_file_exists_with_peb(void) {
    /* fu_ensure_k32 already cached */
    assert(file_exists("Makefile") == 1);
    printf("  PASS: file_exists_with_peb\n");
}
static void test_dir_exists_not_found(void) {
    assert(dir_exists("nonexistent_dir_xyz") == 0);
    printf("  PASS: dir_exists_not_found\n");
}
static void test_file_exists_not_found(void) {
    assert(file_exists("nonexistent_file_xyz") == 0);
    printf("  PASS: file_exists_not_found\n");
}
static void test_dir_exists_null_input(void) { dir_exists(NULL); printf("  PASS: dir_exists_null_input\n"); }
static void test_file_exists_null_input(void) { file_exists(NULL); printf("  PASS: file_exists_null_input\n"); }

int main(void) {
    printf("=== test_file_utils ===\n");
    test_path_join_basic();
    test_path_join_null_a();
    test_path_join_null_b();
    test_path_join_both_null();
    test_path_join_empty_a();
    test_path_join_empty_b();
    test_path_join_long();
    test_basename_with_sep();
    test_basename_no_sep();
    test_basename_nested();
    test_basename_just_sep();
    test_read_file_real();
    test_read_file_missing();
    test_read_file_empty();
    test_read_file_binary();
    test_dir_exists_with_peb();
    test_file_exists_with_peb();
    test_dir_exists_not_found();
    test_file_exists_not_found();
    test_dir_exists_null_input();
    test_file_exists_null_input();
    printf("=== test_file_utils: ALL PASSED ===\n");
    return 0;
}
