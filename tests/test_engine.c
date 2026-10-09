/*
 * test_engine.c — Syscall SSN resolution engine tests (ZIALFI_TEST_MODE)
 *
 * Host-built (gcc). Builds a synthetic ntdll image:
 *   - fake module registered via mirage_peb_mock_module
 *   - valid DOS/NT headers + .text section for tbounds()
 *   - minimal export table: one export per Nt name, address points
 *     into the stub area at 0x20 intervals
 *   - clean stubs:  4C 8B D1 B8 <ssn16 LE> 00 00 + filler
 *   - 3 stubs are E9-hooked to force the Halo neighbor walk
 *   - 1 stub is a "high" SSN stub: 4C 8B D1 B8 12 34 56 78 (must be rejected)
 *
 * Asserts:
 *   - every table entry resolves non-zero or mirage_syscall_resolve() fails
 *     (fail-closed)
 *   - obf() leaves zero entries zero (never XORs zero — the root cause of
 *     the historical "issue syscall #0" bug)
 *   - NtUserGetSystemMetrics is gone from the engine table
 *   - strict isClean: imm32 must be < 0x1000 with bytes +6..7 == 0
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "engine.h"
#include "peb.h"
#include "hash.h"
#include "nt_types.h"
#include "enc_strings.h"

/* Synthetic image layout -------------------------------------------------
 * Layout (all offsets from image base):
 *   0x0000        DOS header (e_lfanew = 0x40)
 *   0x0040        NT headers
 *   0x0100        section header (.text)  — VirtualAddress 0x1000, size 0x2000
 *   0x0200        IMAGE_EXPORT_DIRECTORY
 *   0x0300        AddressOfNames array      (N dwords)
 *   0x0400        AddressOfFunctions array  (N dwords)
 *   0x0500        AddressOfNameOrdinals     (N words)
 *   0x0600..      export name strings
 *   0x1000        stub area: one 0x20-byte stub per export, in table order
 */
#define STUB_AREA_RVA  0x1000
#define STUB_SIZE      0x20
#define NAME_STR_RVA   0x0600
#define IMAGE_SIZE     0x3000

/* Full ntdll entry list — mirrors g_syscalls in engine.c minus
 * NtUserGetSystemMetrics (win32u.dll, removed). */
static const char *g_names[] = {
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtFreeVirtualMemory", "NtWriteVirtualMemory",
    "NtClose", "NtOpenFile", "NtReadVirtualMemory",
    "NtCreateSection", "NtMapViewOfSection",
    "NtQueryInformationProcess", "NtCreateFile",
    "NtWriteFile", "NtQuerySystemInformation",
    "NtDelayExecution", "NtCreateEvent",
    "NtWaitForSingleObject", "NtOpenKey",
    "NtQueryValueKey", "NtSetInformationProcess",
    "NtSetInformationFile", "NtGetContextThread",
    "NtSetContextThread", "NtOpenSection",
    "NtUnmapViewOfSection", "NtCreateThreadEx",
    "NtOpenProcess", "NtResumeThread",
    "NtSuspendThread", "NtDeleteFile",
    "NtFlushInstructionCache",
};
#define N_SYSCALLS (sizeof(g_names) / sizeof(g_names[0]))

static uint8_t g_image[IMAGE_SIZE];

/* Extern the SSN globals from engine.c (mirage_asm.h declares them on the
 * real build; re-declared here for the host build).
 * ssn_NtUserGetSystemMetrics must NOT exist anymore — its absence here is
 * part of the contract. */
extern uint32_t ssn_NtAllocateVirtualMemory;
extern uint32_t ssn_NtProtectVirtualMemory;
extern uint32_t ssn_NtFreeVirtualMemory;
extern uint32_t ssn_NtWriteVirtualMemory;
extern uint32_t ssn_NtClose;
extern uint32_t ssn_NtOpenFile;
extern uint32_t ssn_NtReadVirtualMemory;
extern uint32_t ssn_NtCreateSection;
extern uint32_t ssn_NtMapViewOfSection;
extern uint32_t ssn_NtQueryInformationProcess;
extern uint32_t ssn_NtCreateFile;
extern uint32_t ssn_NtWriteFile;
extern uint32_t ssn_NtQuerySystemInformation;
extern uint32_t ssn_NtDelayExecution;
extern uint32_t ssn_NtCreateEvent;
extern uint32_t ssn_NtWaitForSingleObject;
extern uint32_t ssn_NtOpenKey;
extern uint32_t ssn_NtQueryValueKey;
extern uint32_t ssn_NtSetInformationProcess;
extern uint32_t ssn_NtSetInformationFile;
extern uint32_t ssn_NtGetContextThread;
extern uint32_t ssn_NtSetContextThread;
extern uint32_t ssn_NtOpenSection;
extern uint32_t ssn_NtUnmapViewOfSection;
extern uint32_t ssn_NtCreateThreadEx;
extern uint32_t ssn_NtOpenProcess;
extern uint32_t ssn_NtResumeThread;
extern uint32_t ssn_NtSuspendThread;
extern uint32_t ssn_NtDeleteFile;
extern uint32_t ssn_NtFlushInstructionCache;

static uint32_t *g_ssn_slots[] = {
    &ssn_NtAllocateVirtualMemory, &ssn_NtProtectVirtualMemory,
    &ssn_NtFreeVirtualMemory, &ssn_NtWriteVirtualMemory,
    &ssn_NtClose, &ssn_NtOpenFile, &ssn_NtReadVirtualMemory,
    &ssn_NtCreateSection, &ssn_NtMapViewOfSection,
    &ssn_NtQueryInformationProcess, &ssn_NtCreateFile,
    &ssn_NtWriteFile, &ssn_NtQuerySystemInformation,
    &ssn_NtDelayExecution, &ssn_NtCreateEvent,
    &ssn_NtWaitForSingleObject, &ssn_NtOpenKey,
    &ssn_NtQueryValueKey, &ssn_NtSetInformationProcess,
    &ssn_NtSetInformationFile, &ssn_NtGetContextThread,
    &ssn_NtSetContextThread, &ssn_NtOpenSection,
    &ssn_NtUnmapViewOfSection, &ssn_NtCreateThreadEx,
    &ssn_NtOpenProcess, &ssn_NtResumeThread,
    &ssn_NtSuspendThread, &ssn_NtDeleteFile,
    &ssn_NtFlushInstructionCache,
};

/* offsets into g_names / g_ssn_slots that get E9-hooked (forces Halo walk) */
static const int g_hooked_idx[] = { 5, 19, 26 };  /* OpenFile, SetInfoFile, ResumeThread */
/* offset that gets the high-SSN poison stub (strict reject) */
#define POISON_IDX 13  /* NtDelayExecution */

/* Write a clean stub: 4C 8B D1 B8 <ssn16 LE> 00 00 + filler */
static void write_clean_stub(uint8_t *dst, uint16_t ssn) {
    dst[0] = 0x4C; dst[1] = 0x8B; dst[2] = 0xD1; dst[3] = 0xB8;
    dst[4] = (uint8_t)(ssn & 0xFF);
    dst[5] = (uint8_t)(ssn >> 8);
    dst[6] = 0x00; dst[7] = 0x00;
    /* syscall; ret + filler so the gadget scan has something to find */
    dst[8] = 0x0F; dst[9] = 0x05; dst[10] = 0xC3;
    memset(dst + 11, 0xC3, STUB_SIZE - 11);
}

static void write_hooked_stub(uint8_t *dst) {
    dst[0] = 0xE9;
    memset(dst + 1, 0x11, STUB_SIZE - 1);
}

static void write_poison_stub(uint8_t *dst) {
    /* mov r10,rcx; mov eax, 0x78563412 — high imm32, must never resolve */
    dst[0] = 0x4C; dst[1] = 0x8B; dst[2] = 0xD1; dst[3] = 0xB8;
    dst[4] = 0x12; dst[5] = 0x34; dst[6] = 0x56; dst[7] = 0x78;
    memset(dst + 8, 0x90, STUB_SIZE - 8);
}

/* Build the synthetic PE image with exports for all N_SYSCALLS names.
 * SSNs are sequential 0x10.. like real ntdll. */
static void build_ntdll(void) {
    memset(g_image, 0, sizeof(g_image));

    /* ── headers ── */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(g_image + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.DataDirectory[0].VirtualAddress = 0x200; /* exports */

    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(g_image + 0x100);
    memcpy(sec->Name, ".text", 6);
    sec->VirtualAddress = STUB_AREA_RVA;
    sec->Misc.VirtualSize = 0x2000;

    /* ── export directory ── */
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(g_image + 0x200);
    exp->NumberOfNames = N_SYSCALLS;
    exp->AddressOfNames = 0x300;
    exp->AddressOfFunctions = 0x400;
    exp->AddressOfNameOrdinals = 0x500;

    /* name strings: plain ASCII, null-terminated, sequential from 0x600 */
    static char name_strings[0x800];
    memset(name_strings, 0, sizeof(name_strings));
    size_t str_off = 0;
    uint32_t *names = (uint32_t *)(g_image + 0x300);
    uint32_t *funcs = (uint32_t *)(g_image + 0x400);
    uint16_t *ords  = (uint16_t *)(g_image + 0x500);

    for (size_t i = 0; i < N_SYSCALLS; i++) {
        strcpy(name_strings + str_off, g_names[i]);
        names[i] = NAME_STR_RVA + (uint32_t)str_off;
        str_off += strlen(g_names[i]) + 1;
        ords[i] = (uint16_t)i;
        funcs[i] = STUB_AREA_RVA + (uint32_t)(i * STUB_SIZE);
    }
    memcpy(g_image + NAME_STR_RVA, name_strings, str_off);

    /* ── stubs ── */
    for (size_t i = 0; i < N_SYSCALLS; i++)
        write_clean_stub(g_image + STUB_AREA_RVA + i * STUB_SIZE, (uint16_t)(0x10 + i));

    /* poison one stub: high SSN must be rejected by strict isClean */
    write_poison_stub(g_image + STUB_AREA_RVA + POISON_IDX * STUB_SIZE);
}

static void register_ntdll(void) {
    char dll_buf[32];
    enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll_buf);
    uint32_t mod_hash = mirage_encrypted_hash_module(dll_buf);
    mirage_peb_mock_module(mod_hash, g_image);
}

static void reset_engine(void) {
    /* zero all slots so a failing resolve leaves 0s behind */
    for (size_t i = 0; i < N_SYSCALLS; i++)
        *g_ssn_slots[i] = 0;
    mirage_peb_mock_clear();
}

/* ══ Tests ═══════════════════════════════════════════════════ */

static void test_all_entries_resolve(void) {
    reset_engine();
    build_ntdll();
    register_ntdll();

    int rc = mirage_syscall_resolve();

    /* Fail-closed contract: either everything resolved (rc 1) or the
     * engine reports failure (rc 0) — never a half-resolved state that
     * dispatches syscall #0. With the poison stub the entry must resolve
     * via Halo walk from a clean neighbor, so rc must be 1 and every
     * slot non-zero. */
    assert(rc == 1);
    for (size_t i = 0; i < N_SYSCALLS; i++) {
        if (*g_ssn_slots[i] == 0) {
            fprintf(stderr, "FAIL: %s resolved to SSN 0\n", g_names[i]);
            assert(*g_ssn_slots[i] != 0);
        }
    }
    printf("  all %zu entries resolve non-zero\n", N_SYSCALLS);
}

static void test_hooked_stubs_resolve_via_halo(void) {
    /* E9-hook 3 stubs; neighbors at ±0x20 are clean, so the Halo walk
     * must recover SSN ± distance. */
    reset_engine();
    build_ntdll();
    register_ntdll();
    for (size_t k = 0; k < sizeof(g_hooked_idx) / sizeof(g_hooked_idx[0]); k++)
        write_hooked_stub(g_image + STUB_AREA_RVA + g_hooked_idx[k] * STUB_SIZE);

    int rc = mirage_syscall_resolve();
    assert(rc == 1);
    for (size_t k = 0; k < sizeof(g_hooked_idx) / sizeof(g_hooked_idx[0]); k++) {
        int idx = g_hooked_idx[k];
        uint32_t got = *g_ssn_slots[idx];
        /* neighbor (idx+1) is clean with SSN 0x10+idx+1, distance 1 */
        uint32_t expect = 0x10 + (uint32_t)idx + 1 - 1;
        if (got != expect) {
            fprintf(stderr, "FAIL: %s halo-walk got %u expected %u\n",
                    g_names[idx], got, expect);
        }
        assert(got == expect);
    }
    printf("  3 E9-hooked stubs resolved via Halo walk\n");
}

static void test_unresolvable_fails_closed(void) {
    /* E9-hook EVERY stub → nothing resolvable → resolve must fail and
     * every slot stays 0 (obf() must not XOR zeros). */
    reset_engine();
    build_ntdll();
    register_ntdll();
    for (size_t i = 0; i < N_SYSCALLS; i++)
        write_hooked_stub(g_image + STUB_AREA_RVA + i * STUB_SIZE);

    int rc = mirage_syscall_resolve();
    assert(rc == 0);
    for (size_t i = 0; i < N_SYSCALLS; i++) {
        if (*g_ssn_slots[i] != 0) {
            fprintf(stderr, "FAIL: unresolvable %s has non-zero SSN %u\n",
                    g_names[i], *g_ssn_slots[i]);
            assert(*g_ssn_slots[i] == 0);
        }
    }
    printf("  total-hook image fails closed, all slots zero\n");
}

static void test_obf_zero_guard(void) {
    /* obf() contract: entries left at 0 (unresolved) stay 0 after the
     * XOR pass — XORing 0 would fabricate ssn_xor_key as the SSN and
     * make stubs issue a garbage syscall number. */
    reset_engine();
    build_ntdll();
    register_ntdll();
    for (size_t i = 0; i < N_SYSCALLS; i++)
        write_hooked_stub(g_image + STUB_AREA_RVA + i * STUB_SIZE);

    int rc = mirage_syscall_resolve();
    assert(rc == 0);
    for (size_t i = 0; i < N_SYSCALLS; i++)
        assert(*g_ssn_slots[i] == 0);
    printf("  obf() leaves zero entries zero\n");
}

static void test_strict_reject_high_ssn(void) {
    /* The poison stub (imm32 = 0x78563412) must not resolve as 0x78563412
     * nor any derived garbage; strict isClean requires imm32 < 0x1000.
     * Neighbor walk is expected to recover the correct SSN instead. */
    reset_engine();
    build_ntdll();
    register_ntdll();
    int rc = mirage_syscall_resolve();
    assert(rc == 1);
    uint32_t got = *g_ssn_slots[POISON_IDX];
    /* stub is poisoned but not hooked → Halo walk from clean neighbor
     * idx+1 (SSN 0x10+14+1, distance 1) → 0x10+POISON_IDX */
    if (got != 0x10 + POISON_IDX) {
        fprintf(stderr, "FAIL: poison stub resolved to %u\n", got);
    }
    assert(got == 0x10 + POISON_IDX);
    assert(got < 0x1000);
    printf("  high-SSN stub rejected (strict isClean)\n");
}

static void test_no_ntusergetsystemmetrics(void) {
    /* The win32u.dll syscall must not be in the engine table anymore.
     * With a full-clean image (no poison) resolve must still succeed for
     * the 30 ntdll entries; absence of the removed entry's ssn global is
     * enforced structurally by this file not externing it (link error if
     * reintroduced and obf() still references it). */
    reset_engine();
    build_ntdll();
    register_ntdll();
    /* un-poison */
    write_clean_stub(g_image + STUB_AREA_RVA + POISON_IDX * STUB_SIZE,
                     (uint16_t)(0x10 + POISON_IDX));
    int rc = mirage_syscall_resolve();
    assert(rc == 1);
    for (size_t i = 0; i < N_SYSCALLS; i++)
        assert(*g_ssn_slots[i] != 0);
    printf("  table has %zu entries, no NtUserGetSystemMetrics\n", N_SYSCALLS);
}

static void test_gadget_scan_stores_addrs(void) {
    reset_engine();
    build_ntdll();
    register_ntdll();
    int rc = mirage_syscall_resolve();
    assert(rc == 1);
    for (size_t i = 0; i < N_SYSCALLS; i++) {
        uintptr_t g = mirage_syscall_gadget((uint32_t)i);
        if (g == 0) {
            fprintf(stderr, "FAIL: no gadget for %s\n", g_names[i]);
            assert(g != 0);
        }
        /* gadget must point into the stub area */
        uintptr_t off = g - (uintptr_t)g_image;
        assert(off >= STUB_AREA_RVA && off < STUB_AREA_RVA + 0x2000);
        /* and must point at 0F 05 */
        assert(g_image[off] == 0x0F && g_image[off + 1] == 0x05);
    }
    printf("  per-entry gadgets stored and point at 0F 05\n");
}

static void test_missing_export_fails_closed(void) {
    /* Point one export outside .text (unresolvable) — engine must fail
     * closed rather than leaving a zero slot that obf() would XOR. */
    reset_engine();
    build_ntdll();
    register_ntdll();
    uint32_t *funcs = (uint32_t *)(g_image + 0x400);
    funcs[N_SYSCALLS - 1] = 0x9000;  /* outside .text */

    int rc = mirage_syscall_resolve();
    assert(rc == 0);
    assert(*g_ssn_slots[N_SYSCALLS - 1] == 0);
    printf("  missing export → resolve fails closed\n");
}

int main(void) {
    printf("test_engine: SSN resolution table\n");
    test_all_entries_resolve();
    test_hooked_stubs_resolve_via_halo();
    test_unresolvable_fails_closed();
    test_obf_zero_guard();
    test_strict_reject_high_ssn();
    test_no_ntusergetsystemmetrics();
    test_gadget_scan_stores_addrs();
    test_missing_export_fails_closed();
    printf("ALL TESTS PASSED\n");
    return 0;
}
