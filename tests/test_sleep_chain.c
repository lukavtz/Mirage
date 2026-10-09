/*
 * test_sleep_chain.c — ROP chain register-contract tests for the
 * Zilean-style sleep obfuscation (build_rop_chain in
 * src/evasion/sleep_obfusc.c).
 *
 * Host-only: compiles sleep_obfusc.c with -DTEST_SLEEP_CHAIN (pure
 * builder, Windows runtime excluded). Asserts per step:
 *   - Rip points at the expected function
 *   - Rcx/Rdx/R8/R9 match the win64 argument slots from the spec table
 *   - Rsp = template.Rsp - 8*(i+1) (8-byte decrement per entry)
 *
 * Step table (mirrors src/evasion/sleep_obfusc.c build_rop_chain):
 *   0: SetEvent(event_ack)                      Rcx=ack
 *   1: NtProtectVirtualMemory(RW)               Rcx=-1 Rdx=&text R8=&size R9=RW
 *   2: SystemFunction032(encrypt)               Rcx=&key Rdx=&data
 *   3: NtGetContextThread(save)                 Rcx=thread Rdx=&backup
 *   4: NtSetContextThread(spoof)                Rcx=thread Rdx=&spoof(template)
 *   5: WaitForSingleObjectEx(timeout)           Rcx=-1 Rdx=timeout R8=FALSE
 *   6: NtSetContextThread(restore)              Rcx=thread Rdx=&backup
 *   7: SystemFunction032(decrypt)               Rcx=&key Rdx=&data
 *   8: NtProtectVirtualMemory(RX)               Rcx=-1 Rdx=&text R8=&size R9=RX
 *   9: SetEvent(event_wake)                     Rcx=wake
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

/* Symbols exported by sleep_obfusc.c under -DTEST_SLEEP_CHAIN */
typedef struct _USTRING_T {
    DWORD           Length;
    DWORD           MaximumLength;
    unsigned char  *Buffer;
} USTRING_T;

typedef NTSTATUS (NTAPI *fnptr_t)(void);
typedef void     (*vfnptr_t)(void);

/* Mirror of rop_chain_inputs_t from sleep_obfusc.c (kept in lockstep:
 * build_rop_chain reads it field-by-field; a layout change here is a
 * test failure, which is the point). */
typedef struct {
    vfnptr_t fn_setevent;
    vfnptr_t fn_wait_ex;
    vfnptr_t fn_sysfunc032;
    vfnptr_t fn_nt_get_ctx;
    vfnptr_t fn_nt_set_ctx;
    vfnptr_t fn_nt_protect;
    vfnptr_t fn_nt_continue;
    vfnptr_t fn_rtl_register;
    vfnptr_t fn_nt_signal;
    vfnptr_t fn_rtl_capture;
    vfnptr_t fn_nt_duplicate;
    HANDLE   event_ack;
    HANDLE   event_wake;
    HANDLE   thread;
    void    *text_va;
    size_t   text_size;
    DWORD    timeout_ms;
    PCONTEXT template_ctx;
    void    *rc4_key;
    void    *rc4_data;
    void    *ctx_backup;
} test_rop_inputs_t;

void build_rop_chain(PCONTEXT rop, size_t rop_count, const void *in);

#define CHAIN_STEPS 10

#ifndef PAGE_READWRITE
#define PAGE_READWRITE  0x04
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ 0x20
#endif

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
} while (0)

int main(void) {
    test_rop_inputs_t in;
    memset(&in, 0, sizeof(in));

    /* Distinct fake addresses so pointer assertions are meaningful. */
    vfnptr_t f_setevent   = (vfnptr_t)0x10001000;
    vfnptr_t f_wait_ex    = (vfnptr_t)0x10002000;
    vfnptr_t f_sysfunc032 = (vfnptr_t)0x10003000;
    vfnptr_t f_get_ctx    = (vfnptr_t)0x10004000;
    vfnptr_t f_set_ctx    = (vfnptr_t)0x10005000;
    vfnptr_t f_protect    = (vfnptr_t)0x10006000;
    in.fn_setevent    = f_setevent;
    in.fn_wait_ex     = f_wait_ex;
    in.fn_sysfunc032  = f_sysfunc032;
    in.fn_nt_get_ctx  = f_get_ctx;
    in.fn_nt_set_ctx  = f_set_ctx;
    in.fn_nt_protect  = f_protect;

    HANDLE ev_ack  = (HANDLE)0x20001000;
    HANDLE ev_wake = (HANDLE)0x20002000;
    HANDLE thread  = (HANDLE)0x20003000;
    in.event_ack  = ev_ack;
    in.event_wake = ev_wake;
    in.thread     = thread;

    in.text_va    = (void *)0x30001000;
    in.text_size  = 0x2000;
    in.timeout_ms = 3000;

    CONTEXT template_ctx;
    memset(&template_ctx, 0, sizeof(template_ctx));
    template_ctx.Rsp = 0x4000F000ULL;
    in.template_ctx = &template_ctx;

    void *rc4_key  = (void *)0x50001000;
    void *rc4_data = (void *)0x50002000;
    void *ctx_bak  = (void *)0x50003000;
    in.rc4_key    = rc4_key;
    in.rc4_data   = rc4_data;
    in.ctx_backup = ctx_bak;

    CONTEXT rop[CHAIN_STEPS];
    memset(rop, 0, sizeof(rop));
    build_rop_chain(rop, CHAIN_STEPS, &in);

    /* ── Step 0: SetEvent(event_ack) ── */
    CHECK(rop[0].Rip == (DWORD64)(uintptr_t)f_setevent, "step0 Rip = SetEvent");
    CHECK(rop[0].Rcx == (DWORD64)(uintptr_t)ev_ack,      "step0 Rcx = event_ack");

    /* ── Step 1: NtProtectVirtualMemory(-1, &text, &size, RW, NULL) ── */
    CHECK(rop[1].Rip == (DWORD64)(uintptr_t)f_protect,   "step1 Rip = NtProtectVirtualMemory");
    CHECK(rop[1].Rcx == (DWORD64)(uintptr_t)(intptr_t)-1, "step1 Rcx = NtCurrentProcess");
    CHECK(rop[1].Rdx == (DWORD64)(uintptr_t)&in.text_va,  "step1 Rdx = &text_va");
    CHECK(rop[1].R8  == (DWORD64)(uintptr_t)&in.text_size, "step1 R8 = &text_size");
    CHECK(rop[1].R9  == (DWORD64)PAGE_READWRITE,          "step1 R9 = PAGE_READWRITE");

    /* ── Step 2: SystemFunction032(&data, &key) — encrypt ── */
    CHECK(rop[2].Rip == (DWORD64)(uintptr_t)f_sysfunc032, "step2 Rip = SystemFunction032");
    CHECK(rop[2].Rcx == (DWORD64)(uintptr_t)rc4_key,      "step2 Rcx = &key USTRING");
    CHECK(rop[2].Rdx == (DWORD64)(uintptr_t)rc4_data,     "step2 Rdx = &data USTRING");

    /* ── Step 3: NtGetContextThread(thread, &backup) ── */
    CHECK(rop[3].Rip == (DWORD64)(uintptr_t)f_get_ctx,    "step3 Rip = NtGetContextThread");
    CHECK(rop[3].Rcx == (DWORD64)(uintptr_t)thread,       "step3 Rcx = thread handle");
    CHECK(rop[3].Rdx == (DWORD64)(uintptr_t)ctx_bak,      "step3 Rdx = &ctx_backup");

    /* ── Step 4: NtSetContextThread(thread, &spoof) ── */
    CHECK(rop[4].Rip == (DWORD64)(uintptr_t)f_set_ctx,    "step4 Rip = NtSetContextThread");
    CHECK(rop[4].Rcx == (DWORD64)(uintptr_t)thread,       "step4 Rcx = thread handle");
    CHECK(rop[4].Rdx == (DWORD64)(uintptr_t)&template_ctx, "step4 Rdx = spoof/template ctx");

    /* ── Step 5: WaitForSingleObjectEx(-1, timeout, FALSE) ── */
    CHECK(rop[5].Rip == (DWORD64)(uintptr_t)f_wait_ex,    "step5 Rip = WaitForSingleObjectEx");
    CHECK(rop[5].Rcx == (DWORD64)(uintptr_t)(intptr_t)-1,  "step5 Rcx = NtCurrentProcess");
    CHECK(rop[5].Rdx == (DWORD64)in.timeout_ms,            "step5 Rdx = timeout ms");
    CHECK(rop[5].R8  == 0,                                 "step5 R8 = FALSE");

    /* ── Step 6: NtSetContextThread(thread, &backup) — restore ── */
    CHECK(rop[6].Rip == (DWORD64)(uintptr_t)f_set_ctx,    "step6 Rip = NtSetContextThread");
    CHECK(rop[6].Rcx == (DWORD64)(uintptr_t)thread,       "step6 Rcx = thread handle");
    CHECK(rop[6].Rdx == (DWORD64)(uintptr_t)ctx_bak,      "step6 Rdx = &ctx_backup");

    /* ── Step 7: SystemFunction032(&data, &key) — decrypt ── */
    CHECK(rop[7].Rip == (DWORD64)(uintptr_t)f_sysfunc032, "step7 Rip = SystemFunction032");
    CHECK(rop[7].Rcx == (DWORD64)(uintptr_t)rc4_key,      "step7 Rcx = &key USTRING");
    CHECK(rop[7].Rdx == (DWORD64)(uintptr_t)rc4_data,     "step7 Rdx = &data USTRING");

    /* ── Step 8: NtProtectVirtualMemory(-1, &text, &size, RX, NULL) ── */
    CHECK(rop[8].Rip == (DWORD64)(uintptr_t)f_protect,    "step8 Rip = NtProtectVirtualMemory");
    CHECK(rop[8].Rcx == (DWORD64)(uintptr_t)(intptr_t)-1,  "step8 Rcx = NtCurrentProcess");
    CHECK(rop[8].Rdx == (DWORD64)(uintptr_t)&in.text_va,   "step8 Rdx = &text_va");
    CHECK(rop[8].R8  == (DWORD64)(uintptr_t)&in.text_size, "step8 R8 = &text_size");
    CHECK(rop[8].R9  == (DWORD64)PAGE_EXECUTE_READ,        "step8 R9 = PAGE_EXECUTE_READ");

    /* ── Step 9: SetEvent(event_wake) ── */
    CHECK(rop[9].Rip == (DWORD64)(uintptr_t)f_setevent,   "step9 Rip = SetEvent");
    CHECK(rop[9].Rcx == (DWORD64)(uintptr_t)ev_wake,      "step9 Rcx = event_wake");

    /* ── Rsp contract: each entry decrements 8 below the template ── */
    for (int i = 0; i < CHAIN_STEPS; i++) {
        DWORD64 expect = template_ctx.Rsp - (DWORD64)(8 * (i + 1));
        if (rop[i].Rsp != expect) {
            printf("FAIL: step %d Rsp = 0x%llx, expected 0x%llx "
                   "(template - 8*(i+1))\n",
                   i, (unsigned long long)rop[i].Rsp,
                   (unsigned long long)expect);
            fails++;
        }
    }
    /* Rsp strictly decreasing across the chain */
    for (int i = 1; i < CHAIN_STEPS; i++)
        CHECK(rop[i].Rsp == rop[i-1].Rsp - 8, "Rsp decreases by exactly 8 per step");

    if (fails) {
        printf("=== test_sleep_chain: %d FAILURES ===\n", fails);
        return 1;
    }
    printf("=== test_sleep_chain PASSED ===\n");
    return 0;
}
