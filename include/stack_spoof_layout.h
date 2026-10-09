/*
 * stack_spoof_layout.h — frame layout constants for spoof_call
 *
 * Single source of truth shared by asm/stack_spoof_stubs.asm (via
 * include/stack_spoof_layout.inc, NASM) and the host-side layout test.
 *
 * Frame at entry of spoof_call (before push rbp):
 *   [rsp+0x00] return address
 *   [rsp+0x08..0x28] caller-provided shadow space (32 bytes, caller's frame)
 *   [rsp+0x28] arg3 ... [rsp+0x68] arg11
 * After `push rbp; mov rbp, rsp`:
 *   [rbp+0x08] = return address  => arg3 at [rbp+0x28], arg11 at [rbp+0x68].
 *
 * In spoof_call's own frame (below rbp) we keep:
 *   - non-volatile save area at NV_SAVE_BASE..+NV_SAVE_SIZE (8 slots)
 *   - arg stash area at STASH_BASE..+STASH_SIZE (8 slots: a2 + a5..a11)
 * Both must lie ABOVE (lower address than) the arg-write window
 * [rsp+0x28..0x60] that the tail-jumped target consumes.
 *
 * After `sub rsp, SPOOF_FRAME_SIZE` (rbp fixed):
 *   rsp = rbp - SPOOF_FRAME_SIZE
 *   [rsp+0x00..0x27] = fake return chain (5 qwords)
 *   [rsp+0x28..0x60] = target stack args a5..a11 (callee's shadow at 0x20
 *                       overlaps a5's home slot — win64 lets the callee
 *                       reuse [rsp+0x20] as a5 home; args 6+ at 0x30..0x60)
 *   [rbp-NV_SAVE_BASE-8 .. ] non-volatile saves (8 qwords, ABOVE rsp+0x60)
 *   [rbp-STASH_BASE .. ]    arg stashes (8 qwords: a2 + a5..a11, ABOVE rsp+0x60)
 */
#ifndef MIRAGE_STACK_SPOOF_LAYOUT_H
#define MIRAGE_STACK_SPOOF_LAYOUT_H

#define SSL_ARG3_OFF    0x28    /* arg3  at frame_base+0x28 (rbp after push) */
#define SSL_ARG4_OFF    0x30
#define SSL_ARG5_OFF    0x38
#define SSL_ARG6_OFF    0x40
#define SSL_ARG7_OFF    0x48
#define SSL_ARG8_OFF    0x50
#define SSL_ARG9_OFF    0x58
#define SSL_ARG10_OFF   0x60
#define SSL_ARG11_OFF   0x68

/* Our frame: 5-slot fake chain + 8 qwords of callee arg/shadow space. */
#define SSL_CHAIN_SIZE     0x28    /* 5 qwords: jmp gadget, add_rsp gadget, RtlUserThreadStart, BaseThreadInitThunk, real ret */
#define SSL_CALLEE_WINDOW  0x28    /* callee-visible: shadow(0x20)+a5 home overlaps; a6..a11 at 0x30..0x60 */
#define SSL_FRAME_SIZE     0x50    /* CHAIN_SIZE + CALLEE_WINDOW (0x28+0x28) */

/* Non-volatile save region: 8 qwords strictly above rsp+0x60 after sub. */
#define SSL_NV_COUNT       8
#define SSL_NV_SAVE_BASE   0x68    /* first save slot at [rbp-0x68] ... [rbp-0x30] */
#define SSL_NV_SAVE_SIZE   (SSL_NV_COUNT * 8)   /* 0x40: covers rbp-0x68 down to rbp-0x29 */

/* Arg stash region: 8 qwords (a2 + a5..a11) above the save region.
 * The asm stashes a2 here too (r9 is repurposed for arg4), so the
 * region spans [rbp-0xe8] ... [rbp-0x70]. */
#define SSL_STASH_COUNT    8
#define SSL_STASH_BASE     (0x68 + SSL_NV_SAVE_SIZE + 0x08 + (SSL_STASH_COUNT - 1) * 8)  /* 0xe8: [rbp-0xe8] ... [rbp-0x70] */
#define SSL_STASH_SIZE     (SSL_STASH_COUNT * 8)    /* 0x40 */

#endif /* MIRAGE_STACK_SPOOF_LAYOUT_H */
