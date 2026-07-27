/*
 * mirage_asm.h — External declarations for NASM-generated symbols
 *
 * These functions are defined in asm/mirage_stubs.asm and assembled
 * with NASM. The C code links against them.
 */

#ifndef MIRAGE_ASM_H
#define MIRAGE_ASM_H

#include "nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── PEB access (asm/mirage_stubs.asm) ────────────────────── */
PVOID getPeb(void);

/* ── SSN storage (written by C engine, read by ASM stubs) ─── */
extern uint32_t ssn_NtAllocateVirtualMemory;
extern uint32_t ssn_NtProtectVirtualMemory;
extern uint32_t ssn_NtFreeVirtualMemory;
extern uint32_t ssn_NtWriteVirtualMemory;
extern uint32_t ssn_NtClose;
extern uint32_t ssn_NtOpenFile;
extern uint32_t ssn_NtReadVirtualMemory;
extern uint32_t ssn_NtCreateSection;
extern uint32_t ssn_NtMapViewOfSection;
extern uint32_t ssn_NtQueryInformationProcess;
extern uint32_t ssn_NtCreateFile;
extern uint32_t ssn_NtWriteFile;
extern uint32_t ssn_NtQuerySystemInformation;
extern uint32_t ssn_NtDelayExecution;
extern uint32_t ssn_NtCreateEvent;
extern uint32_t ssn_NtWaitForSingleObject;
extern uint32_t ssn_NtOpenKey;
extern uint32_t ssn_NtQueryValueKey;
extern uint32_t ssn_NtSetInformationProcess;
extern uint32_t ssn_NtSetInformationFile;
extern uint32_t ssn_NtUserGetSystemMetrics;
extern uint32_t ssn_NtGetContextThread;
extern uint32_t ssn_NtSetContextThread;
extern uint32_t ssn_NtOpenSection;
extern uint32_t ssn_NtUnmapViewOfSection;
extern uint32_t ssn_NtCreateThreadEx;
extern uint32_t ssn_NtOpenProcess;
extern uint32_t ssn_NtResumeThread;
extern uint32_t ssn_NtSuspendThread;
extern uint32_t ssn_NtDeleteFile;
extern uint32_t ssn_NtFlushInstructionCache;

/* ── Gadget pool (filled by C code, used by ASM stubs) ────── */
extern uint64_t gadget_pool[64];

/* ── Syscall stubs (each loads SSN, XOR deobfuscates, jumps) ─ */
uint64_t NtAllocateVirtualMemory_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtProtectVirtualMemory_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtFreeVirtualMemory_stub(uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtWriteVirtualMemory_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtClose_stub(uint64_t);
uint64_t NtOpenFile_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtReadVirtualMemory_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtCreateSection_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtMapViewOfSection_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtQueryInformationProcess_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtCreateFile_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtWriteFile_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtQuerySystemInformation_stub(uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtDelayExecution_stub(uint64_t, uint64_t);
uint64_t NtCreateEvent_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtWaitForSingleObject_stub(uint64_t, uint64_t, uint64_t);
uint64_t NtOpenKey_stub(uint64_t, uint64_t, uint64_t);
uint64_t NtQueryValueKey_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtSetInformationProcess_stub(uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtSetInformationFile_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtUserGetSystemMetrics_stub(uint64_t);
uint64_t NtGetContextThread_stub(uint64_t, uint64_t);
uint64_t NtSetContextThread_stub(uint64_t, uint64_t);
uint64_t NtOpenSection_stub(uint64_t, uint64_t, uint64_t);
uint64_t NtUnmapViewOfSection_stub(uint64_t, uint64_t);
uint64_t NtCreateThreadEx_stub(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtOpenProcess_stub(uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t NtResumeThread_stub(uint64_t, uint64_t);
uint64_t NtSuspendThread_stub(uint64_t, uint64_t);
uint64_t NtDeleteFile_stub(uint64_t);
uint64_t NtFlushInstructionCache_stub(uint64_t, uint64_t, uint64_t);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_ASM_H */
