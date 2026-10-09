/*
 * engine.h — Syscall engine for zialfi
 * 
 * When PEB walk works: uses indirect syscalls via NASM stubs
 * When PEB walk fails: falls back to standard WinAPI imports
 */
#ifndef ENGINE_H
#define ENGINE_H

#include <windows.h>
#include <stdint.h>

typedef long NTSTATUS;

/* Resolves syscalls via PEB walk, returns 1 on success */
/*
 * Per-syscall indirect-execution gadget (address of a 0F 05 sequence in
 * ntdll, within 0x22 bytes forward of the resolved stub). Index is the
 * table position in g_syscalls (engine.c) — see MIRAGE_SYSCALL_COUNT.
 * Returns 0 if the entry was not resolved or no gadget was found.
 */
uintptr_t mirage_syscall_gadget(uint32_t index);

int mirage_syscall_resolve(void);

/* Wrappers: try indirect syscall first, fallback to WinAPI */
NTSTATUS mirage_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG ZeroBits, SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS mirage_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, ULONG* OldAccessProtection);
NTSTATUS mirage_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    SIZE_T* RegionSize, ULONG FreeType);
NTSTATUS mirage_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, SIZE_T* NumberOfBytesWritten);
NTSTATUS mirage_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToRead, SIZE_T* NumberOfBytesRead);
NTSTATUS mirage_NtClose(HANDLE Handle);
NTSTATUS mirage_NtQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);
NTSTATUS mirage_NtQueryInformationProcess(HANDLE ProcessHandle,
    ULONG ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, ULONG* ReturnLength);
NTSTATUS mirage_NtDelayExecution(BOOLEAN Alertable, LARGE_INTEGER* DelayInterval);
NTSTATUS mirage_NtCreateFile(HANDLE* FileHandle, ULONG DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock, PVOID AllocationSize,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS mirage_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer,
    ULONG Length, PVOID ByteOffset, PVOID Key);
NTSTATUS mirage_NtSetInformationProcess(HANDLE ProcessHandle,
    ULONG ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength);
NTSTATUS mirage_NtOpenKey(HANDLE* KeyHandle, ULONG DesiredAccess, PVOID ObjectAttributes);
NTSTATUS mirage_NtQueryValueKey(HANDLE KeyHandle, PVOID ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, ULONG* ResultLength);
NTSTATUS mirage_NtOpenProcess(HANDLE* ProcessHandle, ULONG DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId);
NTSTATUS mirage_NtCreateThreadEx(HANDLE* ThreadHandle, ULONG DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);
NTSTATUS mirage_NtFlushInstructionCache(HANDLE ProcessHandle,
    PVOID BaseAddress, SIZE_T NumberOfBytesToFlush);
NTSTATUS mirage_NtCreateEvent(HANDLE* EventHandle, ULONG DesiredAccess,
    PVOID ObjectAttributes, ULONG EventType, ULONG InitialState);
NTSTATUS mirage_NtDeleteFile(PVOID ObjectAttributes);
NTSTATUS mirage_NtSetInformationFile(HANDLE FileHandle, PVOID IoStatusBlock,
    PVOID FileInformation, ULONG Length, ULONG FileInformationClass);
LONG mirage_NtUserGetSystemMetrics(ULONG nIndex);

/* Gadget pool for indirect syscalls */
/* L5: engine.h declares uintptr_t, mirage_asm.h declares uint64_t.
 * Both are 8 bytes on x86_64 Win — safe as-is. Migrate both to uintptr_t if targeting x86. */
extern uintptr_t gadget_pool[64];
int mirage_init_gadget_pool(void);

#endif /* ENGINE_H */
