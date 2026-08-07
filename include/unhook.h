/*
 * unhook.h — NTDLL .text unhooking for Mirage-C
 *
 * Restores clean .text from disk-based ntdll.dll into the in-memory
 * ntdll module before syscall resolution, defeating userland hooks.
 *
 * Must be called BEFORE mirage_syscall_resolve().
 */
#ifndef MIRAGE_UNHOOK_H
#define MIRAGE_UNHOOK_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * unhook_ntdll — Restore ntdll.dll .text from a fresh copy.
 *
 * Two-path approach:
 *   1. NtOpenSection on \\KnownDlls\\ntdll.dll (kernel section object)
 *   2. Fallback: NtCreateFile → NtCreateSection → NtMapViewOfSection
 *
 * Backs up original bytes internally for restore_ntdll().
 *
 * Returns 1 on success, 0 on failure.
 */
int unhook_ntdll(void);

/*
 * restore_ntdll — Revert .text to the bytes saved by unhook_ntdll().
 *
 * No-op if unhook_ntdll() was never called or succeeded.
 */
void restore_ntdll(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_UNHOOK_H */
