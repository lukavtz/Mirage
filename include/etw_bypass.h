/*
 * etw_bypass.h — ETW bypass for Mirage-C
 *
 * Patches ntdll!EtwEventWrite (or EtwEventWriteEx as fallback)
 * to return immediately, preventing Event Tracing for Windows
 * from logging ETW events from this process.
 */

#ifndef MIRAGE_ETW_BYPASS_H
#define MIRAGE_ETW_BYPASS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_patch_etw — Patch EtwEventWrite in ntdll.dll.
 *
 * Resolves EtwEventWrite by hash from ntdll. Falls back to
 * EtwEventWriteEx if EtwEventWrite is not found. Patches the
 * first byte with 0xC3 (ret) via NtProtectVirtualMemory.
 *
 * Returns 1 on success, 0 on failure.
 */
int mirage_patch_etw(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_ETW_BYPASS_H */
