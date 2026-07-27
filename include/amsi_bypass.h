/*
 * amsi_bypass.h — AMSI bypass for Mirage-C
 *
 * Patches amsi.dll!AmsiScanBuffer to return immediately (ret 0xC3).
 * Uses NtProtectVirtualMemory to make the function writable,
 * overwrites the first byte with 0xC3, then restores protection.
 */

#ifndef MIRAGE_AMSI_BYPASS_H
#define MIRAGE_AMSI_BYPASS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_patch_amsi — Patch AmsiScanBuffer in amsi.dll.
 *
 * Loads amsi.dll via PEB walk, resolves AmsiScanBuffer by hash,
 * changes page protection to RWX, writes 0xC3 (ret) as the first
 * instruction, flushes instruction cache, and restores protection.
 *
 * Returns 1 on success, 0 on failure.
 */
int mirage_patch_amsi(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_AMSI_BYPASS_H */
