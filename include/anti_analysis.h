/*
 * anti_analysis.h — Weighted scoring gate for anti-analysis for Mirage-C
 *
 * Direct translation of Zig src/evasion/anti_analysis.zig.
 * Aggregates all evasion checks into a weighted score and decides
 * whether to exit (analysis environment detected).
 */

#ifndef MIRAGE_ANTI_ANALYSIS_H
#define MIRAGE_ANTI_ANALYSIS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Analysis flags (bitfield) ───────────────────────────── */
typedef struct {
    uint32_t ram_low         : 1;
    uint32_t cpu_few         : 1;
    uint32_t vm_registry     : 1;
    uint32_t timing_anomaly  : 1;
    uint32_t debugger        : 1;
    uint32_t small_screen    : 1;
    uint32_t process_list    : 1;
    uint32_t disk_small      : 1;
    uint32_t uptime_low      : 1;
    uint32_t mouse_static    : 1;
    uint32_t geo_cis         : 1;
    uint32_t hosting_ip      : 1;
    uint32_t _unused         : 20;
} mirage_analysis_flags;

/* ── Analysis result ─────────────────────────────────────── */
typedef struct {
    uint32_t            score;
    mirage_analysis_flags flags;
} mirage_analysis_result;

/*
 * mirage_anti_analysis_run — Execute all evasion checks and compute score.
 * Returns populated result struct.
 */
mirage_analysis_result mirage_anti_analysis_run(void);

/*
 * mirage_anti_analysis_should_exit — Check if score exceeds threshold.
 * Returns 1 if should exit, 0 if safe to continue.
 */
int mirage_anti_analysis_should_exit(mirage_analysis_result result);

/*
 * mirage_anti_analysis_print — Print score and detected flags.
 */
void mirage_anti_analysis_print(mirage_analysis_result result);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_ANTI_ANALYSIS_H */
