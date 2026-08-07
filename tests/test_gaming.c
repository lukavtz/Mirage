/*
 * test_gaming.c — Gaming module: depth limit, launcher table, name matching
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_gaming tests/test_gaming.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ── Inline launcher table from gaming.c ──────────────────── */

static const struct {
    const char *name;
    const char *subdir;
    const char *relative;
} mc_launchers[] = {
    { "TLauncher",        ".tlauncher",        "minecraft" },
    { "Lunar Client",     ".lunarclient",      "offline" },
    { "Feather",          ".feather",           "minecraft" },
    { "Badlion",          ".badlion",           "minecraft" },
    { "PolyMC",           "PolyMC",             "minecraft" },
    { "Prism",            "PrismLauncher",      "minecraft" },
    { "MultiMC",          "MultiMC",            "minecraft" },
    { "ATLauncher",       "ATLauncher",         "minecraft" },
    { "GDLauncher",       "GDLauncher",         "minecraft" },
    { "HMCL",             "HMCL",               ".minecraft" },
    { "SKlauncher",       "SKlauncher",         "minecraft" },
    { "Technic",          "technic",            "minecraft" },
    { "Crystal",          "crystal-launcher",   "minecraft" },
    { "Salwyrr",          "SalwyrrLauncher",    "minecraft" },
    { "Pojav",            "PojavLauncher",      "minecraft" },
    { "CKPack",           "ckpack",             "minecraft" },
    { "Novoline",         "novoline",           "versions" },
    { "MagicLauncher",    "MagicLauncher",      "minecraft" },
};
#define MC_LAUNCHER_COUNT (sizeof(mc_launchers) / sizeof(mc_launchers[0]))

/* ── Depth limit simulation ──────────────────────────────── */

static int max_depth_reached;

static void copy_dir_sim(const char *src, const char *dst, int depth) {
    (void)src; (void)dst;
    if (depth > 16) return;
    if (depth > max_depth_reached) max_depth_reached = depth;
    copy_dir_sim(src, dst, depth + 1);
}

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_launcher_count(void) {
    assert(MC_LAUNCHER_COUNT == 18);
}

static void test_launcher_names_unique(void) {
    for (size_t i = 0; i < MC_LAUNCHER_COUNT; i++) {
        for (size_t j = i + 1; j < MC_LAUNCHER_COUNT; j++) {
            assert(strcmp(mc_launchers[i].name, mc_launchers[j].name) != 0);
        }
    }
}

static void test_launcher_subdirs_unique(void) {
    for (size_t i = 0; i < MC_LAUNCHER_COUNT; i++) {
        for (size_t j = i + 1; j < MC_LAUNCHER_COUNT; j++) {
            assert(strcmp(mc_launchers[i].subdir, mc_launchers[j].subdir) != 0);
        }
    }
}

static void test_launcher_no_nulls(void) {
    for (size_t i = 0; i < MC_LAUNCHER_COUNT; i++) {
        assert(mc_launchers[i].name != NULL);
        assert(mc_launchers[i].subdir != NULL);
        assert(mc_launchers[i].relative != NULL);
    }
}

static void test_launcher_path_construction(void) {
    /* Verify path construction: %APPDATA%\\<subdir>\\<relative> */
    char path[512];
    snprintf(path, sizeof(path), "%s\\%s\\%s", "C:\\Users\\test\\AppData\\Roaming",
             mc_launchers[0].subdir, mc_launchers[0].relative);
    assert(strcmp(path, "C:\\Users\\test\\AppData\\Roaming\\.tlauncher\\minecraft") == 0);
}

static void test_launcher_special_cases(void) {
    /* HMCL uses ".minecraft" not "minecraft" */
    assert(strcmp(mc_launchers[9].relative, ".minecraft") == 0);
    /* Novoline uses "versions" not "minecraft" */
    assert(strcmp(mc_launchers[16].relative, "versions") == 0);
    /* Lunar Client uses "offline" */
    assert(strcmp(mc_launchers[1].relative, "offline") == 0);
}

static void test_depth_limit_at_16(void) {
    max_depth_reached = -1;
    copy_dir_sim("src", "dst", 0);
    assert(max_depth_reached == 16);
}

static void test_depth_limit_exceeded(void) {
    max_depth_reached = -1;
    copy_dir_sim("src", "dst", 17);
    assert(max_depth_reached == -1); /* returns immediately */
}

static void test_depth_limit_at_boundary(void) {
    max_depth_reached = -1;
    copy_dir_sim("src", "dst", 16);
    assert(max_depth_reached == 16);
}

int main(void) {
    test_launcher_count();
    test_launcher_names_unique();
    test_launcher_subdirs_unique();
    test_launcher_no_nulls();
    test_launcher_path_construction();
    test_launcher_special_cases();
    test_depth_limit_at_16();
    test_depth_limit_exceeded();
    test_depth_limit_at_boundary();
    printf("test_gaming: ALL PASSED\n");
    return 0;
}
