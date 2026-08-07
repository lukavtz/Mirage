/*
 * test_keylogger.c — Keylogger special_key_name + circular buffer tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_keylogger tests/test_keylogger.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define VK_BACK    0x08
#define VK_TAB     0x09
#define VK_RETURN  0x0D
#define VK_SHIFT   0x10
#define VK_CONTROL 0x11
#define VK_MENU    0x12
#define VK_CAPITAL 0x14
#define VK_ESCAPE  0x1B
#define VK_DELETE  0x2E
#define VK_LWIN    0x5B
#define VK_RWIN    0x5C

#define KEYLOG_BUFFER_SIZE 65536

typedef unsigned int DWORD;

static const char *special_key_name(DWORD vk) {
    switch (vk) {
    case VK_BACK:    return "[BACK]";
    case VK_TAB:     return "[TAB]";
    case VK_RETURN:  return "[ENTER]";
    case VK_ESCAPE:  return "[ESC]";
    case VK_DELETE:  return "[DEL]";
    case 0x21:       return "[PGUP]";
    case 0x22:       return "[PGDN]";
    case 0x23:       return "[END]";
    case 0x24:       return "[HOME]";
    case 0x25:       return "[LEFT]";
    case 0x26:       return "[UP]";
    case 0x27:       return "[RIGHT]";
    case 0x28:       return "[DOWN]";
    case 0x2C:       return "[PRTSC]";
    case 0x2D:       return "[INS]";
    case 0x70: return "[F1]";
    case 0x71: return "[F2]";
    case 0x72: return "[F3]";
    case 0x73: return "[F4]";
    case 0x74: return "[F5]";
    case 0x75: return "[F6]";
    case 0x76: return "[F7]";
    case 0x77: return "[F8]";
    case 0x78: return "[F9]";
    case 0x79: return "[F10]";
    case 0x7A: return "[F11]";
    case 0x7B: return "[F12]";
    case VK_SHIFT:
    case VK_CONTROL:
    case VK_MENU:
    case VK_CAPITAL:
    case VK_LWIN:
    case VK_RWIN:
        return NULL;
    default:
        return NULL;
    }
}

/* ── Circular buffer ─────────────────────────────────────── */

static char            g_buf[KEYLOG_BUFFER_SIZE];
static volatile size_t g_head;
static volatile size_t g_tail;

static void buf_reset(void) { g_head = 0; g_tail = 0; }

static void buf_write(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        g_buf[g_head] = data[i];
        g_head = (g_head + 1) % KEYLOG_BUFFER_SIZE;
        if (g_head == g_tail)
            g_tail = (g_tail + 1) % KEYLOG_BUFFER_SIZE;
    }
}

static size_t buf_readable(void) {
    if (g_head >= g_tail) return g_head - g_tail;
    return KEYLOG_BUFFER_SIZE - g_tail + g_head;
}

static void buf_read(char *out, size_t max) {
    size_t n = 0;
    while (g_tail != g_head && n < max) {
        out[n++] = g_buf[g_tail];
        g_tail = (g_tail + 1) % KEYLOG_BUFFER_SIZE;
    }
    if (n < max) out[n] = '\0';
}

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_special_keys_navigation(void) {
    assert(strcmp(special_key_name(VK_BACK), "[BACK]") == 0);
    assert(strcmp(special_key_name(VK_TAB), "[TAB]") == 0);
    assert(strcmp(special_key_name(VK_RETURN), "[ENTER]") == 0);
    assert(strcmp(special_key_name(VK_ESCAPE), "[ESC]") == 0);
    assert(strcmp(special_key_name(VK_DELETE), "[DEL]") == 0);
    assert(strcmp(special_key_name(0x21), "[PGUP]") == 0);
    assert(strcmp(special_key_name(0x22), "[PGDN]") == 0);
    assert(strcmp(special_key_name(0x23), "[END]") == 0);
    assert(strcmp(special_key_name(0x24), "[HOME]") == 0);
    assert(strcmp(special_key_name(0x25), "[LEFT]") == 0);
    assert(strcmp(special_key_name(0x26), "[UP]") == 0);
    assert(strcmp(special_key_name(0x27), "[RIGHT]") == 0);
    assert(strcmp(special_key_name(0x28), "[DOWN]") == 0);
    assert(strcmp(special_key_name(0x2C), "[PRTSC]") == 0);
    assert(strcmp(special_key_name(0x2D), "[INS]") == 0);
}

static void test_special_keys_function(void) {
    assert(strcmp(special_key_name(0x70), "[F1]") == 0);
    assert(strcmp(special_key_name(0x75), "[F6]") == 0);
    assert(strcmp(special_key_name(0x7B), "[F12]") == 0);
}

static void test_special_keys_modifiers_null(void) {
    assert(special_key_name(VK_SHIFT) == NULL);
    assert(special_key_name(VK_CONTROL) == NULL);
    assert(special_key_name(VK_MENU) == NULL);
    assert(special_key_name(VK_CAPITAL) == NULL);
    assert(special_key_name(VK_LWIN) == NULL);
    assert(special_key_name(VK_RWIN) == NULL);
}

static void test_special_keys_unknown(void) {
    assert(special_key_name(0x00) == NULL);
    assert(special_key_name(0x41) == NULL);
    assert(special_key_name(0xFF) == NULL);
    assert(special_key_name(0x7C) == NULL);
}

static void test_buf_basic(void) {
    buf_reset();
    buf_write("ABC", 3);
    char out[16] = {0};
    buf_read(out, sizeof(out));
    assert(strcmp(out, "ABC") == 0);
}

static void test_buf_empty(void) {
    buf_reset();
    assert(buf_readable() == 0);
}

static void test_buf_overflow(void) {
    buf_reset();
    /* Fill entire buffer (65535 effective slots due to circular design) */
    char data[KEYLOG_BUFFER_SIZE];
    memset(data, 'A', sizeof(data));
    buf_write(data, KEYLOG_BUFFER_SIZE);
    /* After filling, the circular buffer keeps 65535 bytes (head==tail triggers advance) */
    assert(buf_readable() == KEYLOG_BUFFER_SIZE - 1);
    /* Write one more byte — oldest gets overwritten */
    buf_write("!", 1);
    assert(buf_readable() == KEYLOG_BUFFER_SIZE - 1);
}

static void test_buf_partial_read(void) {
    buf_reset();
    buf_write("HelloWorld", 10);
    char out[6] = {0};
    buf_read(out, 5);
    assert(strcmp(out, "Hello") == 0);
    assert(buf_readable() == 5);
    buf_read(out, 5);
    assert(strcmp(out, "World") == 0);
}

static void test_buf_incremental(void) {
    buf_reset();
    buf_write("A", 1);
    buf_write("B", 1);
    buf_write("C", 1);
    assert(buf_readable() == 3);
    char out[4] = {0};
    buf_read(out, sizeof(out));
    assert(strcmp(out, "ABC") == 0);
}

static void test_buf_size(void) {
    assert(KEYLOG_BUFFER_SIZE == 65536);
}

int main(void) {
    test_special_keys_navigation();
    test_special_keys_function();
    test_special_keys_modifiers_null();
    test_special_keys_unknown();
    test_buf_basic();
    test_buf_empty();
    test_buf_overflow();
    test_buf_partial_read();
    test_buf_incremental();
    test_buf_size();
    printf("test_keylogger: ALL PASSED\n");
    return 0;
}
