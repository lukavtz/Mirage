/*
 * test_sqlite_fault.c -- SQLite fault injection tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc/parsers -std=c11 \
 *        -o tests/test_sqlite_fault tests/test_sqlite_fault.c src/parsers/sqlite.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite.h"

#define TEST(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); g_failed++; } while(0)

/* Helper: expect sqlite_open to fail */
static int g_passed = 0, g_failed = 0;

static int expect_open_fail(const unsigned char *buf, size_t len, const char *label) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, buf, len);
    if (rc != 0) { TEST(label); return 0; }
    FAIL(label, "expected open to fail");
    sqlite_close(&sdb);
    return 1;
}

/* Helper: expect read_table to fail after successful open */
static int expect_read_fail(const unsigned char *buf, size_t len, const char *label) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, buf, len);
    if (rc != 0) { TEST(label); return 0; }
    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "test", &rows, &count);
    if (rc != 0 || count == 0) { TEST(label); sqlite_free_rows(rows, count); sqlite_close(&sdb); return 0; }
    FAIL(label, "expected read_table to fail");
    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
    return 1;
}

int main(void) {
    printf("=== test_sqlite_fault: SQLite fault injection ===\n");

    /* 1. Truncated header (< 100 bytes) */
    {
        unsigned char buf[50]; memset(buf, 0, 50);
        memcpy(buf, "SQLite format 3\0", 16);
        expect_open_fail(buf, 50, "truncated_header rejects");
    }

    /* 2. Zero-filled buffer */
    {
        unsigned char buf[1024]; memset(buf, 0, 1024);
        expect_open_fail(buf, 1024, "zero_filled rejects");
    }

    /* 3. Invalid page size (0) */
    {
        unsigned char buf[4096]; memset(buf, 0, 4096);
        memcpy(buf, "SQLite format 3\0", 16);
        buf[16]=0; buf[17]=0;
        expect_read_fail(buf, 4096, "page_size_zero rejects");
    }

    /* 4. Invalid page size (3 - not power of 2) */
    {
        unsigned char buf[4096]; memset(buf, 0, 4096);
        memcpy(buf, "SQLite format 3\0", 16);
        buf[16]=0; buf[17]=3;
        expect_read_fail(buf, 4096, "page_size_three rejects");
    }

    /* 5. Corrupted page type (0xFF) */
    {
        unsigned char buf[4096]; memset(buf, 0, 4096);
        memcpy(buf, "SQLite format 3\0", 16);
        buf[16]=0x10; buf[17]=0; buf[18]=1; buf[19]=1;
        buf[21]=64; buf[22]=32; buf[23]=32;
        buf[100]=0xFF;
        expect_read_fail(buf, 4096, "corrupted_page_type rejects");
    }

    /* 6. NULL buffer */
    {
        SqliteDb sdb;
        int rc = sqlite_open(&sdb, NULL, 100);
        if (rc != 0) TEST("null_buffer rejects");
        else { FAIL("null_buffer", "expected fail"); sqlite_close(&sdb); }
    }

    /* 7. Zero size */
    {
        unsigned char buf[1] = {0};
        SqliteDb sdb;
        int rc = sqlite_open(&sdb, buf, 0);
        if (rc != 0) TEST("zero_size rejects");
        else { FAIL("zero_size", "expected fail"); sqlite_close(&sdb); }
    }

    /* 8. Random garbage */
    {
        unsigned char buf[4096];
        unsigned int seed = 0xDEADBEEF;
        for (size_t i = 0; i < 4096; i++) { seed = seed*1103515245+12345; buf[i]=(unsigned char)(seed>>16); }
        expect_open_fail(buf, 4096, "random_garbage rejects");
    }

    /* 9. Double close safety */
    {
        SqliteDb sdb;
        memset(&sdb, 0, sizeof(sdb));
        sqlite_close(&sdb);
        sqlite_close(&sdb);
        TEST("double_close no crash");
    }

    /* 10. free_rows NULL safety */
    {
        sqlite_free_rows(NULL, 0);
        sqlite_free_rows(NULL, 0);
        TEST("double_free_rows no crash");
    }

    printf("=== test_sqlite_fault: %d/%d PASSED ===\n", g_passed, g_passed + g_failed);
    return g_failed ? 1 : 0;
}
