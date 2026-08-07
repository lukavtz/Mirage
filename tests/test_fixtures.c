/*
 * test_fixtures.c -- Fabricated SQLite DB fixtures
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc/parsers -std=c11 \
 *        -o tests/test_fixtures tests/test_fixtures.c src/parsers/sqlite.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite.h"

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/*
 * Build a test DB following exact pattern from test_sqlite.c:
 * - page_size=1024, 2 pages
 * - Page 1: SQLite header (0-99) + sqlite_master btree (100+)
 * - Page 2: data btree with nrows
 * - Manual SqliteDb setup (skip sqlite_open)
 */
static void build_test_db(SqliteDb *sdb, unsigned char **out_db, size_t *out_len,
                           const char *table_name, const char *create_sql,
                           const char **row_data, int nrows, int ncols) {
    const int page_size = 1024;
    size_t total = page_size * 2;
    unsigned char *db = calloc(1, total);
    assert(db);

    /* Page 1: SQLite header + sqlite_master btree */
    memcpy(db, "SQLite format 3\0", 16);
    db[16] = (page_size >> 8) & 0xFF; db[17] = page_size & 0xFF;

    /* Btree header at offset 100 */
    unsigned char *bt1 = db + 100;
    bt1[0] = 0x0d;  /* leaf table */
    bt1[3] = 0; bt1[4] = 1;  /* 1 cell */

    /* Build sqlite_master cell */
    const char *type_str = "table";
    int type_len = (int)strlen(type_str);
    int name_len = (int)strlen(table_name);
    int sql_len = (int)strlen(create_sql);

    int st_type = 13 + type_len * 2;
    int st_name = 13 + name_len * 2;
    int st_tbl  = 13 + name_len * 2;
    int st_rp   = 1;
    int st_sql  = 13 + sql_len * 2;

    int hdr_size = 1 + 1 + 1 + 1 + 1 + 2;
    int payload_size = hdr_size + type_len + name_len + name_len + 1 + sql_len;

    unsigned char cell[512];
    int cpos = 0;
    /* Cell format: payload_size, rowid, header, serials, data */
    cell[cpos++] = (unsigned char)payload_size;
    cell[cpos++] = 1;  /* rowid */
    cell[cpos++] = (unsigned char)hdr_size;
    cell[cpos++] = (unsigned char)st_type;
    cell[cpos++] = (unsigned char)st_name;
    cell[cpos++] = (unsigned char)st_tbl;
    cell[cpos++] = (unsigned char)st_rp;
    /* st_sql varint (may be >127) */
    if (st_sql < 128) {
        cell[cpos++] = (unsigned char)st_sql;
    } else {
        cell[cpos++] = (unsigned char)(0x80 | (st_sql >> 7));
        cell[cpos++] = (unsigned char)(st_sql & 0x7F);
    }
    memcpy(cell + cpos, type_str, type_len); cpos += type_len;
    memcpy(cell + cpos, table_name, name_len); cpos += name_len;
    memcpy(cell + cpos, table_name, name_len); cpos += name_len;
    cell[cpos++] = 2;  /* rootpage */
    memcpy(cell + cpos, create_sql, sql_len); cpos += sql_len;

    int cell_off = page_size - cpos;
    memcpy(db + cell_off, cell, cpos);

    /* Cell pointer and content area in btree header */
    bt1[5] = (cell_off >> 8) & 0xFF; bt1[6] = cell_off & 0xFF;
    bt1[8] = (cell_off >> 8) & 0xFF; bt1[9] = cell_off & 0xFF;

    /* Page 2: data btree */
    unsigned char *p2 = db + page_size;
    p2[0] = 0x0d;
    p2[3] = (nrows >> 8) & 0xFF; p2[4] = nrows & 0xFF;

    /* Build data cells */
    unsigned char cells[8][256];
    int csizes[8];
    int total_cell_size = 0;

    for (int r = 0; r < nrows && r < 8; r++) {
        int cpos2 = 0;
        /* Calculate payload */
        int phdr = 1; /* header size byte */
        int pdata = 0;
        for (int c = 0; c < ncols; c++) {
            int idx = r * ncols + c;
            int len = (int)strlen(row_data[idx]);
            phdr += (len * 2 + 13 < 128) ? 1 : 2;
            pdata += len;
        }
        int pay_sz = phdr + pdata;

        /* Cell: payload_size, rowid, header, serials, data */
        if (pay_sz < 128) cells[r][cpos2++] = (unsigned char)pay_sz;
        else { cells[r][cpos2++] = (unsigned char)(0x80 | (pay_sz >> 7)); cells[r][cpos2++] = (unsigned char)(pay_sz & 0x7F); }
        cells[r][cpos2++] = (unsigned char)(r + 1);  /* rowid */
        cells[r][cpos2++] = (unsigned char)phdr;
        for (int c = 0; c < ncols; c++) {
            int idx = r * ncols + c;
            int len = (int)strlen(row_data[idx]);
            int st = 13 + len * 2;
            if (st < 128) cells[r][cpos2++] = (unsigned char)st;
            else { cells[r][cpos2++] = (unsigned char)(0x80 | (st >> 7)); cells[r][cpos2++] = (unsigned char)(st & 0x7F); }
        }
        for (int c = 0; c < ncols; c++) {
            int idx = r * ncols + c;
            int len = (int)strlen(row_data[idx]);
            memcpy(cells[r] + cpos2, row_data[idx], len);
            cpos2 += len;
        }
        csizes[r] = cpos2;
        total_cell_size += cpos2;
    }

    /* Place cells at end of page 2, packed */
    int cursor = page_size;
    for (int r = nrows - 1; r >= 0; r--) {
        cursor -= csizes[r];
        memcpy(p2 + cursor, cells[r], csizes[r]);
    }
    int first_cell = cursor;

    /* Write cell pointers at p2+8 */
    cursor = first_cell;
    for (int r = 0; r < nrows; r++) {
        p2[8 + r * 2] = (cursor >> 8) & 0xFF;
        p2[8 + r * 2 + 1] = cursor & 0xFF;
        cursor += csizes[r];
    }

    /* Cell content area */
    p2[5] = (first_cell >> 8) & 0xFF;
    p2[6] = first_cell & 0xFF;

    /* Manual SqliteDb setup */
    memset(sdb, 0, sizeof(*sdb));
    sdb->data = db;
    sdb->len = total;
    sdb->page_size = page_size;

    *out_db = db;
    *out_len = total;
}

int main(void) {
    int passed = 0, failed = 0;
    printf("=== test_fixtures: Fabricated SQLite DB fixtures ===\n");

    /* Test 1: Chrome Login Data (3 rows) */
    {
        const char *vals[] = {
            "https://example.com", "user1", "enc_pass1",
            "https://test.org",    "user2", "enc_pass2",
            "https://foo.bar",     "user3", "enc_pass3",
        };
        unsigned char *db; size_t sz; SqliteDb sdb;
        build_test_db(&sdb, &db, &sz, "logins",
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT)",
            vals, 3, 3);
        SqliteRow *rows = NULL; size_t count = 0;
        int rc = sqlite_read_table(&sdb, "logins", &rows, &count);
        if (rc == 0 && count == 3) TEST("chrome_login row count");
        else { char m[64]; snprintf(m,64,"expected 3, got %zu (rc=%d)", count, rc); FAIL("chrome_login", m); }
        sqlite_free_rows(rows, count); free(db);
    }

    /* Test 2: Chrome Cookies (5 rows) */
    {
        const char *vals[] = {
            ".example.com", "sid", "abc",
            ".example.com", "theme", "dark",
            ".test.org",    "tok", "x",
            ".foo.bar",     "lang", "en",
            ".foo.bar",     "p", "y",
        };
        unsigned char *db; size_t sz; SqliteDb sdb;
        build_test_db(&sdb, &db, &sz, "cookies",
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT)",
            vals, 5, 3);
        SqliteRow *rows = NULL; size_t count = 0;
        int rc = sqlite_read_table(&sdb, "cookies", &rows, &count);
        if (rc == 0 && count == 5) TEST("cookie row count");
        else { char m[64]; snprintf(m,64,"expected 5, got %zu (rc=%d)", count, rc); FAIL("cookies", m); }
        sqlite_free_rows(rows, count); free(db);
    }

    /* Test 3: verify column values */
    {
        const char *vals[] = {"http://example.com", "user1", "pass1"};
        unsigned char *db; size_t sz; SqliteDb sdb;
        build_test_db(&sdb, &db, &sz, "logins",
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT)",
            vals, 1, 3);
        SqliteRow *rows = NULL; size_t count = 0;
        int rc = sqlite_read_table(&sdb, "logins", &rows, &count);
        if (rc == 0 && count == 1 && rows[0].count >= 3 &&
            rows[0].values[0].type == SQLITE_VAL_TEXT &&
            memcmp(rows[0].values[0].as.text.ptr, "http://example.com",
                   rows[0].values[0].as.text.len) == 0) {
            TEST("column value extraction");
        } else {
            FAIL("column value extraction", "wrong value or type");
        }
        sqlite_free_rows(rows, count); free(db);
    }

    /* Test 4: table not found */
    {
        const char *vals[] = {"x"};
        unsigned char *db; size_t sz; SqliteDb sdb;
        build_test_db(&sdb, &db, &sz, "real_table",
            "CREATE TABLE real_table (a TEXT)", vals, 1, 1);
        SqliteRow *rows = NULL; size_t count = 0;
        int rc = sqlite_read_table(&sdb, "nonexistent", &rows, &count);
        if (rc != 0 || count == 0) TEST("table_not_found");
        else FAIL("table_not_found", "expected failure");
        sqlite_free_rows(rows, count); free(db);
    }

    /* Test 5: free_rows NULL */
    {
        sqlite_free_rows(NULL, 0);
        TEST("free_rows NULL no crash");
    }

    printf("=== test_fixtures: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
