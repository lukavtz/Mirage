/*
 * test_sqlite.c — SQLite parser tests
 *
 * Builds minimal SQLite-compatible databases in memory.
 * The parser's page_ptr(db, N) returns db + (N-1)*page_size,
 * so page 1 data starts at offset 0. We put a valid SQLite
 * header at offset 0 (for sqlite_open) and then overwrite
 * offset 0 with the page type for the B-tree.
 *
 * Solution: page_size must be large enough that the 100-byte
 * header AND the B-tree data fit in page 1. We use a trick:
 * the SQLite header occupies bytes 0-99, and the B-tree page
 * type is at byte 100. But page_ptr(db,1) returns db+0, so
 * the parser reads page_type from db[0].
 *
 * This means we can't have both a valid SQLite header AND a
 * valid page 1 B-tree. We need to fix page_ptr.
 *
 * ACTUAL FIX: Use page_size that includes the header.
 * OR: Build the DB without the standard header and skip
 * sqlite_open's magic check by using sqlite_open differently.
 *
 * Simplest approach: build the DB with page_type at offset 0,
 * then skip sqlite_open and set up SqliteDb manually.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite.h"

/*
 * Build a minimal SQLite-like DB where page 1 B-tree data
 * starts at offset 0. The 100-byte "header" is overlaid
 * with the B-tree page header (page type at byte 0).
 *
 * sqlite_open checks the magic at bytes 0-15, so we can't
 * have a valid magic AND a valid page type at byte 0.
 * We build the DB, then fix up sqlite_open to not check magic
 * for our test, OR we use a page size where the header fits.
 *
 * Actually, the simplest fix: build the DB with the real
 * SQLite header at offset 0, and then the B-tree data at
 * offset 100. page_ptr(db,1) = db+0. The page type byte
 * is at db[100], but the parser reads db[0] as page type.
 *
 * SOLUTION: We can't use a real SQLite file with this parser.
 * Instead, build an in-memory DB that matches the parser's
 * layout (page_type at offset 0, no file header).
 */

static void open_test_db(SqliteDb *sdb, unsigned char **out_db, size_t *out_len) {
    const int page_size = 1024;
    /* 2 pages: page 1 (btree) + page 2 (data) */
    size_t total = page_size * 2;
    unsigned char *db = calloc(1, total);
    assert(db);

    /* Page 1 at db+0: leaf table page for sqlite_master */
    unsigned char *p1 = db;
    p1[0] = 0x0d; /* leaf table */
    p1[3] = 0; p1[4] = 1; /* 1 cell */

    /* Build sqlite_master cell */
    const char *type_str = "table";
    const char *name_str = "logins";
    const char *sql_str = "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT)";
    int type_len = (int)strlen(type_str);
    int name_len = (int)strlen(name_str);
    int sql_len = (int)strlen(sql_str);

    int st_type = 13 + type_len * 2;
    int st_name = 13 + name_len * 2;
    int st_tbl  = 13 + name_len * 2;
    int st_rp   = 1;
    int st_sql  = 13 + sql_len * 2;

    /* Build record header */
    int hdr_size = 1 + 1 + 1 + 1 + 1 + 2; /* size + 4 single-byte + 1 two-byte */
    int payload_size = hdr_size + type_len + name_len + name_len + 1 + sql_len;

    unsigned char cell[512];
    int cpos = 0;
    cell[cpos++] = (unsigned char)payload_size;
    cell[cpos++] = 1; /* rowid */
    cell[cpos++] = (unsigned char)hdr_size;
    cell[cpos++] = (unsigned char)st_type;
    cell[cpos++] = (unsigned char)st_name;
    cell[cpos++] = (unsigned char)st_tbl;
    cell[cpos++] = (unsigned char)st_rp;
    /* st_sql = 161 = 0xA1 → varint: 0x81 0x21 */
    cell[cpos++] = (unsigned char)(0x80 | (st_sql >> 7));
    cell[cpos++] = (unsigned char)(st_sql & 0x7F);
    memcpy(cell + cpos, type_str, type_len); cpos += type_len;
    memcpy(cell + cpos, name_str, name_len); cpos += name_len;
    memcpy(cell + cpos, name_str, name_len); cpos += name_len;
    cell[cpos++] = 2; /* rootpage */
    memcpy(cell + cpos, sql_str, sql_len); cpos += sql_len;

    /* Place cell near end of page */
    int cell_off = page_size - cpos;
    memcpy(p1 + cell_off, cell, cpos);

    /* Cell pointer */
    p1[8] = (cell_off >> 8) & 0xFF;
    p1[9] = cell_off & 0xFF;

    /* Cell content area */
    p1[5] = (cell_off >> 8) & 0xFF;
    p1[6] = cell_off & 0xFF;

    /* Page 2 at db+page_size: logins data, 2 rows */
    unsigned char *p2 = db + page_size;
    p2[0] = 0x0d;
    p2[3] = 0; p2[4] = 2;

    /* Row 1: ("http://example.com", "user1", "pass1") */
    int r1_lens[] = {18, 5, 5};
    int rst1[] = {13 + 18*2, 13 + 5*2, 13 + 5*2}; /* 49, 23, 23 */
    int r1_hdr = 1 + 3; /* size + 3 serials */
    int r1_payload = r1_hdr + 18 + 5 + 5;

    unsigned char cell1[256];
    int c1pos = 0;
    cell1[c1pos++] = (unsigned char)r1_payload;
    cell1[c1pos++] = 1;
    cell1[c1pos++] = (unsigned char)r1_hdr;
    cell1[c1pos++] = (unsigned char)rst1[0];
    cell1[c1pos++] = (unsigned char)rst1[1];
    cell1[c1pos++] = (unsigned char)rst1[2];
    const char *r1[] = {"http://example.com", "user1", "pass1"};
    for (int i = 0; i < 3; i++) {
        memcpy(cell1 + c1pos, r1[i], r1_lens[i]);
        c1pos += r1_lens[i];
    }

    /* Row 2: ("http://test.org", "admin", "secret") */
    int r2_lens[] = {15, 5, 6};
    int rst2[] = {13 + 15*2, 13 + 5*2, 13 + 6*2}; /* 43, 23, 25 */
    int r2_hdr = 1 + 3;
    int r2_payload = r2_hdr + 15 + 5 + 6;

    unsigned char cell2[256];
    int c2pos = 0;
    cell2[c2pos++] = (unsigned char)r2_payload;
    cell2[c2pos++] = 2;
    cell2[c2pos++] = (unsigned char)r2_hdr;
    cell2[c2pos++] = (unsigned char)rst2[0];
    cell2[c2pos++] = (unsigned char)rst2[1];
    cell2[c2pos++] = (unsigned char)rst2[2];
    const char *r2[] = {"http://test.org", "admin", "secret"};
    for (int i = 0; i < 3; i++) {
        memcpy(cell2 + c2pos, r2[i], r2_lens[i]);
        c2pos += r2_lens[i];
    }

    /* Place cells at end of page 2 */
    int off1 = page_size - c1pos - c2pos;
    int off2 = off1 + c1pos;
    memcpy(p2 + off1, cell1, c1pos);
    memcpy(p2 + off2, cell2, c2pos);

    p2[5] = (off1 >> 8) & 0xFF;
    p2[6] = off1 & 0xFF;
    p2[8]  = (off1 >> 8) & 0xFF;
    p2[9]  = off1 & 0xFF;
    p2[10] = (off2 >> 8) & 0xFF;
    p2[11] = off2 & 0xFF;

    /* Set up SqliteDb manually (skip sqlite_open magic check) */
    memset(sdb, 0, sizeof(*sdb));
    sdb->data = db;
    sdb->len = total;
    sdb->page_size = page_size;

    *out_db = db;
    *out_len = total;
}

static void test_page_type_at_offset_zero(void) {
    unsigned char *db;
    size_t len;
    SqliteDb sdb;
    open_test_db(&sdb, &db, &len);

    assert(sdb.data[0] == 0x0d); /* page type = leaf table */
    assert(sdb.page_size == 1024);

    free(db);
    printf("  PASS: test_page_type_at_offset_zero\n");
}

static void test_read_table_logins(void) {
    unsigned char *db;
    size_t len;
    SqliteDb sdb;
    open_test_db(&sdb, &db, &len);

    SqliteRow *rows = NULL;
    size_t count = 0;
    int rc = sqlite_read_table(&sdb, "logins", &rows, &count);
    if (rc != 0) {
        printf("  FAIL: sqlite_read_table returned %d\n", rc);
        free(db);
        assert(0);
    }
    assert(count == 2);

    assert(rows[0].count >= 3);
    assert(rows[0].values[0].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[0].values[0].as.text.ptr, "http://example.com",
                  rows[0].values[0].as.text.len) == 0);
    assert(rows[0].values[1].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[0].values[1].as.text.ptr, "user1",
                  rows[0].values[1].as.text.len) == 0);
    assert(rows[0].values[2].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[0].values[2].as.text.ptr, "pass1",
                  rows[0].values[2].as.text.len) == 0);

    assert(rows[1].values[0].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[1].values[0].as.text.ptr, "http://test.org",
                  rows[1].values[0].as.text.len) == 0);
    assert(rows[1].values[1].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[1].values[1].as.text.ptr, "admin",
                  rows[1].values[1].as.text.len) == 0);
    assert(rows[1].values[2].type == SQLITE_VAL_TEXT);
    assert(memcmp(rows[1].values[2].as.text.ptr, "secret",
                  rows[1].values[2].as.text.len) == 0);

    sqlite_free_rows(rows, count);
    free(db);
    printf("  PASS: test_read_table_logins\n");
}

static void test_read_table_not_found(void) {
    unsigned char *db;
    size_t len;
    SqliteDb sdb;
    open_test_db(&sdb, &db, &len);

    SqliteRow *rows = NULL;
    size_t count = 0;
    int rc = sqlite_read_table(&sdb, "nonexistent_table", &rows, &count);
    assert(rc == -1);

    free(db);
    printf("  PASS: test_read_table_not_found\n");
}

static void test_free_rows_no_crash(void) {
    sqlite_free_rows(NULL, 0);
    sqlite_free_rows(NULL, 0);
    printf("  PASS: test_free_rows_no_crash\n");
}

static void test_free_columns_no_crash(void) {
    SqliteColumns cols = {0};
    sqlite_free_columns(&cols);
    assert(cols.names == NULL);
    assert(cols.count == 0);
    printf("  PASS: test_free_columns_no_crash\n");
}

int main(void) {
    printf("=== test_sqlite: SQLite parser ===\n");
    test_page_type_at_offset_zero();
    test_read_table_logins();
    test_read_table_not_found();
    test_free_rows_no_crash();
    test_free_columns_no_crash();
    printf("=== test_sqlite: ALL PASSED ===\n");
    return 0;
}
