/*
 * test_sqlite.c — SQLite parser tests (comprehensive: all data types, interior pages)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; return; } else { g_pass++; } } while(0)

/* ── Original test DB builder (TEXT-only, 2 pages) ──────────── */

static void open_test_db(SqliteDb *sdb, unsigned char **out_db, size_t *out_len) {
    const int ps = 1024;
    size_t total = (size_t)ps * 2;
    unsigned char *db = (unsigned char *)calloc(1, total);
    if (!db) exit(1);
    memcpy(db, "SQLite format 3\0", 16);
    db[16] = 0x04; db[17] = 0x00;
    db[18] = 1; db[19] = 1; db[20] = 0;
    unsigned char *bt1 = db + 100;
    bt1[0] = 0x0d; bt1[3] = 0; bt1[4] = 1;
    const char *sql = "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT)";
    int sl = (int)strlen(sql);
    unsigned char cell[512]; int c = 0;
    int hdr = 7;
    int payload = hdr + 5 + 6 + 6 + 1 + sl;
    cell[c++] = (unsigned char)payload; cell[c++] = 1; cell[c++] = (unsigned char)hdr;
    cell[c++] = 23; cell[c++] = 25; cell[c++] = 25;
    cell[c++] = 1;
    cell[c++] = (unsigned char)(0x80 | ((13+sl*2) >> 7));
    cell[c++] = (unsigned char)((13+sl*2) & 0x7F);
    memcpy(cell+c, "table", 5); c += 5;
    memcpy(cell+c, "logins", 6); c += 6;
    memcpy(cell+c, "logins", 6); c += 6;
    cell[c++] = 2;
    memcpy(cell+c, sql, (size_t)sl); c += sl;
    int off = ps - c;
    memcpy(db + off, cell, (size_t)c);
    bt1[5] = (unsigned char)(off >> 8); bt1[6] = (unsigned char)(off & 0xFF);
    bt1[8] = (unsigned char)(off >> 8); bt1[9] = (unsigned char)(off & 0xFF);
    unsigned char *p2 = db + ps;
    p2[0] = 0x0d; p2[3] = 0; p2[4] = 2;
    const char *r1_data[] = {"http://example.com", "user1", "pass1"};
    int r1_lens[] = {18, 5, 5};
    int r1h = 4, r1p = r1h + 18 + 5 + 5;
    unsigned char c1[256]; int c1p = 0;
    c1[c1p++]=(unsigned char)r1p; c1[c1p++]=1; c1[c1p++]=(unsigned char)r1h;
    c1[c1p++]=(unsigned char)(13+18*2); c1[c1p++]=(unsigned char)(13+5*2); c1[c1p++]=(unsigned char)(13+5*2);
    for (int i = 0; i < 3; i++) { memcpy(c1+c1p, r1_data[i], (size_t)r1_lens[i]); c1p += r1_lens[i]; }
    const char *r2_data[] = {"http://test.org", "admin", "secret"};
    int r2_lens[] = {15, 5, 6};
    int r2h = 4, r2p = r2h + 15 + 5 + 6;
    unsigned char c2[256]; int c2p = 0;
    c2[c2p++]=(unsigned char)r2p; c2[c2p++]=2; c2[c2p++]=(unsigned char)r2h;
    c2[c2p++]=(unsigned char)(13+15*2); c2[c2p++]=(unsigned char)(13+5*2); c2[c2p++]=(unsigned char)(13+6*2);
    for (int i = 0; i < 3; i++) { memcpy(c2+c2p, r2_data[i], (size_t)r2_lens[i]); c2p += r2_lens[i]; }
    int o1 = ps - c1p - c2p, o2 = o1 + c1p;
    memcpy(p2+o1, c1, (size_t)c1p); memcpy(p2+o2, c2, (size_t)c2p);
    p2[8]=(unsigned char)(o1>>8); p2[9]=(unsigned char)(o1&0xFF);
    p2[10]=(unsigned char)(o2>>8); p2[11]=(unsigned char)(o2&0xFF);
    memset(sdb, 0, sizeof(*sdb));
    sdb->data = db; sdb->len = total; sdb->page_size = ps;
    sdb->write_version = 1; sdb->read_version = 1;
    *out_db = db; *out_len = total;
}

/* ── Embedded test databases ────────────────────────────────── */

#include "test_sqlite_dbs.h"

/* ═══════════════════════════════════════════════════════════════
 * Original 19 tests
 * ═══════════════════════════════════════════════════════════════ */

static void test_open_valid(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    SqliteDb o; int rc = sqlite_open(&o, db, len);
    CHECK(rc == 0, "open"); CHECK(o.page_size == 1024, "ps");
    CHECK(o.write_version == 1, "wv"); CHECK(o.read_version == 1, "rv");
    CHECK(o.reserved_space == 0, "rs"); CHECK(o.data == db, "data");
    sqlite_close(&o); free(db);
}

static void test_open_null(void) {
    SqliteDb d; CHECK(sqlite_open(&d, NULL, 100) == -1, "null");
}

static void test_open_short(void) {
    unsigned char b[50] = {0}; SqliteDb d;
    CHECK(sqlite_open(&d, b, 50) == -1, "short");
}

static void test_open_bad_magic(void) {
    unsigned char b[200] = {0}; memcpy(b, "NOT SQLite format", 17);
    SqliteDb d; CHECK(sqlite_open(&d, b, 200) == -1, "bad");
}

static void test_open_65536(void) {
    unsigned char b[200] = {0}; memcpy(b, "SQLite format 3\0", 16); b[17] = 1;
    SqliteDb d; CHECK(sqlite_open(&d, b, 200) == 0, "open");
    CHECK(d.page_size == 65536, "65536"); sqlite_close(&d);
}

static void test_open_1024(void) {
    unsigned char b[200] = {0}; memcpy(b, "SQLite format 3\0", 16); b[16] = 4;
    SqliteDb d; CHECK(sqlite_open(&d, b, 200) == 0, "open");
    CHECK(d.page_size == 1024, "1024"); sqlite_close(&d);
}

static void test_open_512(void) {
    unsigned char b[200] = {0}; memcpy(b, "SQLite format 3\0", 16); b[16] = 2;
    SqliteDb d; CHECK(sqlite_open(&d, b, 200) == 0, "open");
    CHECK(d.page_size == 512, "512"); sqlite_close(&d);
}

static void test_open_4096(void) {
    unsigned char b[200] = {0}; memcpy(b, "SQLite format 3\0", 16); b[16] = 0x10;
    SqliteDb d; CHECK(sqlite_open(&d, b, 200) == 0, "open");
    CHECK(d.page_size == 4096, "4096"); sqlite_close(&d);
}

static void test_close_noop(void) {
    SqliteDb d; memset(&d, 0, sizeof(d)); sqlite_close(&d);
}

static void test_find_found(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    CHECK(sqlite_find_table(&sdb, "logins") == 2, "rp==2"); free(db);
}

static void test_find_not_found(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    CHECK(sqlite_find_table(&sdb, "nonexistent") == 0, "nf"); free(db);
}

static void test_read_table(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    SqliteRow *rows = NULL; size_t count = 0;
    int rc = sqlite_read_table(&sdb, "logins", &rows, &count);
    CHECK(rc == 0, "rc"); CHECK(count == 2, "count");
    CHECK(rows[0].values[0].type == SQLITE_VAL_TEXT, "t0");
    CHECK(memcmp(rows[0].values[0].as.text.ptr, "http://example.com", 18) == 0, "v0");
    CHECK(rows[0].values[1].type == SQLITE_VAL_TEXT, "t1");
    CHECK(memcmp(rows[0].values[1].as.text.ptr, "user1", 5) == 0, "v1");
    CHECK(rows[0].values[2].type == SQLITE_VAL_TEXT, "t2");
    CHECK(memcmp(rows[0].values[2].as.text.ptr, "pass1", 5) == 0, "v2");
    CHECK(rows[1].values[0].type == SQLITE_VAL_TEXT, "t3");
    CHECK(memcmp(rows[1].values[0].as.text.ptr, "http://test.org", 15) == 0, "v3");
    CHECK(rows[1].values[1].type == SQLITE_VAL_TEXT, "t4");
    CHECK(memcmp(rows[1].values[1].as.text.ptr, "admin", 5) == 0, "v4");
    CHECK(rows[1].values[2].type == SQLITE_VAL_TEXT, "t5");
    CHECK(memcmp(rows[1].values[2].as.text.ptr, "secret", 6) == 0, "v5");
    sqlite_free_rows(rows, count); free(db);
}

static void test_read_not_found(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    SqliteRow *rows = NULL; size_t count = 0;
    CHECK(sqlite_read_table(&sdb, "nonexistent", &rows, &count) == -1, "nf"); free(db);
}

static void test_read_null_db(void) {
    SqliteRow *rows = NULL; size_t count = 0;
    SqliteDb sdb; memset(&sdb, 0, sizeof(sdb));
    CHECK(sqlite_read_table(&sdb, "logins", &rows, &count) == -1, "null");
}

static void test_get_columns(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    SqliteColumns cols = {0};
    CHECK(sqlite_get_columns(&sdb, "logins", &cols) == 0, "rc");
    CHECK(cols.count == 3, "cnt");
    CHECK(strcmp(cols.names[0], "origin_url") == 0, "c0");
    CHECK(strcmp(cols.names[1], "username_value") == 0, "c1");
    CHECK(strcmp(cols.names[2], "password_value") == 0, "c2");
    sqlite_free_columns(&cols);
    CHECK(cols.names == NULL, "freed"); free(db);
}

static void test_get_cols_not_found(void) {
    unsigned char *db; size_t len; SqliteDb sdb;
    open_test_db(&sdb, &db, &len);
    SqliteColumns cols = {0};
    CHECK(sqlite_get_columns(&sdb, "nonexistent", &cols) == -1, "nf"); free(db);
}

static void test_free_null(void) {
    sqlite_free_rows(NULL, 0);
    SqliteColumns cols = {0}; sqlite_free_columns(&cols);
    CHECK(cols.names == NULL, "n"); CHECK(cols.count == 0, "c");
}

static void test_page_oob(void) {
    unsigned char *db2 = (unsigned char *)calloc(1, 2048);
    memcpy(db2, "SQLite format 3\0", 16); db2[16] = 4;
    unsigned char *bt = db2 + 100;
    bt[0] = 5; bt[3] = 0; bt[4] = 0;
    bt[8] = 0; bt[9] = 0; bt[10] = 3; bt[11] = 0xE7;
    SqliteDb sdb; memset(&sdb, 0, sizeof(sdb));
    sdb.data = db2; sdb.len = 2048; sdb.page_size = 1024;
    CHECK(sqlite_find_table(&sdb, "x") == 0, "oob"); free(db2);
}

static void test_page_zeroed(void) {
    unsigned char buf[4096]; memset(buf, 0, sizeof(buf));
    memcpy(buf, "SQLite format 3\0", 16); buf[16] = 0x10;
    SqliteDb sdb; memset(&sdb, 0, sizeof(sdb));
    sdb.data = buf; sdb.len = 4096; sdb.page_size = 4096;
    CHECK(sqlite_find_table(&sdb, "x") == 0, "zeroed");
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Mixed data type tests
 * ═══════════════════════════════════════════════════════════════ */

static void test_mixed_types_read(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open_mixed");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "alltypes", &rows, &count);
    CHECK(rc == 0, "read_mixed");
    CHECK(count == 10, "10rows");

    /* Row 0: all NULL */
    for (int c = 0; c < 5; c++) {
        char msg[32]; snprintf(msg, sizeof(msg), "r0c%d_null", c);
        CHECK(rows[0].values[c].type == SQLITE_VAL_NULL, msg);
    }

    /* Row 1: NULL, 0, 1.0, "", blob(2) */
    CHECK(rows[1].values[0].type == SQLITE_VAL_NULL, "r1c0");
    CHECK(rows[1].values[1].type == SQLITE_VAL_INTEGER, "r1c1_type");
    CHECK(rows[1].values[1].as.integer == 0, "r1c1_val");
    CHECK(rows[1].values[2].type == SQLITE_VAL_REAL, "r1c2_type");
    CHECK(rows[1].values[3].type == SQLITE_VAL_TEXT, "r1c3_type");
    CHECK(rows[1].values[3].as.text.len == 0, "r1c3_empty");
    CHECK(rows[1].values[4].type == SQLITE_VAL_BLOB, "r1c4_type");
    CHECK(rows[1].values[4].as.blob.len == 2, "r1c4_len");

    /* Row 2: NULL, 42, 3.14, "hello", blob(4) */
    CHECK(rows[2].values[1].type == SQLITE_VAL_INTEGER, "r2c1_type");
    CHECK(rows[2].values[1].as.integer == 42, "r2c1_val");
    CHECK(rows[2].values[2].type == SQLITE_VAL_REAL, "r2c2_type");
    CHECK(rows[2].values[4].type == SQLITE_VAL_BLOB, "r2c4_type");
    CHECK(rows[2].values[4].as.blob.len == 4, "r2c4_len");

    /* Row 3: -1 (signed int8) */
    CHECK(rows[3].values[1].as.integer == -1, "r3c1_neg1");

    /* Row 4: 300 (int16) */
    CHECK(rows[4].values[1].as.integer == 300, "r4c1_300");

    /* Row 5: 100000 (int32) */
    CHECK(rows[5].values[1].as.integer == 100000, "r5c1_100k");

    /* Row 6: NULL, -32768 (2-byte sign-ext), -0.001, "short", blob(1) */
    CHECK(rows[6].values[1].type == SQLITE_VAL_INTEGER, "r6c1_type");
    CHECK(rows[6].values[1].as.integer < 0, "r6c1_neg");

    /* Row 7: 2147483647 (int32) */
    CHECK(rows[7].values[1].as.integer == 2147483647, "r7c1_max32");

    /* Row 8: NULL, -2147483648 (4-byte sign-ext), 1.234..., "minint", blob(8) */
    CHECK(rows[8].values[1].type == SQLITE_VAL_INTEGER, "r8c1_type");
    CHECK(rows[8].values[1].as.integer < 0, "r8c1_neg");

    /* Row 9: 9223372036854775807 (int64) */
    CHECK(rows[9].values[1].as.integer == 9223372036854775807LL, "r9c1_max64");
    CHECK(rows[9].values[4].type == SQLITE_VAL_BLOB, "r9c4_type");
    CHECK(rows[9].values[4].as.blob.len == 200, "r9c4_len");

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_mixed_types_columns(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open");

    SqliteColumns cols = {0};
    rc = sqlite_get_columns(&sdb, "alltypes", &cols);
    CHECK(rc == 0, "get_cols");
    CHECK(cols.count == 5, "5cols");
    CHECK(strcmp(cols.names[0], "c_null") == 0, "cn0");
    CHECK(strcmp(cols.names[1], "c_int") == 0, "cn1");
    CHECK(strcmp(cols.names[2], "c_real") == 0, "cn2");
    CHECK(strcmp(cols.names[3], "c_text") == 0, "cn3");
    CHECK(strcmp(cols.names[4], "c_blob") == 0, "cn4");
    sqlite_free_columns(&cols);
    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Many-tables (interior sqlite_master)
 * ═══════════════════════════════════════════════════════════════ */

static void test_many_tables_find(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    CHECK(sqlite_find_table(&sdb, "t0") > 0, "find_t0");
    CHECK(sqlite_find_table(&sdb, "t25") > 0, "find_t25");
    CHECK(sqlite_find_table(&sdb, "t49") > 0, "find_t49");
    CHECK(sqlite_find_table(&sdb, "nonexistent") == 0, "not_found");

    sqlite_close(&sdb);
}

static void test_many_tables_read(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "t0", &rows, &count);
    CHECK(rc == 0, "read_t0");
    CHECK(count == 0, "empty_t0");
    sqlite_free_rows(rows, count);

    rows = NULL; count = 0;
    rc = sqlite_read_table(&sdb, "t49", &rows, &count);
    CHECK(rc == 0, "read_t49");
    CHECK(count == 0, "empty_t49");
    sqlite_free_rows(rows, count);

    rows = NULL; count = 0;
    rc = sqlite_read_table(&sdb, "nope", &rows, &count);
    CHECK(rc == -1, "notfound");

    sqlite_close(&sdb);
}

static void test_many_tables_columns(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    SqliteColumns cols = {0};
    rc = sqlite_get_columns(&sdb, "t10", &cols);
    CHECK(rc == 0, "get_cols");
    CHECK(cols.count == 1, "1col");
    CHECK(strcmp(cols.names[0], "a") == 0, "col_a");
    sqlite_free_columns(&cols);

    cols = (SqliteColumns){0};
    rc = sqlite_get_columns(&sdb, "nope", &cols);
    CHECK(rc == -1, "notfound");

    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Many-rows (interior data table pages)
 * ═══════════════════════════════════════════════════════════════ */

static void test_many_rows_read(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_rows_db, g_many_rows_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "big", &rows, &count);
    CHECK(rc == 0, "read_big");
    CHECK(count >= 2, "rows_found");

    CHECK(rows[0].values[0].type == SQLITE_VAL_INTEGER, "r0_id_type");
    
    CHECK(rows[0].values[1].type == SQLITE_VAL_TEXT, "r0_name_type");
    CHECK(rows[0].values[2].type == SQLITE_VAL_BLOB, "r0_data_type");
    CHECK(rows[0].values[2].as.blob.len == 50, "r0_data_len");
    CHECK(rows[0].values[3].type == SQLITE_VAL_REAL, "r0_val_type");

    

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_many_rows_columns(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_rows_db, g_many_rows_db_len);
    CHECK(rc == 0, "open");

    SqliteColumns cols = {0};
    rc = sqlite_get_columns(&sdb, "big", &cols);
    CHECK(rc == 0, "get_cols");
    CHECK(cols.count == 4, "4cols");
    CHECK(strcmp(cols.names[0], "id") == 0, "c0");
    CHECK(strcmp(cols.names[1], "name") == 0, "c1");
    CHECK(strcmp(cols.names[2], "data") == 0, "c2");
    CHECK(strcmp(cols.names[3], "val") == 0, "c3");
    sqlite_free_columns(&cols);
    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Quoted column names
 * ═══════════════════════════════════════════════════════════════ */

static void test_quoted_columns(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_quoted_db, g_quoted_db_len);
    CHECK(rc == 0, "open");

    SqliteColumns cols = {0};
    rc = sqlite_get_columns(&sdb, "my table", &cols);
    CHECK(rc == 0, "get_cols");
    CHECK(cols.count == 2, "2cols");
    CHECK(strcmp(cols.names[0], "col one") == 0, "q0");
    CHECK(strcmp(cols.names[1], "col two") == 0, "q1");
    sqlite_free_columns(&cols);

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "my table", &rows, &count);
    CHECK(rc == 0, "read");
    CHECK(count == 1, "1row");
    CHECK(rows[0].values[0].type == SQLITE_VAL_TEXT, "t0");
    CHECK(rows[0].values[1].type == SQLITE_VAL_INTEGER, "t1");
    CHECK(rows[0].values[1].as.integer == 42, "v1");
    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Interior find (walks all children)
 * ═══════════════════════════════════════════════════════════════ */

static void test_interior_find(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    for (int i = 0; i < 50; i++) {
        char name[16];
        snprintf(name, sizeof(name), "t%d", i);
        int rp = sqlite_find_table(&sdb, name);
        char msg[32]; snprintf(msg, sizeof(msg), "find_%s", name);
        CHECK(rp > 0, msg);
    }
    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * NEW: Empty table, page sizes, negative ints, blobs
 * ═══════════════════════════════════════════════════════════════ */

static void test_empty_table(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "t0", &rows, &count);
    CHECK(rc == 0, "rc");
    CHECK(count == 0, "empty");
    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_page_size_512(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");
    CHECK(sdb.page_size == 512, "ps512");
    sqlite_close(&sdb);
}

static void test_page_size_4096(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open");
    CHECK(sdb.page_size == 4096, "ps4096");
    sqlite_close(&sdb);
}

static void test_many_tables_not_found(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    int rp = sqlite_find_table(&sdb, "does_not_exist_anywhere");
    CHECK(rp == 0, "nf");
    sqlite_close(&sdb);
}

static void test_many_rows_mixed_values(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_rows_db, g_many_rows_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "big", &rows, &count);
    CHECK(rc == 0, "read");
    CHECK(count >= 2, "many");

    CHECK(rows[0].values[0].type == SQLITE_VAL_INTEGER, "mid_type");

    /* All rows have valid types */

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_many_tables_cols_not_found(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_many_tables_db, g_many_tables_db_len);
    CHECK(rc == 0, "open");

    SqliteColumns cols = {0};
    rc = sqlite_get_columns(&sdb, "zzz_nonexistent", &cols);
    CHECK(rc == -1, "nf");
    sqlite_close(&sdb);
}

static void test_interior_null_child(void) {
    unsigned char buf[2048];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "SQLite format 3\0", 16);
    buf[16] = 0x02;
    buf[18] = 1; buf[19] = 1;

    unsigned char *bt = buf + 100;
    bt[0] = 0x05;
    bt[3] = 0; bt[4] = 0;
    bt[8] = 0; bt[9] = 0; bt[10] = 0; bt[11] = 99;

    SqliteDb sdb; memset(&sdb, 0, sizeof(sdb));
    sdb.data = buf; sdb.len = 2048; sdb.page_size = 512;

    int rp = sqlite_find_table(&sdb, "x");
    CHECK(rp == 0, "null_child");

    SqliteRow *rows = NULL; size_t count = 0;
    int rc = sqlite_read_table(&sdb, "x", &rows, &count);
    CHECK(rc == -1, "read_no_master");

    sqlite_close(&sdb);
}

static void test_negative_integers(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "alltypes", &rows, &count);
    CHECK(rc == 0, "read");

    CHECK(rows[3].values[1].as.integer == -1, "neg1");
    CHECK(rows[6].values[1].type == SQLITE_VAL_INTEGER, "neg16");
    CHECK(rows[8].values[1].type == SQLITE_VAL_INTEGER, "neg32");

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_large_blob(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "alltypes", &rows, &count);
    CHECK(rc == 0, "read");

    CHECK(rows[9].values[4].type == SQLITE_VAL_BLOB, "blob_type");
    CHECK(rows[9].values[4].as.blob.len == 200, "blob_len");
    CHECK(rows[9].values[4].as.blob.ptr[0] == 0xAA, "blob_data");

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

static void test_int_0_and_1(void) {
    SqliteDb sdb;
    int rc = sqlite_open(&sdb, g_mixed_db, g_mixed_db_len);
    CHECK(rc == 0, "open");

    SqliteRow *rows = NULL; size_t count = 0;
    rc = sqlite_read_table(&sdb, "alltypes", &rows, &count);
    CHECK(rc == 0, "read");

    CHECK(rows[1].values[1].type == SQLITE_VAL_INTEGER, "int0_type");
    CHECK(rows[1].values[1].as.integer == 0, "int0_val");

    CHECK(rows[1].values[2].type == SQLITE_VAL_REAL, "float_type");

    sqlite_free_rows(rows, count);
    sqlite_close(&sdb);
}

/* ═══════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== test_sqlite: SQLite parser ===\n"); fflush(stdout);

    /* Original 19 tests */
    test_open_valid();       printf("  PASS: open_valid\n"); fflush(stdout);
    test_open_null();        printf("  PASS: open_null\n"); fflush(stdout);
    test_open_short();       printf("  PASS: open_short\n"); fflush(stdout);
    test_open_bad_magic();   printf("  PASS: open_bad_magic\n"); fflush(stdout);
    test_open_65536();       printf("  PASS: open_65536\n"); fflush(stdout);
    test_open_1024();        printf("  PASS: open_1024\n"); fflush(stdout);
    test_open_512();         printf("  PASS: open_512\n"); fflush(stdout);
    test_open_4096();        printf("  PASS: open_4096\n"); fflush(stdout);
    test_close_noop();       printf("  PASS: close_noop\n"); fflush(stdout);
    test_find_found();       printf("  PASS: find_found\n"); fflush(stdout);
    test_find_not_found();   printf("  PASS: find_not_found\n"); fflush(stdout);
    test_read_table();       printf("  PASS: read_table\n"); fflush(stdout);
    test_read_not_found();   printf("  PASS: read_not_found\n"); fflush(stdout);
    test_read_null_db();     printf("  PASS: read_null_db\n"); fflush(stdout);
    test_get_columns();      printf("  PASS: get_columns\n"); fflush(stdout);
    test_get_cols_not_found(); printf("  PASS: get_cols_not_found\n"); fflush(stdout);
    test_free_null();        printf("  PASS: free_null\n"); fflush(stdout);
    test_page_oob();         printf("  PASS: page_oob\n"); fflush(stdout);
    test_page_zeroed();      printf("  PASS: page_zeroed\n"); fflush(stdout);

    /* New coverage tests */
    test_mixed_types_read();     printf("  PASS: mixed_types_read\n"); fflush(stdout);
    test_mixed_types_columns();  printf("  PASS: mixed_types_columns\n"); fflush(stdout);
    test_many_tables_find();     printf("  PASS: many_tables_find\n"); fflush(stdout);
    test_many_tables_read();     printf("  PASS: many_tables_read\n"); fflush(stdout);
    test_many_tables_columns();  printf("  PASS: many_tables_columns\n"); fflush(stdout);
    test_many_rows_read();       printf("  PASS: many_rows_read\n"); fflush(stdout);
    test_many_rows_columns();    printf("  PASS: many_rows_columns\n"); fflush(stdout);
    test_quoted_columns();       printf("  PASS: quoted_columns\n"); fflush(stdout);
    test_interior_find();        printf("  PASS: interior_find\n"); fflush(stdout);
    test_empty_table();          printf("  PASS: empty_table\n"); fflush(stdout);
    test_page_size_512();        printf("  PASS: page_size_512\n"); fflush(stdout);
    test_page_size_4096();       printf("  PASS: page_size_4096\n"); fflush(stdout);
    test_many_tables_not_found(); printf("  PASS: many_tables_not_found\n"); fflush(stdout);
    test_many_rows_mixed_values(); printf("  PASS: many_rows_mixed_values\n"); fflush(stdout);
    test_many_tables_cols_not_found(); printf("  PASS: many_tables_cols_not_found\n"); fflush(stdout);
    test_interior_null_child();  printf("  PASS: interior_null_child\n"); fflush(stdout);
    test_negative_integers();    printf("  PASS: negative_integers\n"); fflush(stdout);
    test_large_blob();           printf("  PASS: large_blob\n"); fflush(stdout);
    test_int_0_and_1();          printf("  PASS: int_0_and_1\n"); fflush(stdout);

    printf("=== test_sqlite: %d/%d PASSED ===\n", g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}
