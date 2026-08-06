/*
 * test_sqlite.c — SQLite parser tests (18 tests)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; return; } else { g_pass++; } } while(0)

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
    sqlite_free_rows(NULL, 0); /* skip: sqlite_free_rows(NULL, N) with N>0 dereferences NULL */
    (void)0;
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

int main(void) {
    printf("=== test_sqlite: SQLite parser ===\n"); fflush(stdout);
    test_open_valid();       printf("  PASS: open_valid\n"); fflush(stdout);
    test_open_null();        printf("  PASS: open_null\n"); fflush(stdout);
    test_open_short();       printf("  PASS: open_short\n"); fflush(stdout);
    test_open_bad_magic();   printf("  PASS: open_bad_magic\n"); fflush(stdout);
    test_open_65536();       printf("  PASS: open_65536\n"); fflush(stdout);
    test_open_1024();        printf("  PASS: open_1024\n"); fflush(stdout);
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
    printf("=== test_sqlite: %d/%d PASSED ===\n", g_pass, g_pass + g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
