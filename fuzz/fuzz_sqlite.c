/*
 * fuzz_sqlite.c -- libFuzzer target for SQLite parser
 * Build: clang -g -O1 -fsanitize=fuzzer,address -Iinclude -Isrc/parsers -std=c11 \
 *        -o fuzz/fuzz_sqlite fuzz/fuzz_sqlite.c src/parsers/sqlite.c
 * Run:   fuzz/fuzz_sqlite -max_len=65536
 */
#include <stdlib.h>
#include <string.h>
#include "sqlite.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    SqliteDb db;
    if (sqlite_open(&db, data, size) != 0) return 0;

    /* Try to read tables that might exist */
    SqliteRow *rows = NULL;
    size_t count = 0;
    sqlite_read_table(&db, "logins", &rows, &count);
    sqlite_free_rows(rows, count);

    rows = NULL; count = 0;
    sqlite_read_table(&db, "cookies", &rows, &count);
    sqlite_free_rows(rows, count);

    rows = NULL; count = 0;
    sqlite_read_table(&db, "test", &rows, &count);
    sqlite_free_rows(rows, count);

    sqlite_close(&db);
    return 0;
}
