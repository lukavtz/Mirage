#ifndef SQLITE_H
#define SQLITE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *data;
    size_t len;
    int page_size;
    int write_version;
    int read_version;
    int reserved_space;
} SqliteDb;

// Cell value — can be NULL, integer, real, text, or blob
typedef enum {
    SQLITE_VAL_NULL = 0,
    SQLITE_VAL_INTEGER,
    SQLITE_VAL_REAL,
    SQLITE_VAL_TEXT,
    SQLITE_VAL_BLOB
} SqliteValueType;

typedef struct {
    SqliteValueType type;
    union {
        int64_t integer;
        double real;
        struct { const unsigned char *ptr; size_t len; } text;
        struct { const unsigned char *ptr; size_t len; } blob;
    } as;
} SqliteValue;

// A single row of values
typedef struct {
    SqliteValue *values;
    size_t count;
} SqliteRow;

// Column names for a table
typedef struct {
    char **names;
    size_t count;
} SqliteColumns;

// Open SQLite database from memory-mapped file
int sqlite_open(SqliteDb *db, const void *data, size_t len);

// Close database
void sqlite_close(SqliteDb *db);

// Find the root page number for a table by name
// Returns 0 if not found, -1 on error
int sqlite_find_table(SqliteDb *db, const char *table_name);

// Read all rows from a table. Caller must free with sqlite_free_rows().
// Returns 0 on success, -1 on error.
int sqlite_read_table(SqliteDb *db, const char *table_name,
                      SqliteRow **rows, size_t *count);

// Get column names for a table. Caller must free with sqlite_free_columns().
int sqlite_get_columns(SqliteDb *db, const char *table_name,
                       SqliteColumns *cols);

// Free rows allocated by sqlite_read_table
void sqlite_free_rows(SqliteRow *rows, size_t count);

// Free columns allocated by sqlite_get_columns
void sqlite_free_columns(SqliteColumns *cols);

#endif
