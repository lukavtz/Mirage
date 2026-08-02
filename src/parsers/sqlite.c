#include "sqlite.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── SQLite file format constants ────────────────────────────── */

static const unsigned char SQLITE_MAGIC[16] = {
    0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66,
    0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00
};

/* Page types */
#define PAGE_TYPE_INTERIOR_INDEX  0x02
#define PAGE_TYPE_INTERIOR_TABLE  0x05
#define PAGE_TYPE_LEAF_INDEX     0x0a
#define PAGE_TYPE_LEAF_TABLE     0x0d

/* Header sizes per page type */
#define LEAF_TABLE_HEADER_SIZE    8
#define INTERIOR_TABLE_HEADER_SIZE 12
#define LEAF_INDEX_HEADER_SIZE    0  /* no header */
#define INTERIOR_INDEX_HEADER_SIZE 0

/* ── Database open / close ───────────────────────────────────── */

int sqlite_open(SqliteDb *db, const void *data, size_t len) {
    if (len < 100) return -1;
    if (memcmp(data, SQLITE_MAGIC, 16) != 0) return -1;

    const unsigned char *p = (const unsigned char *)data;
    db->page_size = (p[16] << 8) | p[17];
    if (db->page_size == 1) db->page_size = 65536;
    db->write_version = p[18];
    db->read_version = p[19];
    db->reserved_space = p[20];
    db->data = p;
    db->len = len;
    return 0;
}

void sqlite_close(SqliteDb *db) {
    (void)db;
}

/* ── Varint reader ───────────────────────────────────────────── */

static size_t read_varint(const unsigned char *buf, size_t buf_size, int64_t *value) {
    int64_t v = 0;
    size_t i;
    for (i = 0; i < 9 && i < buf_size; i++) {
        unsigned char b = buf[i];
        if (i < 8) {
            v = (v << 7) | (b & 0x7F);
        } else {
            v = (v << 8) | b;
        }
        if (!(b & 0x80)) break;
    }
    if (value) *value = v;
    return i + 1;
}

/* ── Serial type size ────────────────────────────────────────── */

static int serial_type_size(int serial_type) {
    if (serial_type == 0) return 0;
    if (serial_type == 1) return 1;
    if (serial_type == 2) return 2;
    if (serial_type == 3) return 3;
    if (serial_type == 4) return 4;
    if (serial_type == 5) return 6;
    if (serial_type == 6) return 8;
    if (serial_type == 7) return 8;
    if (serial_type == 8) return 0;
    if (serial_type == 9) return 0;
    if (serial_type >= 12 && serial_type % 2 == 0)
        return (serial_type - 12) / 2;
    if (serial_type >= 13 && serial_type % 2 == 1)
        return (serial_type - 13) / 2;
    return 0;
}

/* ── Integer value from raw bytes ────────────────────────────── */

static int64_t read_int_be(const unsigned char *data, int nbytes) {
    int64_t val = 0;
    for (int i = 0; i < nbytes; i++)
        val = (val << 8) | data[i];
    /* sign-extend for signed types */
    if (nbytes > 0 && nbytes < 8 && (data[0] & 0x80)) {
        for (int i = nbytes; i < 8; i++)
            val = (val << 8) | 0xFF;
    }
    return val;
}

/* ── Get a page pointer ──────────────────────────────────────── */

static const unsigned char *page_ptr(const SqliteDb *db, int page_num) {
    if (page_num < 1) return NULL;
    size_t offset = (size_t)(page_num - 1) * (size_t)db->page_size;
    if (offset + (size_t)db->page_size > db->len) return NULL;
    return db->data + offset;
}

/* Page 1 has a 100-byte database header before the b-tree header.
 * All other pages start directly with the b-tree header. */
static int btree_offset(int page_num) {
    return (page_num == 1) ? 100 : 0;
}

/* ── Read the sqlite_master schema ───────────────────────────── */

/* sqlite_master row layout:
 *   [0] type     TEXT
 *   [1] name     TEXT
 *   [2] tbl_name TEXT
 *   [3] rootpage INTEGER
 *   [4] sql      TEXT
 */

/* ── Parse a sqlite_master cell for name + rootpage ──────── */

static int parse_master_cell(const unsigned char *cell, const char *table_name,
                             int64_t *out_rootpage) {
    size_t pos = 0;
    int64_t payload_len;
    pos += read_varint(cell + pos, 50, &payload_len);
    pos += read_varint(cell + pos, 50, NULL); /* rowid */
    pos += read_varint(cell + pos, 50, NULL); /* header size */

    int64_t col_serials[5];
    for (int c = 0; c < 5; c++)
        pos += read_varint(cell + pos, 50, &col_serials[c]);

    const unsigned char *p = cell + pos;
    const char *name = NULL;
    int name_len = 0;
    int64_t rootpage = 0;

    for (int c = 0; c < 5; c++) {
        int stype = (int)col_serials[c];
        int ssize = serial_type_size(stype);
        if (c == 1 && stype >= 13 && stype % 2 == 1) {
            name = (const char *)p;
            name_len = (stype - 13) / 2;
        }
        if (c == 3) {
            if (stype == 8) rootpage = 0;
            else if (stype == 9) rootpage = 1;
            else if (stype >= 1 && stype <= 6)
                rootpage = read_int_be(p, ssize);
        }
        p += ssize;
    }

    if (name && name_len == (int)strlen(table_name) &&
        memcmp(name, table_name, (size_t)name_len) == 0) {
        if (out_rootpage) *out_rootpage = rootpage;
        return 1; /* found */
    }
    return 0; /* not this cell */
}

/* ── Recursive helper: find table starting from any page ──── */

static int sqlite_find_table_in_page(SqliteDb *db, int pg,
                                     const char *table_name) {
    const unsigned char *page = page_ptr(db, pg);
    if (!page) return 0;

    int page_type = page[0];
    int hdr = btree_offset(pg);
    const unsigned char *bt = page + hdr;

    if (page_type == PAGE_TYPE_LEAF_TABLE) {
        int n_cells = (bt[3] << 8) | bt[4];
        for (int i = 0; i < n_cells; i++) {
            size_t cpo = (size_t)hdr + LEAF_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page[cpo] << 8) | (size_t)page[cpo + 1];
            int64_t rp = 0;
            if (parse_master_cell(page + co, table_name, &rp))
                return (int)rp;
        }
    } else if (page_type == PAGE_TYPE_INTERIOR_TABLE) {
        int n_cells = (bt[3] << 8) | bt[4];
        uint32_t right_child = ((uint32_t)bt[8] << 24) |
                               ((uint32_t)bt[9] << 16) |
                               ((uint32_t)bt[10] << 8) |
                               (uint32_t)bt[11];

        /* Cell pointer array: 2 bytes per entry at INTERIOR_TABLE_HEADER_SIZE */
        for (int i = 0; i < n_cells; i++) {
            /* Read cell offset from pointer array */
            size_t cpo = (size_t)hdr + INTERIOR_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page[cpo] << 8) | (size_t)page[cpo + 1];
            const unsigned char *cell = page + co;
            /* First 4 bytes of interior table cell = left child page number (big-endian) */
            uint32_t child_pg = ((uint32_t)cell[0] << 24) |
                                ((uint32_t)cell[1] << 16) |
                                ((uint32_t)cell[2] << 8) |
                                (uint32_t)cell[3];
            int result = sqlite_find_table_in_page(db, (int)child_pg, table_name);
            if (result > 0) return result;
        }
        /* Check right-most child pointer */
        if (right_child > 0) {
            int result = sqlite_find_table_in_page(db, (int)right_child, table_name);
            if (result > 0) return result;
        }
    }

    return 0; /* not found */
}

/* Find root page for a table. Parses sqlite_master B-tree. */
int sqlite_find_table(SqliteDb *db, const char *table_name) {
    return sqlite_find_table_in_page(db, 1, table_name);
}

/* ── Read a single record from a leaf table cell ─────────────── */

/* Reads columns from a cell starting at `cell`. Stores into `values`.
 * Returns number of bytes consumed from cell, or 0 on error.
 *
 * Cell format for leaf table:
 *   payload_length (varint)
 *   rowid (varint)
 *   record_header:
 *     header_size (varint, includes itself)
 *     serial_types (varints)
 *   column_data
 */
static size_t read_record(const unsigned char *cell, size_t cell_max,
                          SqliteValue *values, size_t max_values) {
    size_t pos = 0;
    int64_t payload_len;
    pos += read_varint(cell + pos, cell_max - pos, &payload_len);
    pos += read_varint(cell + pos, cell_max - pos, NULL); /* rowid */

    int64_t header_size;
    pos += read_varint(cell + pos, cell_max - pos, &header_size);
    if (header_size <= 0 || (size_t)header_size > cell_max) return 0;

    size_t header_end = pos + (size_t)header_size - 1; /* -1 because header_size includes itself */
    size_t serial_start = pos;

    /* Count columns by reading serial types until header_end */
    size_t n_cols = 0;
    size_t tmp = pos;
    while (tmp < header_end && n_cols < max_values) {
        int64_t st;
        tmp += read_varint(cell + tmp, cell_max - tmp, &st);
        n_cols++;
    }

    /* Read serial types */
    int64_t *serials = (int64_t *)calloc(n_cols, sizeof(int64_t));
    if (!serials) return 0;
    pos = serial_start;
    for (size_t i = 0; i < n_cols; i++) {
        pos += read_varint(cell + pos, cell_max - pos, &serials[i]);
    }

    /* Read values */
    for (size_t i = 0; i < n_cols && i < max_values; i++) {
        int st = (int)serials[i];
        int sz = serial_type_size(st);
        const unsigned char *p = cell + pos;

        if (st == 0) {
            values[i].type = SQLITE_VAL_NULL;
        } else if (st >= 1 && st <= 6) {
            values[i].type = SQLITE_VAL_INTEGER;
            values[i].as.integer = read_int_be(p, sz);
        } else if (st == 7) {
            values[i].type = SQLITE_VAL_REAL;
            double d;
            uint64_t u;
            memcpy(&u, p, 8);
            /* swap endianness */
            u = ((u & 0xFF00000000000000ULL) >> 56) |
                ((u & 0x00FF000000000000ULL) >> 40) |
                ((u & 0x0000FF0000000000ULL) >> 24) |
                ((u & 0x000000FF00000000ULL) >> 8)  |
                ((u & 0x00000000FF000000ULL) << 8)  |
                ((u & 0x0000000000FF0000ULL) << 24) |
                ((u & 0x000000000000FF00ULL) << 40) |
                ((u & 0x00000000000000FFULL) << 56);
            memcpy(&d, &u, 8);
            values[i].as.real = d;
        } else if (st == 8) {
            values[i].type = SQLITE_VAL_INTEGER;
            values[i].as.integer = 0;
        } else if (st == 9) {
            values[i].type = SQLITE_VAL_INTEGER;
            values[i].as.integer = 1;
        } else if (st >= 12 && st % 2 == 0) {
            values[i].type = SQLITE_VAL_BLOB;
            values[i].as.blob.ptr = p;
            values[i].as.blob.len = (size_t)sz;
        } else if (st >= 13 && st % 2 == 1) {
            values[i].type = SQLITE_VAL_TEXT;
            values[i].as.text.ptr = p;
            values[i].as.text.len = (size_t)sz;
        } else {
            values[i].type = SQLITE_VAL_NULL;
        }

        pos += (size_t)sz;
    }

    free(serials);
    (void)cell_max; /* bounds already checked */
    return pos;
}

/* ── Read all rows from a leaf table page ────────────────────── */

static void read_leaf_rows(const SqliteDb *db, const unsigned char *page,
                           SqliteRow **out_rows, size_t *out_count,
                           size_t *alloc_cap) {
    int n_cells = (page[3] << 8) | page[4];

    for (int i = 0; i < n_cells; i++) {
        size_t cell_ptr_off = LEAF_TABLE_HEADER_SIZE + (size_t)i * 2;
        size_t cell_offset = ((size_t)page[cell_ptr_off] << 8) |
                             (size_t)page[cell_ptr_off + 1];
        const unsigned char *cell = page + cell_offset;

        /* Allocate a row with max 64 columns */
        size_t max_cols = 64;
        SqliteValue *vals = (SqliteValue *)calloc(max_cols, sizeof(SqliteValue));
        if (!vals) continue;

        size_t consumed = read_record(cell, (size_t)db->page_size - cell_offset,
                                      vals, max_cols);
        if (consumed == 0) {
            free(vals);
            continue;
        }

        /* Shrink to actual column count */
        size_t actual_cols = 0;
        for (size_t c = 0; c < max_cols; c++) {
            if (vals[c].type != SQLITE_VAL_NULL || c < 5)
                actual_cols = c + 1;
            else if (c > 0)
                break;
        }
        /* More precise: count non-tail-nulls */
        actual_cols = max_cols;
        while (actual_cols > 0 && vals[actual_cols - 1].type == SQLITE_VAL_NULL) {
            /* Check if this was really set — for now use max_cols */
            actual_cols--;
        }
        if (actual_cols == 0) actual_cols = max_cols;

        /* Grow output array if needed */
        if (*out_count >= *alloc_cap) {
            size_t new_cap = *alloc_cap == 0 ? 64 : *alloc_cap * 2;
            SqliteRow *new_rows = (SqliteRow *)realloc(*out_rows,
                                    new_cap * sizeof(SqliteRow));
            if (!new_rows) { free(vals); continue; }
            *out_rows = new_rows;
            *alloc_cap = new_cap;
        }

        (*out_rows)[*out_count].values = vals;
        (*out_rows)[*out_count].count = actual_cols;
        (*out_count)++;
    }
}

/* ── Find table and read all rows ────────────────────────────── */

int sqlite_read_table(SqliteDb *db, const char *table_name,
                      SqliteRow **rows, size_t *count) {
    *rows = NULL;
    *count = 0;

    /* Read sqlite_master to find root page of the target table */
    const unsigned char *page1 = page_ptr(db, 1);
    if (!page1) { printf("[!] sqlite_read_table: page1 NULL\n"); return -1; }

    int root_page = 0;
    int pt = page1[0 + btree_offset(1)];

    if (pt == PAGE_TYPE_LEAF_TABLE) {
        const unsigned char *bt = page1 + btree_offset(1);
        int n_cells = (bt[3] << 8) | bt[4];

        for (int i = 0; i < n_cells; i++) {
            size_t cpo = btree_offset(1) + LEAF_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page1[cpo] << 8) | (size_t)page1[cpo + 1];
            const unsigned char *cell = page1 + co;

            size_t pos = 0;
            int64_t payload;
            pos += read_varint(cell + pos, 10, &payload);
            pos += read_varint(cell + pos, 10, NULL); /* rowid */
            pos += read_varint(cell + pos, 10, NULL); /* header size */

            /* Read serial types */
            int64_t s[5];
            for (int c = 0; c < 5; c++)
                pos += read_varint(cell + pos, 10, &s[c]);

            /* Extract col 1 (name) and col 3 (rootpage) */
            const unsigned char *p = cell + pos;
            const char *name = NULL;
            int name_len = 0;
            int64_t rp = 0;

            for (int c = 0; c < 5; c++) {
                int st = (int)s[c];
                int sz = serial_type_size(st);
                if (c == 1 && st >= 13 && st % 2 == 1) {
                    name = (const char *)p;
                    name_len = (st - 13) / 2;
                }
                if (c == 3) {
                    if (st == 8) rp = 0;
                    else if (st == 9) rp = 1;
                    else if (st >= 1 && st <= 6) rp = read_int_be(p, sz);
                }
                p += sz;
            }


            if (name && name_len == (int)strlen(table_name) &&
                memcmp(name, table_name, (size_t)name_len) == 0) {
                root_page = (int)rp;
                break;
            }
        }
    } else if (pt == PAGE_TYPE_INTERIOR_TABLE) {
        /* Interior sqlite_master — traverse children to find the table */
        const unsigned char *bt = page1 + btree_offset(1);
        int nc = (bt[3] << 8) | bt[4];
        /* Right-most child pointer at bytes 8-11 of b-tree header */
        int right_child = ((int)bt[8] << 24) | ((int)bt[9] << 16) |
                          ((int)bt[10] << 8) | (int)bt[11];

        /* Collect all child page numbers from cells */
        int children[256];
        int n_children = 0;

        /* Cell pointer array: 2 bytes per entry, starting at offset 12 */
        for (int i = 0; i < nc && n_children < 255; i++) {
            size_t cpo = btree_offset(1) + INTERIOR_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page1[cpo] << 8) | (size_t)page1[cpo + 1];
            const unsigned char *cell = page1 + co;
            /* First 4 bytes of interior table cell = left child page number */
            int child = ((int)cell[0] << 24) | ((int)cell[1] << 16) |
                        ((int)cell[2] << 8) | (int)cell[3];
            children[n_children++] = child;
        }
        if (n_children < 256) children[n_children++] = right_child;

        /* Traverse each child page looking for our table */
        for (int ci = 0; ci < n_children && root_page == 0; ci++) {
            const unsigned char *child_page = page_ptr(db, children[ci]);
            if (!child_page) continue;
            int cpt = child_page[0]; /* child pages (not page1) have no DB header */

            if (cpt == PAGE_TYPE_LEAF_TABLE) {
                int cn_cells = (child_page[3] << 8) | child_page[4];
                for (int j = 0; j < cn_cells; j++) {
                    size_t cpo2 = LEAF_TABLE_HEADER_SIZE + (size_t)j * 2;
                    size_t co2 = ((size_t)child_page[cpo2] << 8) | (size_t)child_page[cpo2 + 1];
                    const unsigned char *cell2 = child_page + co2;
                    size_t pos2 = 0;
                    int64_t payload2;
                    pos2 += read_varint(cell2 + pos2, 50, &payload2);
                    pos2 += read_varint(cell2 + pos2, 50, NULL);
                    pos2 += read_varint(cell2 + pos2, 50, NULL);
                    int64_t s2[5];
                    for (int c = 0; c < 5; c++)
                        pos2 += read_varint(cell2 + pos2, 50, &s2[c]);
                    const unsigned char *p2 = cell2 + pos2;
                    const char *name2 = NULL;
                    int name2_len = 0;
                    int64_t rp2 = 0;
                    for (int c = 0; c < 5; c++) {
                        int st = (int)s2[c];
                        int sz = serial_type_size(st);
                        if (c == 1 && st >= 13 && st % 2 == 1) {
                            name2 = (const char *)p2;
                            name2_len = (st - 13) / 2;
                        }
                        if (c == 3) {
                            if (st == 8) rp2 = 0;
                            else if (st == 9) rp2 = 1;
                            else if (st >= 1 && st <= 6) rp2 = read_int_be(p2, sz);
                        }
                        p2 += sz;
                    }
                    if (name2 && name2_len == (int)strlen(table_name) &&
                        memcmp(name2, table_name, (size_t)name2_len) == 0) {
                        root_page = (int)rp2;
                    }
                }
            } else if (cpt == PAGE_TYPE_INTERIOR_TABLE) {
                /* Recurse one more level — read child page pointers */
                int cc = (child_page[3] << 8) | child_page[4];
                int crp = ((int)child_page[8] << 24) | ((int)child_page[9] << 16) |
                          ((int)child_page[10] << 8) | (int)child_page[11];
                int grandchild_pages[256];
                int ngc = 0;
                for (int g = 0; g < cc && ngc < 255; g++) {
                    size_t gcpo = INTERIOR_TABLE_HEADER_SIZE + (size_t)g * 2;
                    size_t gco = ((size_t)child_page[gcpo] << 8) | (size_t)child_page[gcpo + 1];
                    const unsigned char *gc = child_page + gco;
                    grandchild_pages[ngc++] = ((int)gc[0] << 24) | ((int)gc[1] << 16) |
                                              ((int)gc[2] << 8) | (int)gc[3];
                }
                grandchild_pages[ngc++] = crp;
                for (int g = 0; g < ngc && root_page == 0; g++) {
                    const unsigned char *gp = page_ptr(db, grandchild_pages[g]);
                    if (!gp || gp[0] != PAGE_TYPE_LEAF_TABLE) continue;
                    int gnc = (gp[3] << 8) | gp[4];
                    for (int j = 0; j < gnc; j++) {
                        size_t gcpo2 = LEAF_TABLE_HEADER_SIZE + (size_t)j * 2;
                        size_t gco2 = ((size_t)gp[gcpo2] << 8) | (size_t)gp[gcpo2 + 1];
                        const unsigned char *gc2 = gp + gco2;
                        size_t gp2 = 0;
                        int64_t gpl;
                        gp2 += read_varint(gc2 + gp2, 50, &gpl);
                        gp2 += read_varint(gc2 + gp2, 50, NULL);
                        gp2 += read_varint(gc2 + gp2, 50, NULL);
                        int64_t gs[5];
                        for (int c = 0; c < 5; c++)
                            gp2 += read_varint(gc2 + gp2, 50, &gs[c]);
                        const unsigned char *gpp = gc2 + gp2;
                        const char *gn = NULL;
                        int gn_len = 0;
                        int64_t grp = 0;
                        for (int c = 0; c < 5; c++) {
                            int st = (int)gs[c];
                            int sz = serial_type_size(st);
                            if (c == 1 && st >= 13 && st % 2 == 1) { gn = (const char *)gpp; gn_len = (st - 13) / 2; }
                            if (c == 3) { if (st == 8) grp = 0; else if (st == 9) grp = 1; else if (st >= 1 && st <= 6) grp = read_int_be(gpp, sz); }
                            gpp += sz;
                        }
                        if (gn && gn_len == (int)strlen(table_name) && memcmp(gn, table_name, (size_t)gn_len) == 0) {
                            root_page = (int)grp;
                        }
                    }
                }
            }
        }
    } else {
    }

    if (root_page < 1) {
        return -1;
    }

    /* Now read the table starting at root_page */
    /* Use a stack-based traversal for B-tree pages */
    size_t alloc_cap = 0;
    int stack[32];
    int sp = 0;
    stack[sp++] = root_page;

    while (sp > 0) {
        int pg = stack[--sp];
        const unsigned char *page = page_ptr(db, pg);
        if (!page) continue;

        int ptype = page[0];

        if (ptype == PAGE_TYPE_LEAF_TABLE) {
            read_leaf_rows(db, page, rows, count, &alloc_cap);
        } else if (ptype == PAGE_TYPE_INTERIOR_TABLE) {
            int nc = (page[3] << 8) | page[4];
            /* Rightmost child pointer */
            int rp = ((int)page[8] << 24) | ((int)page[9] << 16) |
                     ((int)page[10] << 8) | (int)page[11];
            if (sp < 31) stack[sp++] = rp;

            /* Interior cell pointers: 4 bytes each (page number in top 3 bytes) */
            const unsigned char *cp = page + INTERIOR_TABLE_HEADER_SIZE;
            for (int i = 0; i < nc; i++) {
                int child = ((int)cp[i * 4] << 24) |
                            ((int)cp[i * 4 + 1] << 16) |
                            ((int)cp[i * 4 + 2] << 8) |
                            (int)cp[i * 4 + 3];
                if (sp < 31) stack[sp++] = child;
            }
        }
    }

    return 0;
}

/* ── Get column names from CREATE TABLE SQL ──────────────────── */

/* Simple parser for: CREATE TABLE x (col1 TYPE, col2 TYPE, ...) */
int sqlite_get_columns(SqliteDb *db, const char *table_name,
                       SqliteColumns *cols) {
    cols->names = NULL;
    cols->count = 0;

    /* We need to parse sqlite_master directly */
    const unsigned char *page1 = page_ptr(db, 1);
    if (!page1) return -1;

    int pt = page1[0 + btree_offset(1)];

    /* Helper: extract name and sql from a sqlite_master leaf cell.
     * Returns 1 if this cell matches table_name. */
    #define CHECK_CELL(cell_ptr, page_ptr_base) do { \
        const unsigned char *_cell = (cell_ptr); \
        size_t _pos = 0; int64_t _pl; \
        _pos += read_varint(_cell + _pos, 50, &_pl); \
        _pos += read_varint(_cell + _pos, 50, NULL); \
        _pos += read_varint(_cell + _pos, 50, NULL); \
        int64_t _s[5]; \
        for (int _c = 0; _c < 5; _c++) \
            _pos += read_varint(_cell + _pos, 50, &_s[_c]); \
        const unsigned char *_p = _cell + _pos; \
        const char *_name = NULL; int _nl = 0; const char *_sql = NULL; \
        for (int _c = 0; _c < 5; _c++) { \
            int _st = (int)_s[_c]; int _sz = serial_type_size(_st); \
            if (_c == 1 && _st >= 13 && _st % 2 == 1) { _name = (const char *)_p; _nl = (_st - 13) / 2; } \
            if (_c == 4 && _st >= 13 && _st % 2 == 1) { _sql = (const char *)_p; } \
            _p += _sz; \
        } \
        if (_name && _nl == (int)strlen(table_name) && \
            memcmp(_name, table_name, (size_t)_nl) == 0 && _sql) { \
            found_sql = _sql; goto found_sql; \
        } \
    } while(0)

    const char *found_sql = NULL;

    if (pt == PAGE_TYPE_LEAF_TABLE) {
        const unsigned char *bt = page1 + btree_offset(1);
        int n_cells = (bt[3] << 8) | bt[4];
        for (int i = 0; i < n_cells; i++) {
            size_t cpo = btree_offset(1) + LEAF_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page1[cpo] << 8) | (size_t)page1[cpo + 1];
            CHECK_CELL(page1 + co, page1);
        }
    } else if (pt == PAGE_TYPE_INTERIOR_TABLE) {
        /* Traverse child pages */
        const unsigned char *bt = page1 + btree_offset(1);
        int nc = (bt[3] << 8) | bt[4];
        int right_child = ((int)bt[8] << 24) | ((int)bt[9] << 16) |
                          ((int)bt[10] << 8) | (int)bt[11];
        int children[256];
        int nch = 0;
        for (int i = 0; i < nc && nch < 255; i++) {
            size_t cpo = btree_offset(1) + INTERIOR_TABLE_HEADER_SIZE + (size_t)i * 2;
            size_t co = ((size_t)page1[cpo] << 8) | (size_t)page1[cpo + 1];
            const unsigned char *cell = page1 + co;
            children[nch++] = ((int)cell[0] << 24) | ((int)cell[1] << 16) |
                              ((int)cell[2] << 8) | (int)cell[3];
        }
        if (nch < 256) children[nch++] = right_child;

        for (int ci = 0; ci < nch && !found_sql; ci++) {
            const unsigned char *cp = page_ptr(db, children[ci]);
            if (!cp) continue;
            int cpt = cp[0];
            if (cpt == PAGE_TYPE_LEAF_TABLE) {
                int cn = (cp[3] << 8) | cp[4];
                for (int j = 0; j < cn && !found_sql; j++) {
                    size_t cpo2 = LEAF_TABLE_HEADER_SIZE + (size_t)j * 2;
                    size_t co2 = ((size_t)cp[cpo2] << 8) | (size_t)cp[cpo2 + 1];
                    CHECK_CELL(cp + co2, cp);
                }
            } else if (cpt == PAGE_TYPE_INTERIOR_TABLE) {
                /* One more level */
                int cc = (cp[3] << 8) | cp[4];
                int crp = ((int)cp[8] << 24) | ((int)cp[9] << 16) |
                          ((int)cp[10] << 8) | (int)cp[11];
                int gc[256]; int ngc = 0;
                for (int g = 0; g < cc && ngc < 255; g++) {
                    size_t gcpo = INTERIOR_TABLE_HEADER_SIZE + (size_t)g * 2;
                    size_t gco = ((size_t)cp[gcpo] << 8) | (size_t)cp[gcpo + 1];
                    const unsigned char *gcc = cp + gco;
                    gc[ngc++] = ((int)gcc[0] << 24) | ((int)gcc[1] << 16) |
                                ((int)gcc[2] << 8) | (int)gcc[3];
                }
                if (ngc < 256) gc[ngc++] = crp;
                for (int g = 0; g < ngc && !found_sql; g++) {
                    const unsigned char *gp = page_ptr(db, gc[g]);
                    if (!gp || gp[0] != PAGE_TYPE_LEAF_TABLE) continue;
                    int gnc = (gp[3] << 8) | gp[4];
                    for (int j = 0; j < gnc && !found_sql; j++) {
                        size_t gcpo2 = LEAF_TABLE_HEADER_SIZE + (size_t)j * 2;
                        size_t gco2 = ((size_t)gp[gcpo2] << 8) | (size_t)gp[gcpo2 + 1];
                        CHECK_CELL(gp + gco2, gp);
                    }
                }
            }
        }
    }

found_sql:
    #undef CHECK_CELL
    if (!found_sql) return -1;

    /* Parse: CREATE TABLE "tablename" ( col1 TYPE, col2 TYPE, ... ) */
    const char *open_paren = strchr(found_sql, '(');
    if (!open_paren) return -1;
    open_paren++;

    const char *close_paren = strrchr(found_sql, ')');
    if (!close_paren) return -1;

    size_t decl_len = (size_t)(close_paren - open_paren);

    /* Count commas not inside quotes */
    size_t n = 1;
    int in_quote = 0;
    for (size_t j = 0; j < decl_len; j++) {
        char c = open_paren[j];
        if (c == '\'' || c == '"') in_quote = !in_quote;
        if (c == ',' && !in_quote) n++;
    }

    cols->names = (char **)calloc(n, sizeof(char *));
    if (!cols->names) return -1;
    cols->count = n;

    /* Extract column names */
    size_t ci = 0;
    const char *cur = open_paren;
    const char *end = close_paren;

    while (ci < n && cur < end) {
        /* Skip whitespace */
        while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\n'))
            cur++;
        if (cur >= end) break;

        /* Handle quoted column names */
        if (*cur == '"' || *cur == '`' || *cur == '[') {
            char q = (*cur == '[') ? ']' : *cur;
            cur++;
            const char *start = cur;
            while (cur < end && *cur != q) cur++;
            size_t clen = (size_t)(cur - start);
            cols->names[ci] = (char *)malloc(clen + 1);
            if (cols->names[ci]) {
                memcpy(cols->names[ci], start, clen);
                cols->names[ci][clen] = 0;
            }
            cur++; /* skip closing quote */
        } else {
            const char *start = cur;
            while (cur < end && *cur != ' ' && *cur != '\t' &&
                   *cur != '\n' && *cur != ',')
                cur++;
            size_t clen = (size_t)(cur - start);
            cols->names[ci] = (char *)malloc(clen + 1);
            if (cols->names[ci]) {
                memcpy(cols->names[ci], start, clen);
                cols->names[ci][clen] = 0;
            }
        }

        /* Skip to next comma */
        while (cur < end && *cur != ',') cur++;
        if (cur < end) cur++; /* skip comma */
        ci++;
    }

    return 0;
}

/* ── Free helpers ────────────────────────────────────────────── */

void sqlite_free_rows(SqliteRow *rows, size_t count) {
    for (size_t i = 0; i < count; i++)
        free(rows[i].values);
    free(rows);
}

void sqlite_free_columns(SqliteColumns *cols) {
    for (size_t i = 0; i < cols->count; i++)
        free(cols->names[i]);
    free(cols->names);
    cols->names = NULL;
    cols->count = 0;
}
