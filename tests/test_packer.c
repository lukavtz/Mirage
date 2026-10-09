/*
 * test_packer.c — TOCTOU tests for the dir-packing TLV buffer
 *
 * Links pack_buffer_from_dir from src/system/packer.c with
 * TEST_PACKER_SEAM: the directory listing and file reads are mocked, so
 * the "file grew between the sizing pass and the read pass" TOCTOU
 * condition is deterministic on host gcc.
 *
 * Format under test: [file_count u32 LE]
 *                    { [name_len u16 LE][name][flen u32 LE][data] } * count
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -DTEST_PACKER_SEAM
 *        -o tests/test_packer tests/test_packer.c src/system/packer.c
 *        src/utils/file_utils.c (see Makefile test-packer)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

#include "packer.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

/* ── Mock directory state (two files: "a.txt", "b.txt") ─────── */
static const char *g_names[2] = {"a.txt", "b.txt"};
static int g_file_count = 2;
static int g_pass = 1;               /* 1 = sizing, 2 = read */

static size_t g_seam_size = 64;      /* size reported by pass-1 */
static int    g_seam_grow_bytes = 0; /* extra bytes read in pass-2 */

/* Seam callbacks (declared extern in packer.c under TEST_PACKER_SEAM) */
typedef HANDLE (*packer_open_dir_fn)(const char *dir, void *ffd);
typedef int    (*packer_next_fn)(HANDLE hf, void *ffd);
typedef void   (*packer_close_fn)(HANDLE hf);
typedef int    (*packer_entry_fn)(void *ffd, const char **name, size_t *name_len,
                                  size_t *size_hint, int *is_dir);

packer_open_dir_fn g_packer_open_dir;
packer_next_fn     g_packer_next;
packer_close_fn    g_packer_close;
packer_entry_fn    g_packer_entry;

static void mock_close(HANDLE hf) { (void)hf; }

/* A 2-entry listing simulated with a cursor: open() resets it,
 * next() advances and reports whether more entries remain. */
static int g_cursor = -1;
static HANDLE mock_open_dir2(const char *dir, void *ffd) {
    (void)dir; (void)ffd;
    g_cursor = 0;
    g_pass++;
    return (HANDLE)0x1234;
}
static int mock_next2(HANDLE hf, void *ffd) {
    (void)hf; (void)ffd;
    return ++g_cursor < g_file_count;
}
static int mock_entry(void *ffd, const char **name, size_t *name_len,
                      size_t *size_hint, int *is_dir) {
    (void)ffd;
    if (g_cursor >= g_file_count) { *is_dir = 1; return 0; } /* end of list */
    *name = g_names[g_cursor];
    *name_len = strlen(*name);
    *size_hint = g_seam_size;
    *is_dir = 0;
    return 0;
}

/* PEB-walk stubs: packer.c calls packer_find_ensure_api() only to resolve
 * Find* APIs, which the seam replaces — stub the resolver to "ready". */
void *mirage_get_module_by_hash(uint32_t h) { (void)h; return (void *)0x1; }
void *mirage_get_function_by_hash(void *mod, uint32_t h) { (void)mod; (void)h; return (void *)0x1; }
uint32_t mirage_encrypted_hash_module(const char *s) { (void)s; return 1; }
uint32_t mirage_encrypted_hash_func(const char *s) { (void)s; return 1; }
void *getPeb(void) { return NULL; }

/* read_file stub: returns g_seam_size + g_seam_grow_bytes deterministic
 * bytes — pass-1 sized for g_seam_size only. NULL when grow < 0. */
unsigned char *read_file(const char *path, size_t *out_len) {
    (void)path;
    if (g_seam_grow_bytes < 0) return NULL;
    size_t n = g_seam_size + (size_t)g_seam_grow_bytes;
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) buf[i] = (unsigned char)(i & 0xFF);
    *out_len = n;
    return buf;
}

static int g_pass_cnt = 0, g_fail_cnt = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail_cnt++; } else { g_pass_cnt++; } \
} while (0)

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint32_t rd16(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

/* Walk the TLV stream; 0 if fully parseable and consistent. */
static int parse_tlv(const unsigned char *buf, size_t len) {
    if (len < 4) return -1;
    uint32_t count = rd32(buf);
    size_t off = 4;
    for (uint32_t i = 0; i < count; i++) {
        if (off + 2 > len) return -1;
        uint32_t name_len = rd16(buf + off); off += 2;
        if (name_len == 0 || off + name_len > len) return -1;
        off += name_len;
        if (off + 4 > len) return -1;
        uint32_t flen = rd32(buf + off); off += 4;
        if (off + flen > len) return -1;
        off += flen;
    }
    return off == len ? 0 : -1;
}

int main(void) {
    printf("=== test_packer: TOCTOU packer ===\n");

    g_packer_open_dir = mock_open_dir2;
    g_packer_next = mock_next2;
    g_packer_close = mock_close;
    g_packer_entry = mock_entry;

    /* ── Case 1: file GROWS between passes ─────────────────────── */
    {
        g_seam_size = 64;
        g_seam_grow_bytes = 512;
        g_cursor = 0; g_pass = 0;
        size_t out_len = 0;
        unsigned char *buf = pack_buffer_from_dir("dir", &out_len, NULL);
        CHECK(buf != NULL, "grow: packer returns buffer");
        if (buf) {
            CHECK(out_len == 4 + 2 * (2 + 5 + 4 + 64 + 512), "grow: exact length");
            CHECK(parse_tlv(buf, out_len) == 0, "grow: TLV parseable, no overflow");
            free(buf);
        }
    }

    /* ── Case 2: read FAILS in pass-2 (file vanished / unreadable) ── */
    {
        g_seam_size = 64;
        g_seam_grow_bytes = -1; /* read_file → NULL */
        g_cursor = 0; g_pass = 0;
        size_t out_len = 0;
        unsigned char *buf = pack_buffer_from_dir("dir", &out_len, NULL);
        CHECK(buf != NULL, "shrink: packer returns buffer");
        if (buf) {
            uint32_t count = rd32(buf);
            CHECK(count == 2, "shrink: file count preserved");
            size_t off = 4;
            int zero_flen = 1;
            for (uint32_t i = 0; i < count; i++) {
                uint32_t name_len = rd16(buf + off); off += 2 + name_len;
                uint32_t flen = rd32(buf + off); off += 4 + flen;
                if (flen != 0) zero_flen = 0;
            }
            CHECK(zero_flen, "shrink: failed reads → zero-length entries");
            CHECK(parse_tlv(buf, out_len) == 0, "shrink: TLV parseable");
            free(buf);
        }
    }

    /* ── Case 3: empty directory ───────────────────────────────── */
    {
        g_file_count = 0;
        g_seam_size = 64;
        g_seam_grow_bytes = 0;
        g_cursor = 0; g_pass = 0;
        size_t out_len = 0;
        unsigned char *buf = pack_buffer_from_dir("dir", &out_len, NULL);
        CHECK(buf == NULL, "empty dir: returns NULL");
        g_file_count = 2;
    }

    printf("=== test_packer: %d/%d PASSED ===\n", g_pass_cnt, g_pass_cnt + g_fail_cnt);
    return g_fail_cnt == 0 ? 0 : 1;
}
