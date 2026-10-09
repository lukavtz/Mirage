#ifndef MIRAGE_PACKER_H
#define MIRAGE_PACKER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pack_buffer_from_dir — pack every regular file in dir into one malloc'd
 * TLV buffer: [file_count u32 LE]{ [name_len u16 LE][name][flen u32 LE][data] }*
 *
 * size_cb (TEST_PACKER_SEAM only) supplies the expected file size for the
 * allocation pass; pass NULL in production to use the directory-enumerated
 * size. TOCTOU-safe: a file that grew between passes triggers a realloc;
 * a failed/over-cap read is stored as a zero-length entry. Never overflows.
 * Returns NULL for an empty directory or allocation failure.
 */
unsigned char *pack_buffer_from_dir(const char *dir, size_t *out_len,
                                    size_t (*size_cb)(const char *path,
                                                      const char *name));

/*
 * pack_and_encrypt_dir — pack dir, LZ4-compress (optional), and encrypt
 * with archive_crypt (ChaCha20-Poly1305). Returns malloc'd buffer and
 * sets *out_len, or NULL on failure / empty directory.
 */
unsigned char *pack_and_encrypt_dir(const char *dir, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_PACKER_H */
