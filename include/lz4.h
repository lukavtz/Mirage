/*
 * lz4.h — LZ4 block format compression/decompression (public domain)
 *
 * No CRT dependency. Uses rt_memcpy/rt_memset from rt_mem.h.
 * Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
 */

#ifndef MIRAGE_LZ4_H
#define MIRAGE_LZ4_H

#include <stddef.h>

/* Returns max compressed size for given input size */
int lz4_compress_bound(int src_size);

/* Compress src into dst. Returns compressed size, or 0 on failure.
 * dst must be at least lz4_compress_bound(src_size) bytes. */
int lz4_compress(const char *src, char *dst, int src_size, int dst_cap);

/* Decompress src into dst. Returns decompressed size, or -1 on failure.
 * dst must be at least dst_cap bytes (caller must know original size). */
int lz4_decompress_safe(const char *src, char *dst, int src_size, int dst_cap);

#endif /* MIRAGE_LZ4_H */
