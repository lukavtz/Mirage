/*
 * lz4.c — LZ4 block format compression/decompression (public domain)
 *
 * Minimal implementation for Mirage exfil payload compression.
 * No CRT dependency — uses memcpy from rt_mem.h.
 * Hash table approach: 4-byte hash, 16-bit entries (hash_log=12 -> 4KB table).
 */

#include "lz4.h"
#include <string.h>
#include <stdint.h>

/* Constants */
#define LZ4_HASH_LOG   12
#define LZ4_HASH_SIZE  (1u << LZ4_HASH_LOG)
#define LZ4_HASH_MASK  (LZ4_HASH_SIZE - 1)
#define MIN_MATCH      4
#define ML_BITS        4
#define ML_MASK        ((1u << ML_BITS) - 1)

/* Helpers */
static inline uint32_t lz4_hash32(uint32_t v) {
    return (v * 2654435761u) >> (32 - LZ4_HASH_LOG);
}

static inline uint16_t read16(const void *p) {
    uint16_t v; memcpy(&v, p, 2); return v;
}

static inline uint32_t read32(const void *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}

static inline void write16(void *p, uint16_t v) {
    memcpy(p, &v, 2);
}

int lz4_compress_bound(int src_size) {
    if (src_size <= 0) return 0;
    return src_size + (src_size / 255) + 16;
}

int lz4_compress(const char *src, char *dst, int src_size, int dst_cap) {
    if (src_size <= 0 || !src || !dst) return 0;

    /* ponytail: 16-bit hash table — works for payloads <64KB (typical);
     * aliases for larger data but compression still correct */
    uint16_t hash_table[LZ4_HASH_SIZE];
    memset(hash_table, 0, sizeof(hash_table));

    const char *ip = src;
    const char *ip_end = src + src_size;
    const char *anchor = ip;
    char *op = dst;
    const char *op_end = dst + dst_cap;

    while (ip < ip_end - MIN_MATCH) {
        uint32_t h = lz4_hash32(read32(ip));
        const char *ref = src + hash_table[h];
        hash_table[h] = (uint16_t)(ip - src);

        if (ref >= ip || (ip - ref) > 0xFFFF ||
            read32(ref) != read32(ip)) {
            ip++;
            continue;
        }

        /* Found match */
        const char *match = ip;
        const char *ref_match = ref;  /* save ref before advancing */
        ip += MIN_MATCH;
        ref += MIN_MATCH;
        const char *limit = ip_end - 8;

        while (ip <= limit) {
            uint32_t diff = read32(ip) ^ read32(ref);
            if (diff) { ip += (__builtin_ctz(diff) >> 3); break; }
            ip += 4; ref += 4;
        }
        if (ip > ip_end - 8) {
            while (ip < ip_end && *ip == *ref) { ip++; ref++; }
        }

        int match_len = (int)(ip - match) - MIN_MATCH;
        int literal_len = (int)(match - anchor);
        int offset = (int)(match - ref_match);

        /* Output */
        if (op + 4 + literal_len + 8 >= op_end) return 0;

        int ll = literal_len < ML_MASK ? literal_len : ML_MASK;
        int ml = match_len < ML_MASK ? match_len : ML_MASK;
        *op++ = (char)((ll << ML_BITS) | ml);

        if (literal_len >= ML_MASK) {
            int rem = literal_len - ML_MASK;
            while (rem >= 255) { *op++ = (char)255; rem -= 255; }
            *op++ = (char)rem;
        }

        memcpy(op, anchor, literal_len);
        op += literal_len;
        write16(op, (uint16_t)offset);
        op += 2;

        if (match_len >= ML_MASK) {
            int rem = match_len - ML_MASK;
            while (rem >= 255) { *op++ = (char)255; rem -= 255; }
            *op++ = (char)rem;
        }

        anchor = ip;
    }

    /* Last literal run */
    int last_lit = (int)(ip_end - anchor);
    if (op + 1 + (last_lit >= ML_MASK ? 1 + (last_lit - ML_MASK) / 255 : 0) + last_lit >= op_end)
        return 0;

    int ll = last_lit < ML_MASK ? last_lit : ML_MASK;
    *op++ = (char)(ll << ML_BITS);
    if (last_lit >= ML_MASK) {
        int rem = last_lit - ML_MASK;
        while (rem >= 255) { *op++ = (char)255; rem -= 255; }
        *op++ = (char)rem;
    }
    memcpy(op, anchor, last_lit);
    op += last_lit;

    return (int)(op - dst);
}

int lz4_decompress_safe(const char *src, char *dst, int src_size, int dst_cap) {
    if (src_size <= 0 || !src || !dst) return -1;

    const char *ip = src;
    const char *ip_end = src + src_size;
    char *op = dst;
    char *op_end = dst + dst_cap;

    while (ip < ip_end) {
        unsigned char token = (unsigned char)*ip++;

        /* Literals */
        int literal_len = token >> ML_BITS;
        if (literal_len == ML_MASK) {
            int extra;
            while (ip < ip_end && (extra = (unsigned char)*ip++) == 255)
                literal_len += 255;
            if (ip >= ip_end) return -1;
            literal_len += extra;
        }

        if (op + literal_len > op_end) return -1;
        if (ip + literal_len > ip_end) return -1;
        memcpy(op, ip, literal_len);
        ip += literal_len;
        op += literal_len;

        if (ip >= ip_end) break;

        /* Match */
        if (ip + 2 > ip_end) return -1;
        int offset = (int)read16(ip);
        ip += 2;
        if (offset <= 0 || offset > (int)(op - dst)) return -1;

        int match_len = (token & ML_MASK) + MIN_MATCH;
        if ((token & ML_MASK) == ML_MASK) {
            int extra;
            while (ip < ip_end && (extra = (unsigned char)*ip++) == 255)
                match_len += 255;
            if (ip >= ip_end) return -1;
            match_len += extra;
        }

        if (op + match_len > op_end) return -1;
        const char *match_src = op - offset;
        int i;
        for (i = 0; i < match_len; i++)
            op[i] = match_src[i];
        op += match_len;
    }

    return (int)(op - dst);
}
