/*
 * chacha_poly.c — ChaCha20-Poly1305 AEAD (RFC 8439)
 *
 * Portable C11 implementation. No external dependencies.
 * Used for archive encryption and authenticated data protection.
 */

#include "chacha_poly.h"
#include "secure_zero.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 *  ChaCha20 core — RFC 8439 §2.1 / §2.2
 * ═══════════════════════════════════════════════════════════════ */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while (0)

static void chacha20_block(uint32_t out[16],
                           const uint32_t key[8],
                           const uint32_t counter,
                           const uint32_t nonce[3]) {
    uint32_t state[16];

    /* Constants */
    state[0]  = 0x61707865;  /* "expa" */
    state[1]  = 0x3320646e;  /* "nd 3" */
    state[2]  = 0x79622065;  /* "e 2b" */
    state[3]  = 0x6b206574;  /* "et k" */

    /* Key */
    state[4]  = key[0];  state[5]  = key[1];
    state[6]  = key[2];  state[7]  = key[3];
    state[8]  = key[4];  state[9]  = key[5];
    state[10] = key[6];  state[11] = key[7];

    /* Counter */
    state[12] = counter;

    /* Nonce */
    state[13] = nonce[0]; state[14] = nonce[1]; state[15] = nonce[2];

    /* Working state */
    uint32_t working[16];
    memcpy(working, state, sizeof(state));

    /* 20 rounds = 10 double-rounds */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTERROUND(working[0], working[4], working[8],  working[12]);
        QUARTERROUND(working[1], working[5], working[9],  working[13]);
        QUARTERROUND(working[2], working[6], working[10], working[14]);
        QUARTERROUND(working[3], working[7], working[11], working[15]);
        /* Diagonal rounds */
        QUARTERROUND(working[0], working[5], working[10], working[15]);
        QUARTERROUND(working[1], working[6], working[11], working[12]);
        QUARTERROUND(working[2], working[7], working[8],  working[13]);
        QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    /* Add original state */
    for (int i = 0; i < 16; i++)
        out[i] = working[i] + state[i];
}

/* XOR data with ChaCha20 keystream */
static void chacha20_crypt(unsigned char *dst,
                           const unsigned char *src, size_t len,
                           const uint32_t key[8],
                           const uint32_t nonce[3],
                           uint32_t initial_counter) {
    uint32_t block[16];
    unsigned char keystream[64];
    size_t off = 0;
    uint32_t counter = initial_counter;

    while (off < len) {
        chacha20_block(block, key, counter, nonce);

        /* Serialize block to keystream */
        for (int i = 0; i < 16; i++) {
            keystream[i * 4 + 0] = (unsigned char)(block[i]);
            keystream[i * 4 + 1] = (unsigned char)(block[i] >> 8);
            keystream[i * 4 + 2] = (unsigned char)(block[i] >> 16);
            keystream[i * 4 + 3] = (unsigned char)(block[i] >> 24);
        }

        size_t block_len = (len - off < 64) ? (len - off) : 64;
        for (size_t i = 0; i < block_len; i++)
            dst[off + i] = src[off + i] ^ keystream[i];

        off += block_len;
        counter++;
    }
}

/* ═══════════════════════════════════════════════════════════════
 *  Poly1305 — RFC 8439 §2.5
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t r[4];
    uint32_t s[4];
    uint64_t h[4];
    unsigned char buf[16];
    size_t buf_len;
} poly1305_st;

static void poly1305_init2(poly1305_st *st, const unsigned char key[32]) {
    for (int i = 0; i < 4; i++) {
        st->r[i] = (uint32_t)key[i*4]
                  | ((uint32_t)key[i*4+1] << 8)
                  | ((uint32_t)key[i*4+2] << 16)
                  | ((uint32_t)key[i*4+3] << 24);
        st->s[i] = (uint32_t)key[i*4+16]
                  | ((uint32_t)key[i*4+17] << 8)
                  | ((uint32_t)key[i*4+18] << 16)
                  | ((uint32_t)key[i*4+19] << 24);
    }
    /* Clamp r */
    st->r[0] &= 0x0fffffff; st->r[1] &= 0x0ffffffc;
    st->r[2] &= 0x0ffffffc; st->r[3] &= 0x0ffffffc;

    memset(st->h, 0, sizeof(st->h));
    st->buf_len = 0;
}

/*
 * Process a 16-byte block: h = (h + block) * r mod p
 *
 * p = 2^130 - 5
 *
 * We compute using 64-bit limbs:
 *   h = h0 + h1*2^32 + h2*2^64 + h3*2^96
 *   r = r0 + r1*2^32 + r2*2^64 + r3*2^96
 *
 * Multiply: 4x4 partial products, then reduce mod p.
 */
static void poly1305_block(poly1305_st *st, const unsigned char block[16]) {
    /* Add block to h */
    uint64_t a0 = st->h[0] + (uint64_t)block[0]
        + ((uint64_t)block[1] << 8)
        + ((uint64_t)block[2] << 16)
        + ((uint64_t)block[3] << 24);
    uint64_t a1 = st->h[1] + (uint64_t)block[4]
        + ((uint64_t)block[5] << 8)
        + ((uint64_t)block[6] << 16)
        + ((uint64_t)block[7] << 24);
    uint64_t a2 = st->h[2] + (uint64_t)block[8]
        + ((uint64_t)block[9] << 8)
        + ((uint64_t)block[10] << 16)
        + ((uint64_t)block[11] << 24);
    uint64_t a3 = st->h[3] + (uint64_t)block[12]
        + ((uint64_t)block[13] << 8)
        + ((uint64_t)block[14] << 16)
        + ((uint64_t)block[15] << 24);

    /* Multiply by r (128-bit) using 64-bit arithmetic */
    uint64_t r0 = st->r[0], r1 = st->r[1];
    uint64_t r2 = st->r[2], r3 = st->r[3];

    /* Partial products */
    uint64_t s0 = a0 * r0;
    uint64_t s1 = a0 * r1 + a1 * r0;
    uint64_t s2 = a0 * r2 + a1 * r1 + a2 * r0;
    uint64_t s3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0;
    uint64_t s4 = a1 * r3 + a2 * r2 + a3 * r1;
    uint64_t s5 = a2 * r3 + a3 * r2;
    uint64_t s6 = a3 * r3;

    /* Carry propagation */
    s1 += s0 >> 32; s0 &= 0xFFFFFFFF;
    s2 += s1 >> 32; s1 &= 0xFFFFFFFF;
    s3 += s2 >> 32; s2 &= 0xFFFFFFFF;
    s4 += s3 >> 32; s3 &= 0xFFFFFFFF;
    s5 += s4 >> 32; s4 &= 0xFFFFFFFF;
    s6 += s5 >> 32; s5 &= 0xFFFFFFFF;
    uint64_t s7 = s6 >> 32; s6 &= 0xFFFFFFFF;

    /* Reduce mod p = 2^130 - 5 */
    s0 += (s7 << 2) + s7;
    s1 += s0 >> 32; s0 &= 0xFFFFFFFF;
    s2 += s1 >> 32; s1 &= 0xFFFFFFFF;
    s3 += s2 >> 32; s2 &= 0xFFFFFFFF;

    st->h[0] = s0; st->h[1] = s1;
    st->h[2] = s2; st->h[3] = s3;
}

static void poly1305_update2(poly1305_st *st,
                             const unsigned char *data, size_t len) {
    if (st->buf_len > 0) {
        size_t need = 16 - st->buf_len;
        size_t n = (len < need) ? len : need;
        memcpy(st->buf + st->buf_len, data, n);
        st->buf_len += n;
        data += n;
        len -= n;
        if (st->buf_len == 16) {
            poly1305_block(st, st->buf);
            st->buf_len = 0;
        }
    }
    while (len >= 16) {
        poly1305_block(st, data);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        memcpy(st->buf, data, len);
        st->buf_len = len;
    }
}

static void poly1305_finish2(poly1305_st *st, unsigned char out[16]) {
    /* Pad final block */
    if (st->buf_len > 0) {
        unsigned char pad[16];
        memset(pad, 0, 16);
        memcpy(pad, st->buf, st->buf_len);
        pad[st->buf_len] = 0x01;
        poly1305_block(st, pad);
    }

    /* Compute h mod p: if h >= p, subtract p */
    uint64_t h0 = st->h[0], h1 = st->h[1];
    uint64_t h2 = st->h[2], h3 = st->h[3];

    /* Try h - (2^130 - 5) = h + 5 - 2^130 */
    uint64_t t0 = h0 + 5;
    uint64_t t1 = h1 + (t0 >> 32); t0 &= 0xFFFFFFFF;
    uint64_t t2 = h2 + (t1 >> 32); t1 &= 0xFFFFFFFF;
    uint64_t t3 = h3 + (t2 >> 32); t2 &= 0xFFFFFFFF;
    uint64_t t4 = t3 >> 32; t3 &= 0xFFFFFFFF;

    /* If t4 != 0, h >= p, use t; else use h */
    uint64_t mask = (t4 - 1);  /* 0xFFFFFFFFFFFFFFFF if h < p */

    h0 = (h0 & mask) | (t0 & ~mask);
    h1 = (h1 & mask) | (t1 & ~mask);
    h2 = (h2 & mask) | (t2 & ~mask);
    h3 = (h3 & mask) | (t3 & ~mask);

    /* Add s (128-bit) */
    uint64_t f0 = h0 + st->s[0];
    uint64_t carry = (f0 < st->s[0]) ? 1 : 0;
    uint64_t f1 = h1 + st->s[1] + carry;
    carry = (f1 < st->s[1]) ? 1 : 0;
    uint64_t f2 = h2 + st->s[2] + carry;
    carry = (f2 < st->s[2]) ? 1 : 0;
    uint64_t f3 = h3 + st->s[3] + carry;

    /* Serialize (little-endian) */
    out[0]  = (unsigned char)f0;        out[1]  = (unsigned char)(f0 >> 8);
    out[2]  = (unsigned char)(f0 >> 16); out[3]  = (unsigned char)(f0 >> 24);
    out[4]  = (unsigned char)(f0 >> 32); out[5]  = (unsigned char)(f0 >> 40);
    out[6]  = (unsigned char)(f0 >> 48); out[7]  = (unsigned char)(f0 >> 56);
    out[8]  = (unsigned char)f1;        out[9]  = (unsigned char)(f1 >> 8);
    out[10] = (unsigned char)(f1 >> 16); out[11] = (unsigned char)(f1 >> 24);
    out[12] = (unsigned char)(f1 >> 32); out[13] = (unsigned char)(f1 >> 40);
    out[14] = (unsigned char)(f1 >> 48); out[15] = (unsigned char)(f1 >> 56);
    (void)f2; (void)f3;
}

/* ═══════════════════════════════════════════════════════════════
 *  ChaCha20-Poly1305 AEAD — RFC 8439 §2.8
 * ═══════════════════════════════════════════════════════════════ */

int chacha_poly_encrypt(const unsigned char *pt, size_t pt_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len) {
    if (pt_len > SIZE_MAX - CHACHA_POLY_TAG_LEN)
        return -1;

    *out_len = pt_len + CHACHA_POLY_TAG_LEN;

    /* Convert key and nonce to little-endian words */
    uint32_t key_words[8], nonce_words[3];
    for (int i = 0; i < 8; i++)
        key_words[i] = (uint32_t)key[i*4]
            | ((uint32_t)key[i*4+1] << 8)
            | ((uint32_t)key[i*4+2] << 16)
            | ((uint32_t)key[i*4+3] << 24);
    for (int i = 0; i < 3; i++)
        nonce_words[i] = (uint32_t)nonce[i*4]
            | ((uint32_t)nonce[i*4+1] << 8)
            | ((uint32_t)nonce[i*4+2] << 16)
            | ((uint32_t)nonce[i*4+3] << 24);

    /* Encrypt with counter = 1 */
    chacha20_crypt(out, pt, pt_len, key_words, nonce_words, 1);

    /* Derive Poly1305 key from counter = 0 block */
    unsigned char poly_key[32];
    uint32_t block[16];
    chacha20_block(block, key_words, 0, nonce_words);
    for (int i = 0; i < 8; i++) {
        poly_key[i*4+0] = (unsigned char)(block[i]);
        poly_key[i*4+1] = (unsigned char)(block[i] >> 8);
        poly_key[i*4+2] = (unsigned char)(block[i] >> 16);
        poly_key[i*4+3] = (unsigned char)(block[i] >> 24);
    }

    /* Compute Poly1305 tag over: AD || pad || ciphertext || pad || AD_len || ct_len */
    poly1305_st mac;
    poly1305_init2(&mac, poly_key);

    if (ad_len > 0) {
        poly1305_update2(&mac, ad, ad_len);
        /* Pad to 16-byte boundary */
        size_t pad_len = (16 - (ad_len % 16)) % 16;
        if (pad_len > 0) {
            unsigned char zeros[16];
            memset(zeros, 0, sizeof(zeros));
            poly1305_update2(&mac, zeros, pad_len);
        }
    }

    if (pt_len > 0) {
        poly1305_update2(&mac, out, pt_len);
        size_t pad_len = (16 - (pt_len % 16)) % 16;
        if (pad_len > 0) {
            unsigned char zeros[16];
            memset(zeros, 0, sizeof(zeros));
            poly1305_update2(&mac, zeros, pad_len);
        }
    }

    /* Length block: AD length and CT length as little-endian 64-bit */
    unsigned char len_block[16];
    uint64_t ad_len_64 = ad_len;
    uint64_t ct_len_64 = pt_len;
    for (int i = 0; i < 8; i++) {
        len_block[i]   = (unsigned char)(ad_len_64 >> (i * 8));
        len_block[i+8] = (unsigned char)(ct_len_64 >> (i * 8));
    }
    poly1305_update2(&mac, len_block, 16);

    /* Finalize */
    poly1305_finish2(&mac, out + pt_len);

    mirage_secure_zero(poly_key, 32);
    return 0;
}

int chacha_poly_decrypt(const unsigned char *ct, size_t ct_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len) {
    if (ct_len < CHACHA_POLY_TAG_LEN)
        return -1;

    size_t msg_len = ct_len - CHACHA_POLY_TAG_LEN;
    *out_len = msg_len;

    /* Convert key and nonce to little-endian words */
    uint32_t key_words[8], nonce_words[3];
    for (int i = 0; i < 8; i++)
        key_words[i] = (uint32_t)key[i*4]
            | ((uint32_t)key[i*4+1] << 8)
            | ((uint32_t)key[i*4+2] << 16)
            | ((uint32_t)key[i*4+3] << 24);
    for (int i = 0; i < 3; i++)
        nonce_words[i] = (uint32_t)nonce[i*4]
            | ((uint32_t)nonce[i*4+1] << 8)
            | ((uint32_t)nonce[i*4+2] << 16)
            | ((uint32_t)nonce[i*4+3] << 24);

    /* Derive Poly1305 key */
    unsigned char poly_key[32];
    uint32_t block[16];
    chacha20_block(block, key_words, 0, nonce_words);
    for (int i = 0; i < 8; i++) {
        poly_key[i*4+0] = (unsigned char)(block[i]);
        poly_key[i*4+1] = (unsigned char)(block[i] >> 8);
        poly_key[i*4+2] = (unsigned char)(block[i] >> 16);
        poly_key[i*4+3] = (unsigned char)(block[i] >> 24);
    }

    /* Compute expected tag */
    poly1305_st mac;
    poly1305_init2(&mac, poly_key);

    if (ad_len > 0) {
        poly1305_update2(&mac, ad, ad_len);
        size_t pad_len = (16 - (ad_len % 16)) % 16;
        if (pad_len > 0) {
            unsigned char zeros[16];
            memset(zeros, 0, sizeof(zeros));
            poly1305_update2(&mac, zeros, pad_len);
        }
    }

    if (msg_len > 0) {
        poly1305_update2(&mac, ct, msg_len);
        size_t pad_len = (16 - (msg_len % 16)) % 16;
        if (pad_len > 0) {
            unsigned char zeros[16];
            memset(zeros, 0, sizeof(zeros));
            poly1305_update2(&mac, zeros, pad_len);
        }
    }

    unsigned char len_block[16];
    uint64_t ad_len_64 = ad_len;
    uint64_t ct_len_64 = msg_len;
    for (int i = 0; i < 8; i++) {
        len_block[i]   = (unsigned char)(ad_len_64 >> (i * 8));
        len_block[i+8] = (unsigned char)(ct_len_64 >> (i * 8));
    }
    poly1305_update2(&mac, len_block, 16);

    unsigned char expected_tag[16];
    poly1305_finish2(&mac, expected_tag);

    /* Constant-time tag comparison */
    const unsigned char *actual_tag = ct + msg_len;
    unsigned char diff = 0;
    for (int i = 0; i < CHACHA_POLY_TAG_LEN; i++)
        diff |= expected_tag[i] ^ actual_tag[i];

    if (diff != 0)
        return -1;

    /* Decrypt */
    chacha20_crypt(out, ct, msg_len, key_words, nonce_words, 1);

    mirage_secure_zero(poly_key, 32);
    return 0;
}
