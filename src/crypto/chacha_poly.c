/*
 * chacha_poly.c — ChaCha20-Poly1305 AEAD (RFC 8439)
 *
 * Thin adapter over Monocypher 3.1.3 primitives (CC0-1.0):
 *   - crypto_ietf_chacha20_ctr : RFC 8439 §2.4 keystream (12-byte nonce,
 *     32-bit block counter)
 *   - crypto_poly1305_*        : RFC 8439 §2.5 MAC (incremental interface)
 *   - crypto_verify16          : constant-time tag comparison
 *
 * Construction per RFC 8439 §2.8:
 *   - Poly1305 key = first 32 bytes of the ChaCha20 block with counter 0
 *   - Ciphertext   = plaintext XOR keystream starting at counter 1
 *   - Tag input    = ad || pad16 || ct || pad16 || le64(ad_len) || le64(ct_len)
 *
 * Wire format preserved: out = ciphertext || tag (16 bytes appended).
 * Returns 0 on success, -1 on error. chacha_poly_decrypt returns -1 on
 * authentication failure.
 */

#include "chacha_poly.h"
#include "monocypher.h"

#include <string.h>

/* zero block used to derive the one-time Poly1305 key (RFC 8439 §2.6) */
static void poly_key_gen(unsigned char poly_key[32],
                         const unsigned char key[CHACHA_POLY_KEY_LEN],
                         const unsigned char nonce[CHACHA_POLY_NONCE_LEN]) {
    unsigned char block0[64] = {0};
    /* counter 0 → keystream block 0; first 32 bytes are the Poly1305 key */
    crypto_ietf_chacha20_ctr(block0, block0, 64, key, nonce, 0);
    memcpy(poly_key, block0, 32);
    crypto_wipe(block0, sizeof(block0));
}

/* pad helper: append zero bytes up to the next 16-byte boundary */
static void pad16(crypto_poly1305_ctx *ctx, size_t len) {
    static const unsigned char zeros[16] = {0};
    size_t rem = (16 - (len % 16)) % 16;
    if (rem != 0)
        crypto_poly1305_update(ctx, zeros, rem);
}

static void le64(unsigned char out[8], size_t v) {
    for (int i = 0; i < 8; i++)
        out[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

/* compute the Poly1305 tag over ad || pad16 || ct || pad16 || lens */
static void compute_tag(unsigned char tag[16],
                        const unsigned char poly_key[32],
                        const unsigned char *ad, size_t ad_len,
                        const unsigned char *ct, size_t ct_len) {
    crypto_poly1305_ctx ctx;
    unsigned char lens[16];

    crypto_poly1305_init(&ctx, poly_key);
    crypto_poly1305_update(&ctx, ad, ad_len);
    pad16(&ctx, ad_len);
    crypto_poly1305_update(&ctx, ct, ct_len);
    pad16(&ctx, ct_len);
    le64(lens, ad_len);
    le64(lens + 8, ct_len);
    crypto_poly1305_update(&ctx, lens, sizeof(lens));
    crypto_poly1305_final(&ctx, tag);
}

int chacha_poly_encrypt(const unsigned char *pt, size_t pt_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len) {
    if (out_len == NULL)
        return -1;
    if (pt_len > 0 && pt == NULL)
        return -1;
    if (ad_len > 0 && ad == NULL)
        return -1;
    if (out == NULL)
        return -1;

    unsigned char poly_key[32];
    poly_key_gen(poly_key, key, nonce);

    /* ciphertext = plaintext XOR keystream from block counter 1 */
    if (pt_len > 0) {
        crypto_ietf_chacha20_ctr(out, pt, pt_len, key, nonce, 1);
    }

    /* tag over ad || pad || ct || pad || lens */
    unsigned char tag[CHACHA_POLY_TAG_LEN];
    compute_tag(tag, poly_key, ad, ad_len, out, pt_len);
    memcpy(out + pt_len, tag, CHACHA_POLY_TAG_LEN);

    *out_len = pt_len + CHACHA_POLY_TAG_LEN;
    crypto_wipe(poly_key, sizeof(poly_key));
    return 0;
}

int chacha_poly_decrypt(const unsigned char *ct, size_t ct_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len) {
    if (out_len == NULL)
        return -1;
    if (ct_len < CHACHA_POLY_TAG_LEN)
        return -1;

    size_t msg_len = ct_len - CHACHA_POLY_TAG_LEN;
    const unsigned char *tag = ct + msg_len;

    if (msg_len > 0 && ct == NULL)
        return -1;
    if (msg_len > 0 && out == NULL)
        return -1;
    if (ad_len > 0 && ad == NULL)
        return -1;

    /* verify tag first: never release plaintext on auth failure */
    unsigned char poly_key[32];
    poly_key_gen(poly_key, key, nonce);

    unsigned char tag_calc[CHACHA_POLY_TAG_LEN];
    compute_tag(tag_calc, poly_key, ad, ad_len, ct, msg_len);

    if (crypto_verify16(tag, tag_calc) != 0) {
        crypto_wipe(poly_key, sizeof(poly_key));
        return -1;   /* authentication failure */
    }

    if (msg_len > 0) {
        crypto_ietf_chacha20_ctr(out, ct, msg_len, key, nonce, 1);
    }
    *out_len = msg_len;

    crypto_wipe(poly_key, sizeof(poly_key));
    return 0;
}
