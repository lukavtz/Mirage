#ifndef FIREFOX_CRYPTO_H
#define FIREFOX_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Firefox key4.db decryption.
 *
 * Firefox stores login passwords in logins.json, encrypted with keys
 * derived from key4.db (NSS database). The key derivation uses:
 *   1. Read global-salt and password blob from metaData table
 *   2. Decrypt password blob via metaPBE (PBKDF2-SHA256 + AES-128-CBC)
 *   3. Read nssPrivate key from nssPrivate table
 *   4. Decrypt nssPrivate key via nssPBE (SHA1 + HMAC-SHA1 + 3DES-CBC)
 *   5. Use decrypted nssPrivate key to decrypt login entries
 */

/*
 * ASN.1 DER parsing helpers.
 * Firefox stores encrypted keys in ASN.1 DER format.
 */
typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} FxAsn1Reader;

int fx_asn1_read_tag(FxAsn1Reader *r, uint8_t *tag);
int fx_asn1_read_length(FxAsn1Reader *r, size_t *length);
int fx_asn1_read_sequence(FxAsn1Reader *r, FxAsn1Reader *content);
int fx_asn1_read_octet_string(FxAsn1Reader *r, const unsigned char **out, size_t *out_len);
int fx_asn1_read_integer(FxAsn1Reader *r, uint64_t *value);
int fx_asn1_read_oid(FxAsn1Reader *r, const unsigned char **out, size_t *out_len);
int fx_asn1_peek_tag(FxAsn1Reader *r, uint8_t *tag);

/*
 * 3DES-CBC decryption using BCrypt (Windows) or OpenSSL.
 * key = 24 bytes, iv = 8 bytes, data must be multiple of 8.
 * Returns 0 on success.
 */
int fx_des3_decrypt_cbc(const uint8_t *key24, const uint8_t *iv8,
                        const unsigned char *data, size_t data_len,
                        unsigned char *out, size_t out_max, size_t *out_len);

/*
 * AES-128-CBC decryption.
 * key = 16 bytes, iv = 16 bytes, data must be multiple of 16.
 * Returns 0 on success.
 */
int fx_aes128_decrypt_cbc(const uint8_t *key16, const uint8_t *iv16,
                          const unsigned char *data, size_t data_len,
                          unsigned char *out, size_t out_max, size_t *out_len);

/*
 * SHA-1 hash. Returns 20-byte digest.
 */
void fx_sha1(const unsigned char *data, size_t len, unsigned char *out20);

/*
 * HMAC-SHA1. Returns 20-byte MAC.
 */
void fx_hmac_sha1(const unsigned char *key, size_t key_len,
                  const unsigned char *data, size_t data_len,
                  unsigned char *out20);

/*
 * Decrypt NSS PBE (used for nssPrivate key).
 * Derives 3DES key via HMAC-SHA1 stretching from global_salt + master_pwd.
 * Returns decrypted key in `out`, sets `out_len`.
 */
int fx_decrypt_nss_pbe(const unsigned char *global_salt, size_t gs_len,
                       const unsigned char *master_pwd, size_t mp_len,
                       const unsigned char *enc_data, size_t enc_len,
                       unsigned char *out, size_t out_max, size_t *out_len);

/*
 * Decrypt Meta PBE (used for password blob in metaData).
 * PBKDF2-SHA256 + AES-128-CBC.
 * Returns decrypted key in `out`, sets `out_len`.
 */
int fx_decrypt_meta_pbe(const unsigned char *global_salt, size_t gs_len,
                        const unsigned char *enc_data, size_t enc_len,
                        unsigned char *out, size_t out_max, size_t *out_len);

/*
 * Decrypt a login PBE entry (used for login username/password).
 * Uses SHA1(key) as 3DES key, first 8 bytes of data as IV.
 * Returns decrypted text in `out`, sets `out_len`.
 */
int fx_decrypt_login_pbe(const unsigned char *key, size_t key_len,
                         const unsigned char *iv_and_data, size_t len,
                         unsigned char *out, size_t out_max, size_t *out_len);

/*
 * Base64 decode.
 */
int fx_base64_decode(const char *input, size_t input_len,
                     unsigned char *out, size_t out_max, size_t *out_len);

#endif
