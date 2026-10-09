package services

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// MIRAGE_SEED (0xAD75E594 from include/config.h) as 4-byte little-endian +
// 4 zero bytes — must stay in sync with the C stealer's config.h.
// NOTE: this constant must be regenerated from include/config.h MIRAGE_SEED
// after every make_polymorphic.py run (the generator randomizes the seed).
// A make_polymorphic.py rewrite of this Go constant is planned separately;
// until then this file must be kept manually synced.
var archiveSeed = []byte{148, 229, 117, 173, 0, 0, 0, 0}

const archivePBKDF2Iter = 210000

var errNotArchive = errors.New("not a Mirage archive")

// DecryptArchive attempts to decrypt a ChaCha20-Poly1305 envelope.
// Wire format: [nonce:12][salt:16][ciphertext][tag:16]
// Returns the plaintext (which may still be LZ4-compressed) or an error.
// If the input is too short or decryption fails, returns errNotArchive
// so the caller can fall back to treating it as a plain ZIP.
func DecryptArchive(data []byte) ([]byte, error) {
	const headerLen = 28 // nonce(12) + salt(16)
	const tagLen = 16

	if len(data) < headerLen+tagLen {
		return nil, errNotArchive
	}

	nonce := data[:12]
	salt := data[12:headerLen]
	payload := data[headerLen:]

	// PBKDF2-SHA256 key derivation
	key := pbkdf2.Key(archiveSeed, salt, archivePBKDF2Iter, 32, sha256.New)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Open expects ciphertext+tag concatenated
	plaintext, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, errNotArchive
	}
	return plaintext, nil
}
