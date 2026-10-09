package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"github.com/pierrec/lz4/v4"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func TestDecryptArchive_ValidRoundtrip(t *testing.T) {
	plaintext := []byte("hello from Mirage C stealer, this is test data for roundtrip verification")

	// Encrypt using the same parameters as the C stealer
	seed := []byte{148, 229, 117, 173, 0, 0, 0, 0} // 0xAD75E594 LE — keep in sync with archiveSeed / MIRAGE_SEED
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 0x10)
	}

	key := pbkdf2.Key(seed, salt, 210000, 32, sha256.New)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Build wire format: [nonce:12][salt:16][ciphertext+tag]
	wire := make([]byte, 0, 12+16+len(ciphertext))
	wire = append(wire, nonce...)
	wire = append(wire, salt...)
	wire = append(wire, ciphertext...)

	result, err := DecryptArchive(wire)
	if err != nil {
		t.Fatalf("DecryptArchive: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", result, plaintext)
	}
}

func TestDecryptArchive_TooShort(t *testing.T) {
	_, err := DecryptArchive([]byte{0x01, 0x02, 0x03})
	if err != errNotArchive {
		t.Errorf("expected errNotArchive, got %v", err)
	}
}

func TestDecryptArchive_WrongKey(t *testing.T) {
	// Encrypt with a different seed
	wrongSeed := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)

	key := pbkdf2.Key(wrongSeed, salt, 210000, 32, sha256.New)
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(nil, nonce, []byte("test"), nil)

	wire := append(append(nonce, salt...), ciphertext...)

	_, err := DecryptArchive(wire)
	if err != errNotArchive {
		t.Errorf("expected errNotArchive (wrong key), got %v", err)
	}
}

func TestDecompressLZ4_Roundtrip(t *testing.T) {
	original := bytes.Repeat([]byte("ABCD"), 1000) // 4000 bytes, highly compressible

	// Compress
	bound := lz4.CompressBlockBound(len(original))
	compressed := make([]byte, bound)
	n, err := lz4.CompressBlock(original, compressed, nil)
	if err != nil {
		t.Fatalf("CompressBlock: %v", err)
	}
	compressed = compressed[:n]

	// Build Mirage format: [magic:0x01][orig_size:4_LE][compressed]
	wire := make([]byte, 5+len(compressed))
	wire[0] = 0x01
	binary.LittleEndian.PutUint32(wire[1:5], uint32(len(original)))
	copy(wire[5:], compressed)

	result, err := DecompressLZ4(wire)
	if err != nil {
		t.Fatalf("DecompressLZ4: %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Errorf("LZ4 roundtrip mismatch: got %d bytes, want %d", len(result), len(original))
	}
}

func TestDecompressLZ4_NoMagic(t *testing.T) {
	_, err := DecompressLZ4([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	if err != errNotLZ4 {
		t.Errorf("expected errNotLZ4, got %v", err)
	}
}

func TestDecompressLZ4_TooShort(t *testing.T) {
	_, err := DecompressLZ4([]byte{0x01, 0x02})
	if err != errNotLZ4 {
		t.Errorf("expected errNotLZ4, got %v", err)
	}
}

func TestDecryptAndDecompress_FullPipeline(t *testing.T) {
	// Simulate the full C stealer pipeline: TLV -> LZ4 -> ChaCha20
	original := bytes.Repeat([]byte("MIRAGE_TEST_DATA"), 256) // 4096 bytes

	// Step 1: LZ4 compress with Mirage format
	bound := lz4.CompressBlockBound(len(original))
	compressed := make([]byte, bound)
	n, _ := lz4.CompressBlock(original, compressed, nil)
	compressed = compressed[:n]

	// Build LZ4 payload: [magic:0x01][orig_size:4_LE][compressed]
	lz4Payload := make([]byte, 5+len(compressed))
	lz4Payload[0] = 0x01
	binary.LittleEndian.PutUint32(lz4Payload[1:5], uint32(len(original)))
	copy(lz4Payload[5:], compressed)

	// Step 2: ChaCha20-Poly1305 encrypt
	seed := []byte{0x94, 0xE5, 0x75, 0xAD, 0x00, 0x00, 0x00, 0x00} // 0xAD75E594 LE — current MIRAGE_SEED, sync with archiveSeed
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x42)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 0xAA)
	}

	key := pbkdf2.Key(seed, salt, 210000, 32, sha256.New)
	aead, _ := chacha20poly1305.New(key)
	ciphertext := aead.Seal(nil, nonce, lz4Payload, nil)

	// Build wire: [nonce:12][salt:16][ciphertext+tag]
	wire := append(append(nonce, salt...), ciphertext...)

	// Step 3: DecryptArchive
	decrypted, err := DecryptArchive(wire)
	if err != nil {
		t.Fatalf("DecryptArchive: %v", err)
	}

	// Step 4: DecompressLZ4
	result, err := DecompressLZ4(decrypted)
	if err != nil {
		t.Fatalf("DecompressLZ4: %v", err)
	}

	if !bytes.Equal(result, original) {
		t.Errorf("full pipeline mismatch: got %d bytes, want %d", len(result), len(original))
	}
}

// Verify that the AES-GCM Chrome decrypt still works (regression test for existing code)
func TestDecryptChromeValue_ExistingStillWorks(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Build a v10 encrypted value: "v10" + nonce(12) + ciphertext + tag(16)
	plaintext := []byte("test_password_12345")
	nonce := make([]byte, 12)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	v10payload := append([]byte("v10"), append(nonce, ciphertext...)...)

	result, err := DecryptChromeValue(v10payload, key)
	if err != nil {
		t.Fatalf("DecryptChromeValue: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("Chrome decrypt mismatch")
	}
}

// TestDecryptArchive_CSamples is the C→Go interop lock: the fixture
// ../../testdata/archive_sample.bin (package cwd = panel/internal/services) is
// generated by the C stealer's real archive_encrypt (tests/test_interop_gen.c,
// target test-interop-gen) using PBKDF2-SHA256(210000) over MIRAGE_SEED and
// RFC 8439 ChaCha20-Poly1305. Go's x/crypto must decrypt it to the exact
// 1024-byte pattern (byte i = i%251).
func TestDecryptArchive_CSamples(t *testing.T) {
	data, err := os.ReadFile("../../testdata/archive_sample.bin")
	if err != nil {
		t.Skipf("fixture not present (run `mingw32-make test-interop-gen`): %v", err)
	}

	plain, err := DecryptArchive(data)
	if err != nil {
		t.Fatalf("DecryptArchive of C-generated fixture: %v", err)
	}

	const wantLen = 1024
	if len(plain) != wantLen {
		t.Fatalf("plaintext length mismatch: got %d, want %d", len(plain), wantLen)
	}
	for i := range wantLen {
		if plain[i] != byte(i%251) {
			t.Fatalf("plaintext mismatch at byte %d: got %d, want %d", i, plain[i], byte(i%251))
		}
	}
}
