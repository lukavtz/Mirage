package services_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"zialfi-panel/internal/services"
)

func TestDecryptChromeV10(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("mysecretpassword123")

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	gcmOutput := gcm.Seal(nil, nonce, plaintext, nil)
	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, gcmOutput...)

	result, err := services.DecryptChromeValue(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptChromeV11(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("v11works")

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	gcmOutput := gcm.Seal(nil, nonce, plaintext, nil)
	encrypted := append([]byte("v11"), nonce...)
	encrypted = append(encrypted, gcmOutput...)

	result, err := services.DecryptChromeValue(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptInvalidVersion(t *testing.T) {
	_, err := services.DecryptChromeValue([]byte("v20xxx"), make([]byte, 32))
	if err == nil {
		t.Error("expected error for v20")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	keyA := make([]byte, 32)
	rand.Read(keyA)
	keyB := make([]byte, 32)
	rand.Read(keyB)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("secret")

	block, _ := aes.NewCipher(keyA)
	gcm, _ := cipher.NewGCM(block)
	gcmOutput := gcm.Seal(nil, nonce, plaintext, nil)
	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, gcmOutput...)

	_, err := services.DecryptChromeValue(encrypted, keyB)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestDecryptTruncated(t *testing.T) {
	_, err := services.DecryptChromeValue([]byte("v10"), make([]byte, 32))
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestChromeAesGcmDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("roundtrip-payload")

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	gcmOutput := gcm.Seal(nil, nonce, plaintext, nil)
	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, gcmOutput...)

	result, err := services.DecryptChromeValue(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}
