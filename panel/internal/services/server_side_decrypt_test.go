package services_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

// ── ExtractMasterKey tests ──────────────────────────────────────

func TestExtractMasterKey_DPAPI(t *testing.T) {
	rawKey := []byte("0123456789abcdef0123456789abcdef")
	dpapiBlob := append([]byte("DPAPI"), rawKey...)
	b64 := base64.StdEncoding.EncodeToString(dpapiBlob)
	localState := buildLocalState(b64)

	ek, err := services.ExtractMasterKey(localState)
	if err != nil {
		t.Fatal(err)
	}
	if ek.Type != services.KeyTypeDPAPI {
		t.Errorf("expected KeyTypeDPAPI, got %d", ek.Type)
	}
	if !bytes.Equal(ek.Raw, rawKey) {
		t.Errorf("expected raw key %x, got %x", rawKey, ek.Raw)
	}
}

func TestExtractMasterKey_AppBound(t *testing.T) {
	rawKey := []byte("abcdef0123456789abcdef0123456789")
	appbBlob := append([]byte("APPB"), rawKey...)
	b64 := base64.StdEncoding.EncodeToString(appbBlob)
	localState := buildLocalState(b64)

	ek, err := services.ExtractMasterKey(localState)
	if err != nil {
		t.Fatal(err)
	}
	if ek.Type != services.KeyTypeAppBound {
		t.Errorf("expected KeyTypeAppBound, got %d", ek.Type)
	}
	if !bytes.Equal(ek.Raw, rawKey) {
		t.Errorf("expected raw key %x, got %x", rawKey, ek.Raw)
	}
}

func TestExtractMasterKey_Raw(t *testing.T) {
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(rawKey)
	localState := buildLocalState(b64)

	ek, err := services.ExtractMasterKey(localState)
	if err != nil {
		t.Fatal(err)
	}
	if ek.Type != services.KeyTypeRaw {
		t.Errorf("expected KeyTypeRaw, got %d", ek.Type)
	}
	if !bytes.Equal(ek.Raw, rawKey) {
		t.Errorf("raw key mismatch")
	}
}

func TestExtractMasterKey_MissingOsCrypt(t *testing.T) {
	localState := []byte(`{"other": "data"}`)
	_, err := services.ExtractMasterKey(localState)
	if err == nil {
		t.Error("expected error for missing os_crypt")
	}
}

func TestExtractMasterKey_MalformedBase64(t *testing.T) {
	localState := []byte(`{"os_crypt": {"encrypted_key": "not!!!valid!!!base64"}}`)
	_, err := services.ExtractMasterKey(localState)
	if err == nil {
		t.Error("expected error for malformed base64")
	}
}

// ── Helpers ─────────────────────────────────────────────────────

func buildLocalState(b64Key string) []byte {
	doc := map[string]interface{}{
		"os_crypt": map[string]interface{}{
			"encrypted_key": b64Key,
		},
	}
	data, _ := json.Marshal(doc)
	return data
}
