// Package builder — AES-256-GCM config injection into MIRAGECFG marker
//
// Migrated from panel/internal/services/build_service.go:63-120.
// Encrypts BuildConfig JSON into the MIRAGECFG placeholder in .rdata.
package builder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

const configMarker = "MIRAGECFG"

// InjectConfig encrypts the build config and writes it into the PE at the MIRAGECFG marker.
// Format: [marker:9][key:32][nonce:12][tag:16][ciphertext:N]
func InjectConfig(exe []byte, config interface{}) ([]byte, error) {
	idx := bytes.Index(exe, []byte(configMarker))
	if idx < 0 {
		return nil, errors.New("mi_cfg: MIRAGECFG marker not found in binary")
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("serialize config: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, jsonData, nil)

	tagSize := gcm.Overhead()
	tag := sealed[len(sealed)-tagSize:]
	ciphertext := sealed[:len(sealed)-tagSize]

	payload := make([]byte, 0, 9+32+12+16+len(sealed))
	payload = append(payload, []byte(configMarker)...)
	payload = append(payload, key...)
	payload = append(payload, nonce...)
	payload = append(payload, tag...)
	payload = append(payload, ciphertext...)

	result := make([]byte, len(exe))
	copy(result, exe)

	end := idx + len(payload)
	if end > len(result) {
		return nil, errors.New("config too large for placeholder space")
	}
	copy(result[idx:], payload)

	return result, nil
}
