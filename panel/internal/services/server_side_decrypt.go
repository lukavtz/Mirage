package services

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// KeyType describes how the encrypted key in Local State was protected.
type KeyType int

const (
	KeyTypeUnknown  KeyType = iota
	KeyTypeDPAPI            // "DPAPI" prefix — Windows CryptUnprotectData
	KeyTypeAppBound         // "APPB" prefix — COM IElevator
	KeyTypeRaw              // no prefix — already a raw AES key
)

// ExtractedKey holds the result of parsing os_crypt.encrypted_key from Local State.
type ExtractedKey struct {
	Raw  []byte // the decoded bytes after stripping the prefix
	Type KeyType
}

// ExtractMasterKey parses Chrome's Local State JSON and extracts the encrypted key.
// Since the panel runs on Linux and cannot call DPAPI/COM, the returned key
// still needs decryption on the client side. The caller should check KeyType:
//   - KeyTypeRaw: key might already be usable (unlikely in production)
//   - KeyTypeDPAPI/KeyTypeAppBound: client must provide the decrypted 32-byte key
//     via a separate master_key.bin file in the archive.
func ExtractMasterKey(localState []byte) (*ExtractedKey, error) {
	var doc struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(localState, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse Local State JSON: %w", err)
	}
	if doc.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("os_crypt.encrypted_key not found")
	}

	decoded, err := base64.StdEncoding.DecodeString(doc.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode encrypted_key: %w", err)
	}

	result := &ExtractedKey{Raw: decoded}

	// Detect prefix
	if len(decoded) >= 4 && string(decoded[:4]) == "APPB" {
		result.Type = KeyTypeAppBound
		result.Raw = decoded[4:]
	} else if len(decoded) >= 5 && string(decoded[:5]) == "DPAPI" {
		result.Type = KeyTypeDPAPI
		result.Raw = decoded[5:]
	} else {
		result.Type = KeyTypeRaw
	}

	return result, nil
}

// DecryptChromeValue decrypts a v10/v11 encrypted value using a 32-byte AES key.
func DecryptChromeValue(encrypted []byte, key []byte) ([]byte, error) {
	if len(encrypted) < 31 {
		return nil, fmt.Errorf("encrypted value too short")
	}
	if string(encrypted[:3]) != "v10" && string(encrypted[:3]) != "v11" {
		return nil, fmt.Errorf("unsupported version: %s", encrypted[:3])
	}

	payload := encrypted[3:]
	if len(payload) < 28 {
		return nil, fmt.Errorf("payload too short")
	}

	nonce := payload[:12]
	ciphertext := payload[12 : len(payload)-16]
	tag := payload[len(payload)-16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, append(ciphertext, tag...), nil)
}
