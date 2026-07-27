package services

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

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
