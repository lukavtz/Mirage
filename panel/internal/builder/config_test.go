package builder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestInjectConfig_NoSignature(t *testing.T) {
	exe := []byte("MZ... not a real PE but no MIRAGECFG")
	_, err := InjectConfig(exe, struct{}{})
	if err == nil {
		t.Error("expected error for missing MIRAGECFG signature")
	}
}

func TestInjectConfig_WithPlaceholder(t *testing.T) {
	// Create exe with MIRAGECFG placeholder
	placeholder := bytes.Repeat([]byte{0}, 9+32+12+16+256) // sig + key + nonce + tag + room for ciphertext
	copy(placeholder[:9], "MIRAGECFG")
	
	exe := make([]byte, 0x400)
	copy(exe[0:2], "MZ")
	copy(exe[0x100:], placeholder)

	config := struct {
		C2Host string
		C2Port int
	}{"test.local", 4433}

	result, err := InjectConfig(exe, config)
	if err != nil {
		t.Fatalf("InjectConfig failed: %v", err)
	}

	// Verify MIRAGECFG marker still present at original offset
	sigIdx := bytes.Index(result, []byte("MIRAGECFG"))
	if sigIdx < 0 {
		t.Error("MIRAGECFG marker not found in result")
	}

	// Verify result contains encrypted+keyed data (not just zeros)
	afterSig := result[sigIdx+9 : sigIdx+9+32+12+16]
	allZero := true
	for _, b := range afterSig {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("encrypted payload appears to be all zeros")
	}

	_ = aes.NewCipher
	_ = cipher.NewGCM
	_ = rand.Read
	_ = json.Marshal
}
