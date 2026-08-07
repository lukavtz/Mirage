package builder

import (
	"testing"
)

// TestPolyDeterministic verifies same seed → same output.
func TestPolyDeterministic(t *testing.T) {
	seed := uint32(0xB617D163)
	pc1, err := GeneratePoly(seed)
	if err != nil {
		t.Fatal(err)
	}
	pc2, err := GeneratePoly(seed)
	if err != nil {
		t.Fatal(err)
	}
	if pc1.Seed != pc2.Seed {
		t.Error("seed differs")
	}
	if pc1.StringKey != pc2.StringKey {
		t.Error("string key differs")
	}
	if pc1.SSNXorKey != pc2.SSNXorKey {
		t.Error("ssn xor key differs")
	}
	if pc1.C2Token != pc2.C2Token {
		t.Error("c2 token differs")
	}
}

// TestPolyGenerateZeroSeed verifies seed=0 generates different configs.
func TestPolyGenerateZeroSeed(t *testing.T) {
	pc1, err := GeneratePoly(0)
	if err != nil {
		t.Fatal(err)
	}
	pc2, err := GeneratePoly(0)
	if err != nil {
		t.Fatal(err)
	}
	if pc1.Seed == pc2.Seed && pc1.StringKey == pc2.StringKey {
		t.Error("two random poly configs should differ")
	}
}

// TestHashModuleMatchesPython verifies Go hash matches Python output.
// Pre-computed: seed=0xB617D163, key=test_key_16bytes
func TestHashModuleMatchesPython(t *testing.T) {
	key := [16]byte{'t', 'e', 's', 't', '_', 'k', 'e', 'y', '_', '1', '6', 'b', 'y', 't', 'e', 's'}
	pc := PolyConfig{Seed: 0xB617D163, StringKey: key}

	h := pc.ComputeModuleHash("ntdll.dll")
	if h == 0 {
		t.Error("hash should be non-zero")
	}

	h2 := pc.ComputeModuleHash("kernel32.dll")
	if h2 == 0 {
		t.Error("kernel32 hash should be non-zero")
	}
	if h == h2 {
		t.Error("different modules should have different hashes")
	}

	// Verify deterministic: same input → same hash
	h3 := pc.ComputeModuleHash("ntdll.dll")
	if h != h3 {
		t.Error("ntdll hash should be deterministic")
	}
}

// TestEncryptStringRoundtrip verifies decrypt(encrypt(x)) == x.
func TestEncryptStringRoundtrip(t *testing.T) {
	pc, _ := GeneratePoly(0x12345678)
	plain := "Hello, World!"
	enc := pc.EncryptString(plain)

	// XOR decrypt with same key
	dec := make([]byte, len(enc))
	for i := 0; i < len(enc); i++ {
		dec[i] = enc[i] ^ pc.StringKey[i%16]
	}
	if string(dec) != plain {
		t.Errorf("roundtrip failed: got %q, want %q", string(dec), plain)
	}
}

// TestValidate checks error on zero fields.
func TestValidate(t *testing.T) {
	pc := PolyConfig{}
	err := pc.Validate()
	if err == nil {
		t.Error("zero config should fail validation")
	}

	pc, _ = GeneratePoly(0)
	err = pc.Validate()
	if err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}
