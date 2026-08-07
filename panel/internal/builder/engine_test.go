package builder

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	e, err := New(Config{})
	if err == nil {
		t.Error("expected error for empty TemplatePath")
	}
	if e != nil {
		t.Error("expected nil engine on error")
	}
}

func TestBuild_NoTemplate(t *testing.T) {
	e := &Engine{}
	_, err := e.Build(nil, PolyConfig{Seed: 1, SSNXorKey: 2})
	if err == nil {
		t.Error("expected error for nil template")
	}
}

func TestBuildMiCfgConfig(t *testing.T) {
	pc := PolyConfig{
		Seed:      0xDEADBEEF,
		StringKey: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		SSNXorKey: 0xCAFEBABE,
	}
	cfg := buildMiCfgConfig(pc)

	if cfg.Seed != pc.Seed {
		t.Errorf("Seed = 0x%x, want 0x%x", cfg.Seed, pc.Seed)
	}
	if cfg.SSNXorKey != pc.SSNXorKey {
		t.Errorf("SSNXorKey = 0x%x, want 0x%x", cfg.SSNXorKey, pc.SSNXorKey)
	}
	if !bytes.Equal(cfg.StringKey[:], pc.StringKey[:]) {
		t.Error("StringKey mismatch")
	}
}

func TestEngine_BuildWithTemplate(t *testing.T) {
	// Build a minimal PE template
	tmpl := make([]byte, 0x200)
	copy(tmpl[0:2], "MZ")
	// ... This would need full PE structure for Morph + PE Mutate + MiCfg + Config injection
	// Skipping full integration test - covered by build_test.go in API layer
	t.Skip("requires full PE template")
}
