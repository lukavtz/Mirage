package builder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPeMutate_ValidPE(t *testing.T) {
	exe := makeMinimalPE(1)
	result := peMutate(bytes.Clone(exe))
	
	peOff := binary.LittleEndian.Uint32(result[0x3C:0x40])
	
	// Timestamp should have changed  
	timestamp := binary.LittleEndian.Uint32(result[peOff+8:peOff+12])
	if timestamp == 0 {
		t.Log("timestamp is 0 (possible, but unlikely)")
	}
	
	// Checksum should be non-zero after repair
	checksumOff := int(peOff) + 24 + 64
	checksum := binary.LittleEndian.Uint32(result[checksumOff:checksumOff+4])
	if checksum == 0 {
		t.Error("checksum should be non-zero after repair")
	}
	
	// Verify result is valid PE
	if !bytes.HasPrefix(result, []byte("MZ")) {
		t.Error("output should start with MZ")
	}
}

func TestPeMutate_NonPE(t *testing.T) {
	tests := []struct{
		name string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short_MZ", []byte("MZ")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := peMutate(tt.input)
			if tt.input == nil && result != nil {
				t.Error("nil input should return nil")
			}
		})
	}
}

func TestNullifyChecksum(t *testing.T) {
	exe := makeMinimalPE(1)
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	checksumOff := int(peOff) + 24 + 64

	binary.LittleEndian.PutUint32(exe[checksumOff:checksumOff+4], 0x12345678)
	nullifyChecksum(exe)
	
	got := binary.LittleEndian.Uint32(exe[checksumOff:checksumOff+4])
	if got != 0 {
		t.Errorf("checksum = 0x%x, want 0", got)
	}
}

func TestRandomizeSectionNames(t *testing.T) {
	exe := makeMinimalPE(1)
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	optHdrSize := int(binary.LittleEndian.Uint16(exe[peOff+20:peOff+22]))
	secTable := int(peOff) + 24 + optHdrSize

	origName := make([]byte, 8)
	copy(origName, exe[secTable:secTable+8])

	randomizeSectionNames(exe)
	
	newName := make([]byte, 8)
	copy(newName, exe[secTable:secTable+8])
	// Should be different from original if original was .text
	if bytes.Equal(newName, origName) && bytes.Equal(origName, []byte(".text\x00\x00\x00")) {
		t.Error("section name should have been randomized")
	}
}

func TestStripDebugDirectory(t *testing.T) {
	exe := makeMinimalPE(1)
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	optHdrSize := int(binary.LittleEndian.Uint16(exe[peOff+20:peOff+22]))
	dataDirOff := int(peOff) + 24 + optHdrSize - 16*8
	debugOff := dataDirOff + 6*8

	stripDebugDirectory(exe)

	va := binary.LittleEndian.Uint32(exe[debugOff:debugOff+4])
	sz := binary.LittleEndian.Uint32(exe[debugOff+4:debugOff+8])
	if va != 0 || sz != 0 {
		t.Errorf("debug dir should be zeroed: VA=0x%x Size=0x%x", va, sz)
	}
}

func TestRepairChecksum(t *testing.T) {
	exe := makeMinimalPE(1)
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	checksumOff := int(peOff) + 24 + 64

	binary.LittleEndian.PutUint32(exe[checksumOff:checksumOff+4], 0)
	repairChecksum(exe)

	got := binary.LittleEndian.Uint32(exe[checksumOff:checksumOff+4])
	if got == 0 {
		t.Error("repairChecksum should compute non-zero checksum")
	}
}

func TestPeMutate_RandomOutputs(t *testing.T) {
	exe := makeMinimalPE(1)
	r1 := peMutate(bytes.Clone(exe))
	r2 := peMutate(bytes.Clone(exe))

	// At least timestamp should differ
	if bytes.Equal(r1, r2) {
		t.Error("two mutations should produce different outputs")
	}
}

func TestStripRichHeader_Found(t *testing.T) {
	exe := makeMinimalPE(1)
	richOff := 0xA0
	copy(exe[richOff:richOff+4], "Rich")
	binary.LittleEndian.PutUint32(exe[richOff+4:richOff+8], 0xDEADBEEF)
	
	stripRichHeader(exe)
	
	cleared := true
	for i := 0x80; i < richOff+8 && i < len(exe); i++ {
		if exe[i] != 0 {
			cleared = false
			break
		}
	}
	if !cleared {
		t.Error("Rich header area should be zeroed after strip")
	}
}

func TestEngineNew_ValidPath(t *testing.T) {
	e, err := New(Config{TemplatePath: "/tmp/fake"})
	if err != nil {
		t.Fatalf("New should not fail on valid TemplatePath: %v", err)
	}
	if e == nil {
		t.Error("expected non-nil engine")
	}
}

func TestPeMutate_ShortExe(t *testing.T) {
	short := make([]byte, 0x100)
	copy(short[0:2], "MZ")
	result := peMutate(short)
	if len(result) != 0x100 {
		t.Error("short exe should be returned as-is")
	}
}
