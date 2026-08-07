package builder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInjectIconEmpty(t *testing.T) {
	exe := makeMinimalPE(1)
	result, err := InjectIcon(exe, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, exe) {
		t.Error("nil icoData should return exe unchanged")
	}
}

func TestInjectIconEmptyData(t *testing.T) {
	exe := makeMinimalPE(1)
	result, err := InjectIcon(exe, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, exe) {
		t.Error("empty icoData should return exe unchanged")
	}
}

func TestInjectIconNonPE(t *testing.T) {
	notPE := []byte{0x00, 0x01, 0x02, 0x03}
	icoData := make([]byte, 100)
	result, err := InjectIcon(notPE, icoData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, notPE) {
		t.Error("non-PE input should return exe unchanged")
	}
}

func TestInjectIconShortExe(t *testing.T) {
	exe := make([]byte, 0x1FF)
	icoData := make([]byte, 100)
	result, err := InjectIcon(exe, icoData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, exe) {
		t.Error("short exe should return unchanged")
	}
}

func TestInjectIconValid(t *testing.T) {
	exe := makeMinimalPE(1)
	icoData := make([]byte, 256)

	peOff := int(binary.LittleEndian.Uint32(exe[0x3C:0x40]))
	origSecCount := int(binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8]))

	result, err := InjectIcon(exe, icoData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) <= len(exe) {
		t.Fatal("result should be larger than original")
	}

	// Section count incremented
	newSecCount := int(binary.LittleEndian.Uint16(result[peOff+6 : peOff+8]))
	if newSecCount != origSecCount+1 {
		t.Errorf("section count: got %d, want %d", newSecCount, origSecCount+1)
	}

	// .icon section header is appended at end of result (last 40 bytes)
	last40 := result[len(result)-40:]
	if !bytes.HasPrefix(last40[:6], []byte(".icon")) {
		t.Fatal(".icon section header not found in last 40 bytes")
	}
	vSize := binary.LittleEndian.Uint32(last40[8:12])
	if vSize != uint32(len(icoData)) {
		t.Errorf("virtual size: got %d, want %d", vSize, len(icoData))
	}

	// Icon data present immediately after original exe
	iconStart := len(exe)
	if !bytes.HasPrefix(result[iconStart:], icoData) {
		t.Error("icoData not found at expected offset in result")
	}
}

func TestInjectIconIdempotent(t *testing.T) {
	exe := makeMinimalPE(1)
	icoData := make([]byte, 100)

	first, err := InjectIcon(exe, icoData)
	if err != nil {
		t.Fatalf("first inject: %v", err)
	}

	second, err := InjectIcon(first, icoData)
	if err != nil {
		t.Fatalf("second inject: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("second injection should be a no-op")
	}

	peOff := int(binary.LittleEndian.Uint32(exe[0x3C:0x40]))
	origSecCount := int(binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8]))
	secCount2 := int(binary.LittleEndian.Uint16(second[peOff+6 : peOff+8]))
	if secCount2 != origSecCount+1 {
		t.Error("section count should not increase on second injection")
	}
}
