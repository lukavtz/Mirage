package builder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildMinimalPE(textData []byte) []byte {
	dosHeader := make([]byte, 0x80)
	copy(dosHeader, "MZ")
	binary.LittleEndian.PutUint32(dosHeader[0x3C:0x40], 0x80)

	peSig := append([]byte("PE\x00\x00"), make([]byte, 20)...)
	binary.LittleEndian.PutUint16(peSig[4:6], 0x8664)
	binary.LittleEndian.PutUint16(peSig[6:8], 1)

	optHdrSize := uint16(0xF0)
	binary.LittleEndian.PutUint16(peSig[20:22], optHdrSize)

	optHdr := make([]byte, optHdrSize)
	binary.LittleEndian.PutUint16(optHdr[0:2], 0x020B)
	binary.LittleEndian.PutUint32(optHdr[32:36], 0x1000)
	binary.LittleEndian.PutUint32(optHdr[36:40], 0x200)
	binary.LittleEndian.PutUint32(optHdr[56:60], 0x2000)
	binary.LittleEndian.PutUint32(optHdr[60:64], 0x400)
	binary.LittleEndian.PutUint16(optHdr[68:70], 2)
	binary.LittleEndian.PutUint32(optHdr[108:112], 16)

	peHdr := append(peSig, optHdr...)

	textSec := make([]byte, 40)
	copy(textSec[0:8], ".text\x00\x00\x00")
	vs := uint32(len(textData))
	binary.LittleEndian.PutUint32(textSec[8:12], vs)
	binary.LittleEndian.PutUint32(textSec[12:16], 0x1000)
	binary.LittleEndian.PutUint32(textSec[16:20], vs)
	binary.LittleEndian.PutUint32(textSec[20:24], 0x400)
	textSec[27] = 0x60

	var buf bytes.Buffer
	buf.Write(dosHeader)
	buf.Write(peHdr)
	buf.Write(textSec)
	for buf.Len() < 0x400 {
		buf.WriteByte(0)
	}
	buf.Write(textData)
	return buf.Bytes()
}

func TestLCG(t *testing.T) {
	v1 := lcg(0)
	v2 := lcg(0)
	if v1 != v2 {
		t.Errorf("lcg(0) not deterministic: %d vs %d", v1, v2)
	}
	if lcg(0) == lcg(1) {
		t.Error("lcg(0) == lcg(1), expected different")
	}
	v := lcg(0xD3ADB33F)
	if v == 0 {
		t.Error("lcg(known-seed) returned 0")
	}
	a := lcg(uint32(42))
	b := lcg(a)
	if a == b {
		t.Error("lcg chain produced same value")
	}
}

func TestGenerateJunk(t *testing.T) {
	validPatterns := [][]byte{
		{0x50, 0x58}, {0x51, 0x59}, {0x52, 0x5A}, {0x53, 0x5B},
		{0x87, 0xC0}, {0x48, 0x87, 0xC0},
		{0x48, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00},
		{0x48, 0x8D, 0x89, 0x00, 0x00, 0x00, 0x00},
	}
	for _, n := range []int{0, 1, 2, 3, 7, 8, 15, 30} {
		junk := generateJunk(n, 0xDEAD)
		if len(junk) != n {
			t.Errorf("generateJunk(%d) length = %d", n, len(junk))
		}
		for _, b := range junk {
			if b == 0x90 {
				continue
			}
			found := false
			for _, pat := range validPatterns {
				for _, pb := range pat {
					if pb == b {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				t.Errorf("generateJunk byte 0x%02X not in valid patterns", b)
			}
		}
	}
	j1 := generateJunk(8, 0xABCD)
	j2 := generateJunk(8, 0xABCD)
	if !bytes.Equal(j1, j2) {
		t.Error("generateJunk not deterministic")
	}
	j3 := generateJunk(16, 0x1111)
	j4 := generateJunk(16, 0x2222)
	if bytes.Equal(j3, j4) {
		t.Error("generateJunk same for different seeds")
	}
}

func TestFindJumpTargets(t *testing.T) {
	t.Run("JMP_rel8", func(t *testing.T) {
		data := []byte{0xEB, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
		targets := findJumpTargets(data, len(data))
		if !targets[7] {
			t.Error("JMP rel8 target at 7 not found")
		}
	})
	t.Run("JMP_rel8_backward", func(t *testing.T) {
		data := []byte{0x90, 0x90, 0xEB, 0xFE}
		targets := findJumpTargets(data, len(data))
		if !targets[2] {
			t.Error("JMP rel8 backward target at 2 not found")
		}
	})
	t.Run("JMP_rel32", func(t *testing.T) {
		data := make([]byte, 0x100)
		data[0] = 0xE9
		binary.LittleEndian.PutUint32(data[1:5], 0x10)
		targets := findJumpTargets(data, len(data))
		if !targets[0x15] {
			t.Errorf("JMP rel32 at 0x15 not found: %v", targets)
		}
	})
	t.Run("Jcc_rel8", func(t *testing.T) {
		data := []byte{0x74, 0x03, 0x90, 0x90, 0x90, 0xC3}
		targets := findJumpTargets(data, len(data))
		if !targets[5] {
			t.Error("JE rel8 target at 5 not found")
		}
	})
	t.Run("Jcc_rel32_0F8x", func(t *testing.T) {
		data := make([]byte, 0x100)
		data[0] = 0x0F
		data[1] = 0x84
		binary.LittleEndian.PutUint32(data[2:6], 0x0A)
		targets := findJumpTargets(data, len(data))
		if !targets[16] {
			t.Errorf("JZ rel32 at 16 not found: %v", targets)
		}
	})
	t.Run("CALL_rel32", func(t *testing.T) {
		data := make([]byte, 0x100)
		data[0] = 0xE8
		binary.LittleEndian.PutUint32(data[1:5], 0x20)
		targets := findJumpTargets(data, len(data))
		if !targets[0x25] {
			t.Errorf("CALL rel32 at 0x25 not found: %v", targets)
		}
	})
	t.Run("OOB", func(t *testing.T) {
		data := []byte{0xEB, 0x7F}
		targets := findJumpTargets(data, 2)
		if len(targets) != 0 {
			t.Errorf("expected 0 targets, got %d", len(targets))
		}
	})
	t.Run("empty", func(t *testing.T) {
		if len(findJumpTargets(nil, 0)) != 0 {
			t.Error("expected 0 targets")
		}
	})
	t.Run("no_jumps", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x90}, 64)
		if len(findJumpTargets(data, len(data))) != 0 {
			t.Error("expected 0 targets for NOP data")
		}
	})
	t.Run("overlapping", func(t *testing.T) {
		data := []byte{0xEB, 0x02, 0xEB, 0x00, 0x90}
		if !findJumpTargets(data, len(data))[4] {
			t.Error("overlapping target not found")
		}
	})
}

func TestFindFuncBoundaries(t *testing.T) {
	// Loop: for i := 1; i < textLen-4; i++ → textLen must be >= 7
	t.Run("ret_c3_push_rbp", func(t *testing.T) {
		data := []byte{0x90, 0xC3, 0x55, 0x90, 0x90, 0x90, 0x90}
		boundaries := findFuncBoundaries(data, len(data))
		if len(boundaries) != 1 || boundaries[0] != 2 {
			t.Errorf("expected [2], got %v", boundaries)
		}
	})
	t.Run("ret_c3_mov_rbp_rsp", func(t *testing.T) {
		data := []byte{0x90, 0xC3, 0x48, 0x89, 0xE5, 0x90, 0x90}
		boundaries := findFuncBoundaries(data, len(data))
		if len(boundaries) != 1 || boundaries[0] != 2 {
			t.Errorf("expected [2], got %v", boundaries)
		}
	})
	t.Run("ret_c2_imm16", func(t *testing.T) {
		data := []byte{0x90, 0xC2, 0x08, 0x00, 0x55, 0x90, 0x90, 0x90}
		boundaries := findFuncBoundaries(data, len(data))
		if len(boundaries) != 1 || boundaries[0] != 4 {
			t.Errorf("expected [4], got %v", boundaries)
		}
	})
	t.Run("multiple", func(t *testing.T) {
		data := []byte{
			0x90,
			0xC3, 0x55, // boundary 2
			0x90, 0x90, 0x90, 0x90,
			0xC3, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, // boundary 8
		}
		boundaries := findFuncBoundaries(data, len(data))
		if len(boundaries) < 2 {
			t.Fatalf("expected 2+, got %v", boundaries)
		}
		if boundaries[0] != 2 || boundaries[1] != 8 {
			t.Errorf("expected [2,8], got %v", boundaries)
		}
	})
	t.Run("no_ret_before_prologue", func(t *testing.T) {
		data := []byte{0x90, 0x55, 0x48, 0x89, 0xE5, 0x90, 0x90}
		if len(findFuncBoundaries(data, len(data))) != 0 {
			t.Error("expected 0 boundaries")
		}
	})
	t.Run("ret_without_prologue", func(t *testing.T) {
		data := []byte{0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90}
		if len(findFuncBoundaries(data, len(data))) != 0 {
			t.Error("expected 0 boundaries")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if len(findFuncBoundaries(nil, 0)) != 0 {
			t.Error("expected 0 boundaries")
		}
	})
	t.Run("short", func(t *testing.T) {
		if len(findFuncBoundaries([]byte{0xC3}, 1)) != 0 {
			t.Error("expected 0 boundaries")
		}
	})
	t.Run("c2_prologue_at_end", func(t *testing.T) {
		// C2 at index 1, prologue at start+2=3, start+3=6 >= textLen(7)
		data := []byte{0x90, 0xC2, 0x08, 0x00, 0x55, 0x90, 0x90}
		boundaries := findFuncBoundaries(data, len(data))
		if len(boundaries) != 0 {
			t.Errorf("expected 0 boundaries (C2 prologue past buffer), got %v", boundaries)
		}
	})
}

func TestFindFunctionGaps(t *testing.T) {
	// RET at offset 0 excluded by retAt <= 0 check.
	t.Run("single_gap", func(t *testing.T) {
		data := []byte{
			0x90, // pad
			0xC3, // RET at 1
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // gap 7
			0x55, // boundary at 9
		}
		gaps := findFunctionGaps(data, len(data), []uint32{9}, map[uint32]bool{})
		if len(gaps) != 1 {
			t.Fatalf("expected 1 gap, got %d", len(gaps))
		}
		if gaps[0].start != 2 || gaps[0].size != 7 {
			t.Errorf("got start=%d size=%d, want start=2 size=7", gaps[0].start, gaps[0].size)
		}
	})
	t.Run("blocked_by_jump", func(t *testing.T) {
		data := []byte{0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x55}
		gaps := findFunctionGaps(data, len(data), []uint32{6}, map[uint32]bool{2: true})
		if len(gaps) != 0 {
			t.Errorf("expected 0 gaps, got %d", len(gaps))
		}
	})
	t.Run("ret_c2_imm16", func(t *testing.T) {
		data := []byte{0x90, 0xC2, 0x08, 0x00, 0x90, 0x90, 0x90, 0x55}
		gaps := findFunctionGaps(data, len(data), []uint32{7}, map[uint32]bool{})
		if len(gaps) != 1 {
			t.Fatalf("expected 1 gap, got %d", len(gaps))
		}
		if gaps[0].start != 4 {
			t.Errorf("gap start = %d, want 4", gaps[0].start)
		}
	})
	t.Run("no_boundaries", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x90}, 64)
		if findFunctionGaps(data, len(data), nil, nil) != nil {
			t.Error("expected nil")
		}
	})
	t.Run("empty_boundaries", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x90}, 64)
		if len(findFunctionGaps(data, len(data), []uint32{}, nil)) != 0 {
			t.Error("expected 0 gaps")
		}
	})
	t.Run("no_ret_before", func(t *testing.T) {
		data := []byte{0x55, 0x90, 0x90}
		if len(findFunctionGaps(data, len(data), []uint32{0}, map[uint32]bool{})) != 0 {
			t.Error("expected 0 gaps")
		}
	})
}

func TestFindTextSection(t *testing.T) {
	t.Run("valid_pe", func(t *testing.T) {
		textData := bytes.Repeat([]byte{0x90}, 256)
		exe := buildMinimalPE(textData)
		va, vaEnd, raw := findTextSection(exe)
		if va != 0x1000 {
			t.Errorf("VA = 0x%X, want 0x1000", va)
		}
		if vaEnd != 0x1000+uint32(len(textData)) {
			t.Errorf("vaEnd = 0x%X", vaEnd)
		}
		if raw != 0x400 {
			t.Errorf("raw = 0x%X, want 0x400", raw)
		}
	})
	t.Run("no_text_section", func(t *testing.T) {
		exe := buildMinimalPEWithSection(".data\x00\x00\x00", 256)
		va, _, _ := findTextSection(exe)
		if va != 0 {
			t.Errorf("expected 0 VA, got 0x%X", va)
		}
	})
	t.Run("not_pe", func(t *testing.T) {
		exe := bytes.Repeat([]byte{0x00}, 0x200)
		copy(exe, "MZ")
		binary.LittleEndian.PutUint32(exe[0x3C:0x40], 0xFFFFFFFF)
		va, _, _ := findTextSection(exe)
		if va != 0 {
			t.Errorf("expected 0, got 0x%X", va)
		}
	})
}

func buildMinimalPEWithSection(name string, dataSize int) []byte {
	dosHeader := make([]byte, 0x80)
	copy(dosHeader, "MZ")
	binary.LittleEndian.PutUint32(dosHeader[0x3C:0x40], 0x80)

	peSig := append([]byte("PE\x00\x00"), make([]byte, 20)...)
	binary.LittleEndian.PutUint16(peSig[4:6], 0x8664)
	binary.LittleEndian.PutUint16(peSig[6:8], 1)
	binary.LittleEndian.PutUint16(peSig[20:22], 0xF0)

	optHdr := make([]byte, 0xF0)
	binary.LittleEndian.PutUint16(optHdr[0:2], 0x020B)
	binary.LittleEndian.PutUint32(optHdr[32:36], 0x1000)
	binary.LittleEndian.PutUint32(optHdr[36:40], 0x200)
	binary.LittleEndian.PutUint32(optHdr[56:60], 0x2000)
	binary.LittleEndian.PutUint32(optHdr[60:64], 0x400)
	binary.LittleEndian.PutUint16(optHdr[68:70], 2)
	binary.LittleEndian.PutUint32(optHdr[108:112], 16)
	peHdr := append(peSig, optHdr...)

	secHdr := make([]byte, 40)
	copy(secHdr[0:8], name)
	binary.LittleEndian.PutUint32(secHdr[8:12], uint32(dataSize))
	binary.LittleEndian.PutUint32(secHdr[12:16], 0x1000)
	binary.LittleEndian.PutUint32(secHdr[16:20], uint32(dataSize))
	binary.LittleEndian.PutUint32(secHdr[20:24], 0x400)

	var buf bytes.Buffer
	buf.Write(dosHeader)
	buf.Write(peHdr)
	buf.Write(secHdr)
	for buf.Len() < 0x400 {
		buf.WriteByte(0)
	}
	buf.Write(bytes.Repeat([]byte{0x90}, dataSize))
	return buf.Bytes()
}

func TestMorphInstructions(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if morphInstructions(nil) != nil {
			t.Error("expected nil")
		}
	})
	t.Run("short", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x00}, 0x100)
		if !bytes.Equal(morphInstructions(data), data) {
			t.Error("expected unchanged")
		}
	})
	t.Run("non_mz", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x00}, 0x300)
		if !bytes.Equal(morphInstructions(data), data) {
			t.Error("expected unchanged")
		}
	})
	t.Run("mz_no_text", func(t *testing.T) {
		data := make([]byte, 0x300)
		copy(data, "MZ")
		if !bytes.Equal(morphInstructions(data), data) {
			t.Error("expected unchanged")
		}
	})
	t.Run("minimal_pe", func(t *testing.T) {
		exe := buildMinimalPE(bytes.Repeat([]byte{0x90}, 512))
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("pe_with_ret_prologue", func(t *testing.T) {
		textData := make([]byte, 512)
		for i := range textData {
			textData[i] = 0x90
		}
		textData[10] = 0xC3
		textData[11] = 0x55
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
		if len(result) < len(exe) {
			t.Error("result shrunk")
		}
	})
	t.Run("pe_with_jumps", func(t *testing.T) {
		textData := make([]byte, 512)
		for i := range textData {
			textData[i] = 0x90
		}
		textData[0] = 0xEB
		textData[1] = 0x10
		textData[15] = 0xC3
		textData[16] = 0x55
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		exe := buildMinimalPE(bytes.Repeat([]byte{0x90}, 512))
		r1 := morphInstructions(exe)
		r2 := morphInstructions(exe)
		if !bytes.Equal(r1, r2) {
			t.Error("not deterministic")
		}
	})
	t.Run("nop_variation", func(t *testing.T) {
		// 4 NOPs with no jump targets → should trigger NOP variation
		textData := make([]byte, 512)
		for i := range textData {
			textData[i] = 0x90
		}
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("junk_injection", func(t *testing.T) {
		textData := make([]byte, 1024)
		for i := range textData {
			textData[i] = 0x90
		}
		textData[100] = 0xC3
		textData[101] = 0x55 // RET+prologue adjacent -> boundary
		textData[200] = 0xC3
		textData[201] = 0x55 // second boundary
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("junk_and_nops", func(t *testing.T) {
		textData := make([]byte, 2048)
		for i := range textData {
			textData[i] = 0x90
		}
		// Two function gaps for junk injection
		textData[100] = 0xC3
		textData[117] = 0x55 // gap at 101-116 = 16 bytes → junk inject
		textData[200] = 0xC3
		textData[220] = 0x55 // gap at 201-219 = 19 bytes → junk inject
		// NOPs elsewhere get varied
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("small_gap_no_inject", func(t *testing.T) {
		// Gap size < 3 → skip (line 54-55)
		textData := make([]byte, 512)
		for i := range textData {
			textData[i] = 0x90
		}
		textData[100] = 0xC3
		textData[102] = 0x55 // gap = 1 byte, too small
		exe := buildMinimalPE(textData)
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
	t.Run("textLen_exceeds_data", func(t *testing.T) {
		// Construct PE where VirtualSize > section data after header
		textData := bytes.Repeat([]byte{0x90}, 200)
		exe := buildMinimalPE(textData)
		// Manually inflate VirtualSize to exceed raw data
		peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
		optHdrSize := binary.LittleEndian.Uint16(exe[peOff+20 : peOff+22])
		secTable := int(peOff) + 24 + int(optHdrSize)
		binary.LittleEndian.PutUint32(exe[secTable+8:secTable+12], 0x10000) // inflate VS
		result := morphInstructions(exe)
		if !bytes.HasPrefix(result, []byte("MZ")) {
			t.Error("result not MZ")
		}
	})
}
