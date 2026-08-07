package builder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeMinimalPE(numSections int) []byte {
	peOff := uint32(0x80)

	dos := make([]byte, 64)
	copy(dos[0:2], "MZ")
	binary.LittleEndian.PutUint32(dos[0x3C:0x40], peOff)

	var buf bytes.Buffer
	buf.Write(dos)
	buf.Write(make([]byte, int(peOff)-64))

	buf.WriteString("PE\x00\x00")

	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:2], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:4], uint16(numSections))
	buf.Write(coff)

	opt := make([]byte, 112)
	opt[0] = 0x0B
	binary.LittleEndian.PutUint32(opt[56:60], 0x4000)
	binary.LittleEndian.PutUint32(opt[60:64], 0x200)
	buf.Write(opt)

	for range numSections {
		hdr := make([]byte, 40)
		copy(hdr[0:8], []byte(".text___\x00"))
		binary.LittleEndian.PutUint32(hdr[8:12], 0x200)
		binary.LittleEndian.PutUint32(hdr[12:16], 0x1000)
		binary.LittleEndian.PutUint32(hdr[16:20], 0x200)
		binary.LittleEndian.PutUint32(hdr[20:24], 0x400)
		hdr[27] = 0x40
		buf.Write(hdr)
	}
	for range numSections {
		buf.Write(make([]byte, 0x200))
	}

	// pad to at least 0x200 for PE validation check
	result := buf.Bytes()
	if len(result) < 0x200 {
		padded := make([]byte, 0x200)
		copy(padded, result)
		return padded
	}
	return result
}

func TestAlignUp(t *testing.T) {
	tests := []struct {
		size, align, want int
	}{
		{0, 0x200, 0},
		{1, 0x200, 0x200},
		{0x200, 0x200, 0x200},
		{0x201, 0x200, 0x400},
		{0xFFF, 0x1000, 0x1000},
		{0x1000, 0x1000, 0x1000},
	}
	for _, tc := range tests {
		got := alignUp(tc.size, tc.align)
		if got != tc.want {
			t.Errorf("alignUp(%d, %d) = %d, want %d", tc.size, tc.align, got, tc.want)
		}
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		n, align, want int
	}{
		{0, 0x200, 0},
		{1, 0x200, 0x200},
		{0x200, 0x200, 0x200},
	}
	for _, tc := range tests {
		got := roundUp(tc.n, tc.align)
		if got != tc.want {
			t.Errorf("roundUp(%d, %d) = %d, want %d", tc.n, tc.align, got, tc.want)
		}
	}
}

func TestBuildSectionData(t *testing.T) {
	cfg := MiCfgConfig{
		Seed:      0xDEADBEEF,
		SSNXorKey: 0xCAFEBABE,
	}
	copy(cfg.StringKey[:], bytes.Repeat([]byte{0x41}, 16))
	cfg.Strings = []MiCfgString{
		{Data: []byte("hello")},
		{Data: []byte("world")},
	}
	cfg.BIP39 = []MiCfgBIP39{
		{Data: bytes.Repeat([]byte{0xFF}, 12)},
	}

	data := buildSectionData(cfg)
	r := bytes.NewReader(data)

	var seed uint32
	binary.Read(r, binary.LittleEndian, &seed)
	if seed != cfg.Seed {
		t.Fatalf("seed: got %#x, want %#x", seed, cfg.Seed)
	}

	var sk [16]byte
	r.Read(sk[:])
	if sk != cfg.StringKey {
		t.Fatalf("string key mismatch")
	}

	var ssn uint32
	binary.Read(r, binary.LittleEndian, &ssn)
	if ssn != cfg.SSNXorKey {
		t.Fatalf("ssn xor key mismatch")
	}

	var nStr uint32
	binary.Read(r, binary.LittleEndian, &nStr)
	if nStr != 2 {
		t.Fatalf("num strings: got %d, want 2", nStr)
	}
	for i, want := range [][]byte{[]byte("hello"), []byte("world")} {
		var ln uint16
		binary.Read(r, binary.LittleEndian, &ln)
		buf := make([]byte, ln)
		r.Read(buf)
		if !bytes.Equal(buf, want) {
			t.Fatalf("string[%d]: got %q, want %q", i, buf, want)
		}
	}

	var nBip uint32
	binary.Read(r, binary.LittleEndian, &nBip)
	if nBip != 1 {
		t.Fatalf("num bip39: got %d, want 1", nBip)
	}
	bLen, _ := r.ReadByte()
	if bLen != 12 {
		t.Fatalf("bip39 len: got %d, want 12", bLen)
	}
	bipData := make([]byte, bLen)
	r.Read(bipData)
	if !bytes.Equal(bipData, bytes.Repeat([]byte{0xFF}, 12)) {
		t.Fatal("bip39 data mismatch")
	}

	if r.Len() != 0 {
		t.Fatalf("trailing bytes: %d", r.Len())
	}
}

func TestWriteMiCfgSection(t *testing.T) {
	cfg := MiCfgConfig{
		Seed:      0xBEEF,
		SSNXorKey: 0xCAFE,
	}
	copy(cfg.StringKey[:], bytes.Repeat([]byte{0x42}, 16))

	exe := makeMinimalPE(1)
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	origSections := binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8])

	result, err := WriteMiCfgSection(exe, cfg)
	if err != nil {
		t.Fatal(err)
	}

	newSections := binary.LittleEndian.Uint16(result[peOff+6 : peOff+8])
	if newSections != origSections+1 {
		t.Errorf("sections: got %d, want %d", newSections, origSections+1)
	}

	// SizeOfImage updated to non-zero
	newSizeOfImage := binary.LittleEndian.Uint32(result[peOff+24+56 : peOff+24+60])
	if newSizeOfImage == 0 {
		t.Error("SizeOfImage must be non-zero")
	}

	// Verify .mi_cfg section header in last 40 bytes
	n := len(result)
	secHdr := result[n-40 : n]
	if !bytes.HasPrefix(secHdr[0:8], []byte(".mi_cfg\x00")) {
		t.Error(".mi_cfg section name not found in trailer")
	}

	// Verify section data is padded to 0x200 alignment
	rawSize := binary.LittleEndian.Uint32(secHdr[16:20])
	if rawSize%0x200 != 0 {
		t.Errorf("raw size not 0x200-aligned: %d", rawSize)
	}
}

func TestWriteMiCfgSectionErrors(t *testing.T) {
	cfg := MiCfgConfig{Seed: 1}
	copy(cfg.StringKey[:], bytes.Repeat([]byte{0x41}, 16))

	tests := []struct {
		name string
		exe  []byte
	}{
		{"nil", nil},
		{"short", make([]byte, 0x100)},
		{"not MZ", bytes.Repeat([]byte{'A'}, 0x200)},
		{"MZ but no PE sig", func() []byte {
			b := make([]byte, 0x200)
			copy(b, "MZ")
			binary.LittleEndian.PutUint32(b[0x3C:0x40], 0x80)
			return b
		}()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := WriteMiCfgSection(tc.exe, cfg)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestWriteMiCfgSectionNoSections(t *testing.T) {
	cfg := MiCfgConfig{Seed: 1}
	copy(cfg.StringKey[:], bytes.Repeat([]byte{0x41}, 16))

	_, err := WriteMiCfgSection(makeMinimalPE(0), cfg)
	if err != nil {
		t.Fatalf("PE with 0 sections should still work: %v", err)
	}
}
