package builder

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func WriteMiCfgSection(exe []byte, cfg MiCfgConfig) ([]byte, error) {
	if len(exe) < 0x200 || !bytes.HasPrefix(exe, []byte("MZ")) {
		return nil, errors.New("mi_cfg: not a PE file")
	}
	peOff := int(binary.LittleEndian.Uint32(exe[0x3C:0x40]))
	if peOff+4 > len(exe) || !bytes.HasPrefix(exe[peOff:], []byte("PE\x00\x00")) {
		return nil, errors.New("mi_cfg: invalid PE signature")
	}

	numSections := int(binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8]))
	secData := buildSectionData(cfg)
	rawSize := roundUp(len(secData), 0x200)
	padded := make([]byte, rawSize)
	copy(padded, secData)

	secHdr := make([]byte, 40)
	copy(secHdr[0:8], []byte(".mi_cfg\x00"))
	binary.LittleEndian.PutUint32(secHdr[8:12], uint32(len(secData)))
	binary.LittleEndian.PutUint32(secHdr[12:16], uint32(alignUp(len(exe), 0x1000)))
	binary.LittleEndian.PutUint32(secHdr[16:20], uint32(rawSize))
	binary.LittleEndian.PutUint32(secHdr[20:24], uint32(len(exe)))
	secHdr[27] = 0x40

	result := make([]byte, len(exe)+rawSize)
	copy(result, exe)
	copy(result[len(exe):], padded)
	result = append(result, secHdr...)

	binary.LittleEndian.PutUint16(result[peOff+6:peOff+8], uint16(numSections+1))
	lastRVA := binary.LittleEndian.Uint32(secHdr[12:16]) + uint32(alignUp(len(secData), 0x1000))
	binary.LittleEndian.PutUint32(result[peOff+24+56:peOff+24+60], lastRVA)

	return result, nil
}

type MiCfgConfig struct {
	Seed      uint32
	StringKey [16]byte
	SSNXorKey uint32
	Strings   []MiCfgString
	BIP39     []MiCfgBIP39
}

type MiCfgString struct{ Data []byte }
type MiCfgBIP39 struct{ Data []byte }

func buildSectionData(cfg MiCfgConfig) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, cfg.Seed)
	buf.Write(cfg.StringKey[:])
	binary.Write(&buf, binary.LittleEndian, cfg.SSNXorKey)
	binary.Write(&buf, binary.LittleEndian, uint32(len(cfg.Strings)))
	for _, s := range cfg.Strings {
		binary.Write(&buf, binary.LittleEndian, uint16(len(s.Data)))
		buf.Write(s.Data)
	}
	binary.Write(&buf, binary.LittleEndian, uint32(len(cfg.BIP39)))
	for _, b := range cfg.BIP39 {
		buf.WriteByte(byte(len(b.Data)))
		buf.Write(b.Data)
	}
	return buf.Bytes()
}

func alignUp(size int, align int) int { return (size + align - 1) / align * align }
func roundUp(n, align int) int        { return (n + align - 1) / align * align }
