package builder

import (
	"bytes"
	"encoding/binary"
	"log/slog"
)

// InjectIcon appends .ico data as a .icon PE section.
func InjectIcon(exe []byte, icoData []byte) ([]byte, error) {
	if len(icoData) == 0 {
		return exe, nil
	}
	if len(exe) < 0x200 || !bytes.HasPrefix(exe, []byte("MZ")) {
		return exe, nil
	}

	peOff := int(binary.LittleEndian.Uint32(exe[0x3C:0x40]))
	if peOff+4 > len(exe) || !bytes.HasPrefix(exe[peOff:], []byte("PE\x00\x00")) {
		return exe, nil
	}

	secCount := int(binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8]))
	optHdrSize := int(binary.LittleEndian.Uint16(exe[peOff+20 : peOff+22]))
	secTable := peOff + 24 + optHdrSize

	for i := 0; i < secCount; i++ {
		off := secTable + i*40
		if off+6 <= len(exe) && bytes.HasPrefix(exe[off:off+6], []byte(".icon")) {
			slog.Debug("icon: already injected, skipping")
			return exe, nil
		}
	}
	// Check the trailer — section header is appended at file end
	if len(exe) >= 40 && bytes.HasPrefix(exe[len(exe)-40:len(exe)-40+6], []byte(".icon")) {
		slog.Debug("icon: already injected, skipping")
		return exe, nil
	}

	align := 0x200
	padLen := align - (len(exe) % align)
	if padLen == align {
		padLen = 0
	}
	rawSize := len(icoData) + padLen

	secHdr := make([]byte, 40)
	copy(secHdr[0:6], ".icon")
	binary.LittleEndian.PutUint32(secHdr[8:12], uint32(len(icoData)))
	binary.LittleEndian.PutUint32(secHdr[12:16], uint32(alignUp(len(exe), 0x1000)))
	binary.LittleEndian.PutUint32(secHdr[16:20], uint32(rawSize))
	binary.LittleEndian.PutUint32(secHdr[20:24], uint32(len(exe)))
	secHdr[27] = 0x40

	result := make([]byte, len(exe)+rawSize)
	copy(result, exe)
	copy(result[len(exe):], icoData)
	result = append(result, secHdr...)

	binary.LittleEndian.PutUint16(result[peOff+6:peOff+8], uint16(secCount+1))

	lastRVA := binary.LittleEndian.Uint32(secHdr[12:16]) + uint32(alignUp(len(icoData), 0x1000))
	sizeOfImageOff := peOff + 24 + 56
	binary.LittleEndian.PutUint32(result[sizeOfImageOff:sizeOfImageOff+4], lastRVA)

	slog.Debug("icon: injected", "size", len(icoData))
	return result, nil
}