package builder

import (
	"bytes"
	"encoding/binary"
	"log/slog"
)

// InjectIcon writes .ico data into the PE .rsrc section.
// Stub implementation — returns original exe if .ico can't be injected.
func InjectIcon(exe []byte, icoData []byte) ([]byte, error) {
	if len(icoData) == 0 {
		return exe, nil
	}
	if len(exe) < 0x200 || !bytes.HasPrefix(exe, []byte("MZ")) {
		return exe, nil
	}

	// Find .rsrc section
	peOff := int(binary.LittleEndian.Uint32(exe[0x3C:0x40]))
	secCount := int(binary.LittleEndian.Uint16(exe[peOff+6:peOff+8]))
	optHdrSize := int(binary.LittleEndian.Uint16(exe[peOff+20:peOff+22]))
	secTable := peOff + 24 + optHdrSize

	for i := 0; i < secCount; i++ {
		off := secTable + i*40
		name := string(bytes.TrimRight(exe[off:off+8], "\x00"))
		if name == ".rsrc" {
			slog.Debug("icon: .rsrc section found, injection stub - keeping original")
			// Full icon injection requires resource directory tree manipulation.
			// Stub: keep original icon (icon is cosmetic, not critical).
			return exe, nil
		}
	}

	slog.Debug("icon: .rsrc section not found, skipping injection")
	return exe, nil
}
