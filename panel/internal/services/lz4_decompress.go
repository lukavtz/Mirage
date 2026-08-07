package services

import (
	"encoding/binary"
	"errors"

	"github.com/pierrec/lz4/v4"
)

var errNotLZ4 = errors.New("not LZ4 compressed")

// DecompressLZ4 decompresses Mirage's LZ4 block format.
// Expected input after ChaCha20 decrypt: [magic:0x01][orig_size:4_LE][compressed:N]
// Returns the decompressed data or errNotLZ4 if the magic byte doesn't match.
func DecompressLZ4(data []byte) ([]byte, error) {
	if len(data) < 5 || data[0] != 0x01 {
		return nil, errNotLZ4
	}

	origSize := binary.LittleEndian.Uint32(data[1:5])
	if origSize == 0 || origSize > 100*1024*1024 { // sanity: max 100MB
		return nil, errNotLZ4
	}

	compressed := data[5:]
	decompressed := make([]byte, origSize)
	n, err := lz4.UncompressBlock(compressed, decompressed)
	if err != nil {
		return nil, err
	}
	if n != int(origSize) {
		return nil, errors.New("LZ4 size mismatch")
	}
	return decompressed, nil
}
