package services

import "encoding/binary"

// parseBMPHeader extracts the width, height, and declared file size from a
// Windows BMP file. It inspects only the BITMAPFILEHEADER (14 bytes) and the
// first 16 bytes of the BITMAPINFOHEADER; pixel data is not decoded.
//
// The function is permissive: ok=false only when the file clearly isn't a BMP
// (no BM magic or biSize < 40). The caller may persist a BMP that fails this
// check and rely on a later heuristic (image dimensions = 0).
func parseBMPHeader(data []byte) (width, height, sizeBytes int, ok bool) {
	// BITMAPFILEHEADER: bfType(2) + bfSize(4) + bfReserved1(2) + bfReserved2(2)
	//                  + bfOffBits(4) = 14 bytes
	// BITMAPINFOHEADER (start): biSize(4) + biWidth(4) + biHeight(4) + biPlanes(2) + biBitCount(2) = 16 bytes
	// Total minimum: 30 bytes
	const minSize = 30
	if len(data) < minSize {
		return 0, 0, 0, false
	}
	if data[0] != 'B' || data[1] != 'M' {
		return 0, 0, 0, false
	}

	biSize := binary.LittleEndian.Uint32(data[14:18])
	if biSize < 40 {
		return 0, 0, 0, false
	}

	w := int32(binary.LittleEndian.Uint32(data[18:22]))
	h := int32(binary.LittleEndian.Uint32(data[22:26]))

	declared := binary.LittleEndian.Uint32(data[2:6])
	return int(w), int(h), int(declared), true
}
