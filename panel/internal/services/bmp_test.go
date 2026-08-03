package services

import (
	"encoding/binary"
	"testing"
)

// makeBMP builds a minimal BMP header with the given width/height and bit
// count. The pixel data region is filled with `pixelBytes` bytes (zero or
// more). The returned buffer is suitable for parseBMPHeader.
func makeBMP(width, height, bitCount int, pixelBytes int) []byte {
	const (
		fileHeaderSize  = 14
		infoHeaderSize  = 40
		headerSize      = fileHeaderSize + infoHeaderSize
	)
	pixels := make([]byte, pixelBytes)
	bmp := make([]byte, headerSize+len(pixels))

	// BITMAPFILEHEADER
	bmp[0] = 'B'
	bmp[1] = 'M'
	binary.LittleEndian.PutUint32(bmp[2:], uint32(headerSize+len(pixels))) // bfSize
	// bfReserved1/2 stay 0
	binary.LittleEndian.PutUint32(bmp[10:], uint32(headerSize)) // bfOffBits

	// BITMAPINFOHEADER
	binary.LittleEndian.PutUint32(bmp[14:], uint32(infoHeaderSize)) // biSize
	binary.LittleEndian.PutUint32(bmp[18:], uint32(width))          // biWidth
	binary.LittleEndian.PutUint32(bmp[22:], uint32(height))         // biHeight
	binary.LittleEndian.PutUint16(bmp[26:], 1)                     // biPlanes
	binary.LittleEndian.PutUint16(bmp[28:], uint16(bitCount))       // biBitCount
	// rest of info header stays 0 (BI_RGB, etc.)

	copy(bmp[headerSize:], pixels)
	return bmp
}

func TestParseBMPHeader(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantW      int
		wantH      int
		wantSize   int
		wantOK     bool
	}{
		{
			name:     "valid 24-bit BMP with pixel data",
			data:     makeBMP(4, 3, 24, 12),
			wantW:    4,
			wantH:    3,
			wantSize: 66,
			wantOK:   true,
		},
		{
			name:     "valid 32-bit BMP",
			data:     makeBMP(1920, 1080, 32, 0),
			wantW:    1920,
			wantH:    1080,
			wantSize: 54,
			wantOK:   true,
		},
		{
			name:     "missing BM magic",
			data:     makeBMP(4, 3, 24, 0)[:30],
			wantOK:   false,
		},
		{
			name: "biSize too small (OS/2 header)",
			// data[0..1] = 'BM', data[14..18] = biSize=12, rest of header bytes 18..30 = 0
			data: func() []byte {
				buf := make([]byte, 30)
				buf[0] = 'B'
				buf[1] = 'M'
				binary.LittleEndian.PutUint32(buf[14:], 12)
				return buf
			}(),
			wantOK: false,
		},
		{
			name:   "empty buffer",
			data:   []byte{},
			wantOK: false,
		},
		{
			name:   "truncated after 10 bytes",
			data:   []byte{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Stamp non-BM magic for the dedicated test
			if tt.name == "missing BM magic" {
				tt.data[0] = 'X'
				tt.data[1] = 'Y'
			}
			w, h, sz, ok := parseBMPHeader(tt.data)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if w != tt.wantW {
				t.Errorf("width = %d, want %d", w, tt.wantW)
			}
			if h != tt.wantH {
				t.Errorf("height = %d, want %d", h, tt.wantH)
			}
			if sz != tt.wantSize {
				t.Errorf("sizeBytes = %d, want %d", sz, tt.wantSize)
			}
		})
	}
}
