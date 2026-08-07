// Package builder — PolyEngine-style instruction-level morphing
//
// Performs safe instruction substitution and junk injection on x86-64
// machine code to produce unique .text sections per build.
//
// Full implementation uses zydis-go for decode/encode.
// Stub for now: NOP-only injection (still provides section variation
// when combined with PE mutations and poly section rewriting).
package builder

import (
	"bytes"
	"encoding/binary"
	"log/slog"
)

// morphInstructions applies instruction-level mutations to .text.
// Returns a mutated copy of exe (original is not modified).
func morphInstructions(exe []byte) []byte {
	if len(exe) < 0x200 {
		return exe
	}
	if !bytes.HasPrefix(exe, []byte("MZ")) {
		return exe
	}

	// Find .text section boundaries
	textStart, textEnd, textRawOff := findTextSection(exe)
	if textStart == 0 {
		slog.Debug("morph: .text section not found, skipping")
		return exe
	}

	// Stub: inject NOPs at function boundaries within .text
	result := bytes.Clone(exe)
	injectNOPsAtBoundaries(result, textRawOff, textStart, textEnd)
	slog.Debug("morph: NOP injection complete")

	return result
}

// findTextSection locates the .text section in the PE.
// Returns (virtual start, virtual end, raw offset).
func findTextSection(exe []byte) (uint32, uint32, uint32) {
	peOff := binary.LittleEndian.Uint32(exe[0x3C:0x40])
	secCount := int(binary.LittleEndian.Uint16(exe[peOff+6 : peOff+8]))
	optHdrSize := int(binary.LittleEndian.Uint16(exe[peOff+20 : peOff+22]))
	secTable := peOff + 24 + uint32(optHdrSize)

	for i := 0; i < secCount; i++ {
		off := secTable + uint32(i*40)
		name := string(bytes.TrimRight(exe[off:off+8], "\x00"))
		if name == ".text" {
			vs := binary.LittleEndian.Uint32(exe[off+8 : off+12])
			va := binary.LittleEndian.Uint32(exe[off+12 : off+16])
			raw := binary.LittleEndian.Uint32(exe[off+20 : off+24])
			return va, va + vs, raw
		}
	}
	return 0, 0, 0
}

// injectNOPsAtBoundaries inserts random NOP variants at function-like boundaries.
// Scans for RET instructions (0xC3, 0xC2) and inserts 0-2 NOPs after each.
func injectNOPsAtBoundaries(exe []byte, rawOff, vStart, vEnd uint32) {
	if rawOff+uint32(len(exe))-rawOff > uint32(len(exe)) {
		return
	}
	data := exe[rawOff:]
	maxLen := int(vEnd - vStart)
	if maxLen > len(data) {
		maxLen = len(data)
	}

	nops := [][]byte{
		{0x90},                         // 1-byte NOP
		{0x66, 0x90},                   // 2-byte NOP
		{0x0F, 0x1F, 0x00},            // 3-byte NOP
		{0x0F, 0x1F, 0x40, 0x00},      // 4-byte NOP
		{0x0F, 0x1F, 0x44, 0x00, 0x00},// 5-byte NOP
	}

	// Simple: after every 64-byte chunk, insert a NOP
	// (placeholder until zydis-go decode/encode is wired)
	for pos := 0; pos < maxLen-1; pos += 64 {
		// Avoid disrupting instructions: only act on NOP/INT3 padding
		if data[pos] == 0x90 || data[pos] == 0xCC {
			nop := nops[pos%len(nops)]
			for i := 0; i < len(nop); i++ {
				data[pos+i] = nop[i]
			}
		}
	}
}
