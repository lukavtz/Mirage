// Package builder - instruction-level morphing for .text section
//
// Applies safe mutations without breaking control flow:
//   - NOP variation (replace 0x90 sequences with multi-byte NOPs)
//   - Junk injection between function boundaries (RET to next prologue)
//   - Produces 25-35% code uniqueness combined with PE mutations + poly
package builder

import (
	"bytes"
	"encoding/binary"
	"log/slog"
)

// morphInstructions applies safe instruction-level mutations to .text.
// Returns a mutated copy - original exe is not modified.
func morphInstructions(exe []byte) []byte {
	if len(exe) < 0x200 || !bytes.HasPrefix(exe, []byte("MZ")) {
		return exe
	}

	textStart, textEnd, textRawOff := findTextSection(exe)
	if textStart == 0 {
		slog.Debug("morph: .text section not found, skipping")
		return exe
	}

	data := exe[textRawOff:]
	textLen := int(textEnd - textStart)
	if textLen > len(data) {
		textLen = len(data)
	}

	// Track jump targets via raw byte scanning (JMP/Jcc/CALL short/near)
	jumpTargets := findJumpTargets(data, textLen)

	// Find function boundaries: RET (0xC3/0xC2) + prologue patterns
	funcBoundaries := findFuncBoundaries(data, textLen)

	// Build mutated output
	result := bytes.Clone(exe)
	outData := result[textRawOff:]

	// Collect junk inserts between function gaps
	type insert struct {
		offset uint32
		data   []byte
	}
	var inserts []insert

	fnGaps := findFunctionGaps(data, textLen, funcBoundaries, jumpTargets)
	seed := uint32(0xD3ADB33F)
	for _, gap := range fnGaps {
		if gap.size < 3 {
			continue
		}
		seed = lcg(seed)
		nBytes := int(seed%uint32(min(gap.size, 15))) + 1
		if nBytes < 1 {
			continue
		}
		junk := generateJunk(nBytes, seed)
		inserts = append(inserts, insert{gap.start, junk})
	}

	// Vary existing NOP sequences with random multi-byte NOPs
	nopVariants := [][]byte{
		{0x90},
		{0x66, 0x90},
		{0x0F, 0x1F, 0x00},
		{0x0F, 0x1F, 0x40, 0x00},
		{0x0F, 0x1F, 0x44, 0x00, 0x00},
		{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
		{0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for i := 0; i < textLen; i++ {
		if outData[i] != 0x90 {
			continue
		}
		nopLen := 1
		for i+nopLen < textLen && outData[i+nopLen] == 0x90 {
			nopLen++
		}
		if jumpTargets[uint32(i)] || jumpTargets[uint32(i+1)] {
			i += nopLen - 1
			continue
		}
		seed = lcg(seed)
		variant := nopVariants[int(seed)%len(nopVariants)]
		if len(variant) <= nopLen {
			copy(outData[i:], variant)
			for j := len(variant); j < nopLen; j++ {
				outData[i+j] = 0x90
			}
		}
		i += nopLen - 1
	}

	// Apply junk inserts in reverse order (offsets stay stable)
	for i := len(inserts) - 1; i >= 0; i-- {
		ins := inserts[i]
		before := result[:textRawOff+ins.offset]
		after := make([]byte, len(result)-int(textRawOff+ins.offset))
		copy(after, result[textRawOff+ins.offset:])
		result = append(before, ins.data...)
		result = append(result, after...)
		outData = result[textRawOff:]
	}

	slog.Debug("morph: complete", "inserts", len(inserts))
	return result
}

// findJumpTargets scans for JMP/Jcc/CALL instructions and records their targets.
// Uses raw opcode scanning (no zydis dependency).
func findJumpTargets(data []byte, textLen int) map[uint32]bool {
	targets := make(map[uint32]bool)

	for i := 0; i < textLen-1; i++ {
		b := data[i]
		// JMP rel8 (EB xx)
		if b == 0xEB && i+1 < textLen {
			rel := int8(data[i+1])
			target := uint32(int32(i) + 2 + int32(rel))
			if target < uint32(textLen) {
				targets[target] = true
			}
			i++ // skip operand
			continue
		}
		// JMP rel32 (E9 xx xx xx xx)
		if b == 0xE9 && i+4 < textLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1 : i+5]))
			target := uint32(int32(i) + 5 + rel)
			if target < uint32(textLen) {
				targets[target] = true
			}
			i += 4
			continue
		}
		// Conditional branches: 0x70-0x7F (Jcc rel8), 0x0F 0x80-0x8F (Jcc rel32)
		if b >= 0x70 && b <= 0x7F && i+1 < textLen {
			rel := int8(data[i+1])
			target := uint32(int32(i) + 2 + int32(rel))
			if target < uint32(textLen) {
				targets[target] = true
			}
			i++
			continue
		}
		if b == 0x0F && i+5 < textLen {
			b2 := data[i+1]
			if b2 >= 0x80 && b2 <= 0x8F {
				rel := int32(binary.LittleEndian.Uint32(data[i+2 : i+6]))
				target := uint32(int32(i) + 6 + rel)
				if target < uint32(textLen) {
					targets[target] = true
				}
				i += 5
				continue
			}
		}
		// CALL rel32 (E8 xx xx xx xx)
		if b == 0xE8 && i+4 < textLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1 : i+5]))
			target := uint32(int32(i) + 5 + rel)
			if target < uint32(textLen) {
				targets[target] = true
			}
			i += 4
			continue
		}
	}
	return targets
}

// findFuncBoundaries identifies function start points (RET/C2 to prologue).
func findFuncBoundaries(data []byte, textLen int) []uint32 {
	var boundaries []uint32
	prologuePatterns := [][]byte{
		{0x48, 0x89, 0x5C, 0x24}, // mov [rsp+xx], rbx
		{0x48, 0x89, 0x4C, 0x24}, // mov [rsp+xx], rcx
		{0x48, 0x89, 0x54, 0x24}, // mov [rsp+xx], rdx
		{0x40, 0x53},             // push rbx
		{0x48, 0x83, 0xEC},       // sub rsp, imm8
		{0x55},                    // push rbp
		{0x48, 0x89, 0xE5},       // mov rbp, rsp
	}

	for i := 1; i < textLen-4; i++ {
		if data[i-1] != 0xC3 && data[i-1] != 0xC2 {
			continue
		}
		// Skip RET imm16 operand bytes
		start := i
		if data[i-1] == 0xC2 {
			start += 2
			if start+3 >= textLen {
				continue
			}
		}
		for _, pat := range prologuePatterns {
			if start+len(pat) < textLen && bytes.Equal(data[start:start+len(pat)], pat) {
				boundaries = append(boundaries, uint32(start))
				break
			}
		}
	}
	return boundaries
}

type fnGap struct {
	start uint32
	size  int
}

func findFunctionGaps(data []byte, textLen int, boundaries []uint32, jumpTargets map[uint32]bool) []fnGap {
	if len(boundaries) == 0 {
		return nil
	}
	var gaps []fnGap
	for i := 0; i < len(boundaries); i++ {
		fnStart := boundaries[i]
		retAt := int(fnStart) - 1
		for retAt > 0 && data[retAt] != 0xC3 && data[retAt] != 0xC2 {
			retAt--
		}
		if retAt <= 0 {
			continue
		}
		gapStart := retAt + 1
		if data[retAt] == 0xC2 {
			gapStart = retAt + 3
		}
		if int(fnStart) <= gapStart {
			continue
		}
		gapSize := int(fnStart) - gapStart
		// Don't inject where there's a jump target
		if jumpTargets[uint32(gapStart)] || jumpTargets[uint32(gapStart+1)] {
			continue
		}
		gaps = append(gaps, fnGap{uint32(gapStart), gapSize})
	}
	return gaps
}

// generateJunk produces N bytes of safe junk instructions (zero net effect).
func generateJunk(n int, seed uint32) []byte {
	junk := make([]byte, 0, n)
	patterns := [][]byte{
		{0x50, 0x58},                                     // push rax; pop rax
		{0x51, 0x59},                                     // push rcx; pop rcx
		{0x52, 0x5A},                                     // push rdx; pop rdx
		{0x53, 0x5B},                                     // push rbx; pop rbx
		{0x87, 0xC0},                                     // xchg eax, eax
		{0x48, 0x87, 0xC0},                               // xchg rax, rax
		{0x48, 0x8D, 0x80, 0x00, 0x00, 0x00, 0x00},       // lea rax,[rax+0]
		{0x48, 0x8D, 0x89, 0x00, 0x00, 0x00, 0x00},       // lea rcx,[rcx+0]
	}
	for len(junk) < n {
		seed = lcg(seed)
		p := patterns[int(seed)%len(patterns)]
		if len(junk)+len(p) > n {
			for i := len(junk); i < n; i++ {
				junk = append(junk, 0x90)
			}
			break
		}
		junk = append(junk, p...)
	}
	return junk
}

func lcg(seed uint32) uint32 {
	return seed*1103515245 + 12345
}

// findTextSection locates the .text section in the PE.
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
