package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"zialfi-panel/internal/builder"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	pc, _ := builder.GeneratePoly(0)

	// enc_strings.h
	h := builder.GenerateEncStringsH(pc)
	os.WriteFile(filepath.Join(root, "include", "enc_strings.h"), []byte(h), 0644)

	// config.h — patch MIRAGE_SEED and MIRAGE_STRING_KEY_ENC
	patchConfigH(filepath.Join(root, "include", "config.h"), pc)

	fmt.Printf("polymorph: enc_strings.h=%d bytes, seed=0x%08X\n", len(h), pc.Seed)
}

func patchConfigH(path string, pc builder.PolyConfig) {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	s := string(data)

	// Patch MIRAGE_SEED
	reSeed := regexp.MustCompile(`#define MIRAGE_SEED\s+0x[0-9A-Fa-f]+`)
	s = reSeed.ReplaceAllString(s, fmt.Sprintf("#define MIRAGE_SEED            0x%08X", pc.Seed))

	// Patch MIRAGE_STRING_KEY_ENC
	reKey := regexp.MustCompile(`static const unsigned char MIRAGE_STRING_KEY_ENC\[16\] = \{\s*[\s\S]*?\};`)
	keyStr := fmt.Sprintf("static const unsigned char MIRAGE_STRING_KEY_ENC[16] = {\n    0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n};",
		pc.StringKey[0], pc.StringKey[1], pc.StringKey[2], pc.StringKey[3],
		pc.StringKey[4], pc.StringKey[5], pc.StringKey[6], pc.StringKey[7],
		pc.StringKey[8], pc.StringKey[9], pc.StringKey[10], pc.StringKey[11],
		pc.StringKey[12], pc.StringKey[13], pc.StringKey[14], pc.StringKey[15])
	s = reKey.ReplaceAllString(s, keyStr)

	os.WriteFile(path, []byte(s), 0644)
}
