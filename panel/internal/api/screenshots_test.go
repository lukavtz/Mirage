package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"zialfi-panel/internal/api"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/testutil"
)

// makeTestBMP returns a minimal 24-bit BMP (4x3) of declared size 66 bytes.
func makeTestBMP() []byte {
	const headerSize = 14 + 40
	pixels := bytes.Repeat([]byte{0x55}, 12)
	bmp := make([]byte, headerSize+len(pixels))
	bmp[0] = 'B'
	bmp[1] = 'M'
	binary.LittleEndian.PutUint32(bmp[2:], uint32(len(bmp)))
	binary.LittleEndian.PutUint32(bmp[10:], uint32(headerSize))
	binary.LittleEndian.PutUint32(bmp[14:], 40)
	binary.LittleEndian.PutUint32(bmp[18:], 4)
	binary.LittleEndian.PutUint32(bmp[22:], 3)
	binary.LittleEndian.PutUint16(bmp[26:], 1)
	binary.LittleEndian.PutUint16(bmp[28:], 24)
	return bmp
}

// makeZipWithBMP builds an in-memory ZIP containing system_info.txt plus a
// screenshot.bmp.
func makeZipWithBMP(t *testing.T, bmp []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("system_info.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("OS: Windows 11\n"))
	f, err = zw.Create("screenshot.bmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bmp)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// uploadZIP posts a ZIP to /api/log with the given metadata JSON and returns
// the parsed session_id (or "" if the upload failed).
func uploadZIP(t *testing.T, r http.Handler, apiKey, filename string, zipData []byte, metadata string) string {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("archive", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(zipData); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("metadata", metadata); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/log", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return ""
	}
	var ur struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ur); err != nil {
		t.Fatal(err)
	}
	return ur.SessionID
}

func TestScreenshot_HappyPath(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token, apiKey := setupE2ETestRouter(t, d, nil)

	bmp := makeTestBMP()
	zipData := makeZipWithBMP(t, bmp)
	sessionID := uploadZIP(t, r, apiKey, "report.zip", zipData,
		`{"hwid":"HAPPYHWID","os":"win11","username":"alice","ip":"1.2.3.4","country":"US"}`)
	if sessionID == "" {
		t.Fatal("upload returned no session_id")
	}

	var filePath string
	var w2, h2, sz2 int
	var mime string
	if err := d.QueryRow(
		"SELECT file_path, width, height, size_bytes, mime_type FROM screenshots WHERE session_id = $1",
		sessionID,
	).Scan(&filePath, &w2, &h2, &sz2, &mime); err != nil {
		t.Fatalf("screenshot row missing: %v", err)
	}
	if w2 != 4 || h2 != 3 || sz2 != 66 || mime != "image/bmp" {
		t.Errorf("row: w=%d h=%d sz=%d mime=%q, want 4/3/66/image/bmp", w2, h2, sz2, mime)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("file not on disk: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(filePath) })

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET failed: %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "image/bmp" {
		t.Errorf("Content-Type = %q, want image/bmp", got)
	}
	if got := w.Body.Bytes(); len(got) != 66 {
		t.Errorf("body size = %d, want 66", len(got))
	}
}

func TestScreenshot_TenantIsolation(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "test-secret", "*", nil, nil, nil, nil)

	userA := createTestUserWithRole(t, d, "tenanta", "pw", "user")
	sessionID := uuid.New().String()
	if _, err := d.Exec(
		`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		 VALUES ($1, 'b', 'h', 'win', 'u', '1.1.1.1', 'US', $2, CURRENT_TIMESTAMP)`,
		sessionID, userA,
	); err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(filepath.Join("data", "screenshots", sessionID+".bmp"))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, makeTestBMP(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(abs) })
	if _, err := d.Exec(
		`INSERT INTO screenshots (id, session_id, file_path, size_bytes, width, height)
		 VALUES ($1, $2, $3, 66, 4, 3)`,
		uuid.New().String(), sessionID, "data/screenshots/"+sessionID+".bmp",
	); err != nil {
		t.Fatal(err)
	}

	tokenB, _ := workerToken(t, d, "tenantb")
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("B saw A's screenshot: %d %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_DeleteAdminOnly(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, adminTok, apiKey := setupE2ETestRouter(t, d, nil)

	bmp := makeTestBMP()
	zipData := makeZipWithBMP(t, bmp)
	sessionID := uploadZIP(t, r, apiKey, "report.zip", zipData,
		`{"hwid":"DELHW","os":"win","username":"u","ip":"2.2.2.2","country":"US"}`)
	if sessionID == "" {
		t.Fatal("upload returned no session_id")
	}

	// GET as admin returns 200 (sanity).
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET = %d, want 200", w.Code)
	}

	// Non-admin DELETE forbidden.
	workerTok, _ := workerToken(t, d, "regularuser")
	req = httptest.NewRequest(http.MethodDelete, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+workerTok)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin DELETE = %d, want 403", w.Code)
	}

	// Admin DELETE 204.
	req = httptest.NewRequest(http.MethodDelete, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("admin DELETE = %d %s, want 204", w.Code, w.Body.String())
	}

	// Subsequent GET 404.
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("post-delete GET = %d, want 404", w.Code)
	}

	// File removed from disk.
	var filePath string
	if err := d.QueryRow("SELECT file_path FROM screenshots WHERE session_id = $1", sessionID).Scan(&filePath); err == nil {
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Errorf("screenshot file still exists: err=%v", err)
		}
	}
}

func TestScreenshot_AbsentFromZip(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token, apiKey := setupE2ETestRouter(t, d, nil)

	// Upload a ZIP with NO screenshot.bmp.
	zipData := createTestZip(t, map[string]string{
		"system_info.txt": "OS: Linux\n",
	})
	sessionID := uploadZIP(t, r, apiKey, "report.zip", zipData,
		`{"hwid":"NOSCREENHW","os":"linux","username":"u","ip":"3.3.3.3","country":"US"}`)
	if sessionID == "" {
		t.Fatal("upload returned no session_id")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("no-screenshot session: GET = %d, want 404", w.Code)
	}

	// Bogus session id.
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/"+uuid.New().String()+"/screenshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("bogus session: GET = %d, want 404", w.Code)
	}
}

// silence unused-import warning if io isn't otherwise referenced.
var _ = io.EOF
