package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSP_IngestValidArchive(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	zipData := createTestZip(t, map[string]string{
		"Browser Data/Chrome_passwords.txt": "https://example.com\tuser\tpass",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", bytes.NewReader(zipData))
	req.Header.Set("Authorization", "Bearer "+token)
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

func TestSSP_NotAZip(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	body := []byte("this is not a zip file")
	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestSSP_EmptyArchive(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestSSP_NoAuth(t *testing.T) {
	d := openTestDB(t)
	r, _ := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}
