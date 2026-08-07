package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestSettings_Update_Valid(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := bytes.NewBufferString(`{"test_key": "test_value"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/settings", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uuid.New().String(), Role: "admin"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	settings, ok := resp["settings"].(map[string]any)
	if !ok {
		t.Fatal("expected settings object in response")
	}
	if settings["test_key"] != "test_value" {
		t.Errorf("expected test_key=test_value, got %v", settings["test_key"])
	}

	var dbVal string
	err := d.QueryRow("SELECT value FROM settings WHERE key = 'test_key'").Scan(&dbVal)
	if err != nil {
		t.Fatal("setting not found in db:", err)
	}
	if dbVal != "test_value" {
		t.Errorf("expected test_value, got %q", dbVal)
	}
}

func TestSettings_Update_NoAuth(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := bytes.NewBufferString(`{"test_key": "test_value"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/settings", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSettings_Update_NoAdminRole(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := bytes.NewBufferString(`{"test_key": "test_value"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/settings", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uuid.New().String(), Role: "worker"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSettings_Update_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := bytes.NewBufferString(`{not valid json`)
	req := httptest.NewRequest(http.MethodPut, "/api/settings", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uuid.New().String(), Role: "admin"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
