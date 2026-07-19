package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/mirage-panel/internal/api"
)

func TestSettingsHandler_Get(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	handler.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	settings, ok := resp["settings"].(map[string]any)
	if !ok {
		t.Fatal("expected settings object")
	}

	if _, ok := settings["rate_limit"]; !ok {
		t.Error("expected rate_limit setting")
	}
}

func TestSettingsHandler_Get_IncludesAudit(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	handler.Get(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	audit, ok := resp["audit"].([]any)
	if !ok {
		t.Fatal("expected audit array")
	}
	if audit == nil {
		t.Error("expected non-nil audit array")
	}
}
