package api_test

import (
	"bytes"
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

func TestSettingsHandler_Update(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := `{"rate_limit":"200","telegram_token":"newtoken"}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var getResp map[string]any
	req2 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w2 := httptest.NewRecorder()
	handler.Get(w2, req2)
	if err := json.Unmarshal(w2.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}

	settings := getResp["settings"].(map[string]any)
	if settings["rate_limit"] != "200" {
		t.Errorf("expected rate_limit=200, got %v", settings["rate_limit"])
	}
	if settings["telegram_token"] != "newtoken" {
		t.Errorf("expected telegram_token=newtoken, got %v", settings["telegram_token"])
	}
}

func TestSettingsHandler_Update_Partial(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	body := `{"telegram_chat_id":"12345"}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var getResp map[string]any
	req2 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w2 := httptest.NewRecorder()
	handler.Get(w2, req2)
	if err := json.Unmarshal(w2.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}

	settings := getResp["settings"].(map[string]any)
	if settings["telegram_chat_id"] != "12345" {
		t.Errorf("expected telegram_chat_id=12345, got %v", settings["telegram_chat_id"])
	}
	if v, ok := settings["rate_limit"]; !ok || v == "" {
		t.Error("expected rate_limit to still exist after partial update")
	}
}

func TestSettingsHandler_Update_InvalidJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSettingsHandler_Update_TriggersCallback(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSettingsHandler(d, "test-secret")

	called := false
	handler.SetOnUpdate(func() { called = true })

	body := `{"rate_limit":"300"}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if !called {
		t.Error("expected onUpdate callback to be called")
	}
}
