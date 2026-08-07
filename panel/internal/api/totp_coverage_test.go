package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestTOTP_Setup_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "totp_setup_ok", "pass123")
	h := api.NewTOTPHandler(d)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/setup", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.Setup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["qr_base64"] == "" {
		t.Fatal("expected non-empty qr_base64")
	}
}

func TestTOTP_Setup_Unauthenticated(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTOTPHandler(d)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/setup", nil)
	w := httptest.NewRecorder()
	h.Setup(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTOTP_Verify_Unauthenticated(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTOTPHandler(d)

	body := strings.NewReader(`{"passcode":"123456"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify", body)
	w := httptest.NewRecorder()
	h.Verify(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTOTP_Verify_NotSetup(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "totp_verify_notsetup", "pass123")
	h := api.NewTOTPHandler(d)

	body := strings.NewReader(`{"passcode":"123456"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify", body)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.Verify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "TOTP not set up. Call setup first." {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestTOTP_Disable_Unauthenticated(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTOTPHandler(d)

	body := strings.NewReader(`{"password":"whatever"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/disable", body)
	w := httptest.NewRecorder()
	h.Disable(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTOTP_Disable_InvalidPassword(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "totp_disable_badpw", "correct_password")
	h := api.NewTOTPHandler(d)

	body := strings.NewReader(`{"password":"wrong_password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/disable", body)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.Disable(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid password" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestTOTP_Required_WithUsername(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "totp_required_user", "pass123")
	// Enable TOTP for this user
	_, err := d.Exec("UPDATE users SET totp_enabled = TRUE WHERE id = $1", uid)
	if err != nil {
		t.Fatal(err)
	}
	h := api.NewTOTPHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/2fa/required?username=totp_required_user", nil)
	w := httptest.NewRecorder()
	h.Required(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]bool
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp["required"] {
		t.Fatal("expected required=true")
	}
}

func TestTOTP_Required_WithoutUsername(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTOTPHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/2fa/required", nil)
	w := httptest.NewRecorder()
	h.Required(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "username is required" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}
