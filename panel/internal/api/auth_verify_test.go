package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestVerifyLogin_MissingCode(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	// Invalid JSON body triggers the 400 path in VerifyLogin
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify-login", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.VerifyLogin(w, req)

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

func TestVerifyLogin_InvalidCode(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "verify_fail", "pass123")
	handler := api.NewAuthHandler(d, "test-secret")

	_, err := d.Exec("UPDATE users SET totp_enabled = TRUE, totp_secret = $1 WHERE id = $2", "JBSWY3DPEHPK3PXP", uid)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"username":"verify_fail","password":"pass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var loginResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	totpToken, ok := loginResp["totp_token"].(string)
	if !ok || totpToken == "" {
		t.Fatal("expected totp_token from login")
	}

	vbody := `{"totp_token":"` + totpToken + `","passcode":"000000"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify-login", bytes.NewReader([]byte(vbody)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.VerifyLogin(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestVerifyLogin_SetupThenVerify(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "totp_full", "pass123")
	authHandler := api.NewAuthHandler(d, "test-secret")
	totpHandler := api.NewTOTPHandler(d)

	loginBody := `{"username":"totp_full","password":"pass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	authHandler.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var loginResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	if loginResp["token"] == "" {
		t.Fatal("expected token from login")
	}

	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/setup", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	setupReq = setupReq.WithContext(middleware.ContextWithClaims(setupReq.Context(), claims))
	w2 := httptest.NewRecorder()
	totpHandler.Setup(w2, setupReq)
	if w2.Code != http.StatusOK {
		t.Fatalf("setup: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var secret string
	if err := d.QueryRow("SELECT totp_secret FROM users WHERE id = $1", uid).Scan(&secret); err != nil || secret == "" {
		t.Fatal("expected non-empty totp_secret")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	verifyBody := `{"passcode":"` + code + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify", bytes.NewReader([]byte(verifyBody)))
	verifyReq = verifyReq.WithContext(middleware.ContextWithClaims(verifyReq.Context(), claims))
	verifyReq.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	totpHandler.Verify(w3, verifyReq)
	if w3.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	req4 := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(loginBody)))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	authHandler.Login(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("second login: expected 200, got %d: %s", w4.Code, w4.Body.String())
	}
	var loginResp2 map[string]any
	if err := json.Unmarshal(w4.Body.Bytes(), &loginResp2); err != nil {
		t.Fatal(err)
	}
	totpToken, ok := loginResp2["totp_token"].(string)
	if !ok || totpToken == "" {
		t.Fatal("expected totp_token from second login")
	}

	code2, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	vBody := `{"totp_token":"` + totpToken + `","passcode":"` + code2 + `"}`
	req5 := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify-login", bytes.NewReader([]byte(vBody)))
	req5.Header.Set("Content-Type", "application/json")
	w5 := httptest.NewRecorder()
	authHandler.VerifyLogin(w5, req5)
	if w5.Code != http.StatusOK {
		t.Fatalf("verify-login: expected 200, got %d: %s", w5.Code, w5.Body.String())
	}

	var verifyResp map[string]any
	if err := json.Unmarshal(w5.Body.Bytes(), &verifyResp); err != nil {
		t.Fatal(err)
	}
	if verifyResp["token"] == "" {
		t.Error("expected non-empty token from verify-login")
	}
	if verifyResp["expires_at"] == "" {
		t.Error("expected non-empty expires_at")
	}
}

func TestVerifyLogin_ExpiredToken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "expireduser", "pass123")
	handler := api.NewAuthHandler(d, "test-secret")

	// A garbage token is not in the temp tokens map -> 401
	vbody := `{"totp_token":"not-a-real-token","passcode":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/2fa/verify-login", bytes.NewReader([]byte(vbody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.VerifyLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
