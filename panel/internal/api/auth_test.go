package api_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/testutil"
	"zialfi-panel/internal/ws"
)

func createTestUser(t *testing.T, d *sql.DB, username, password string) string {
	t.Helper()
	return createTestUserWithRole(t, d, username, password, "admin")
}

func createTestUserWithRole(t *testing.T, d *sql.DB, username, password, role string) string {
	t.Helper()
	id := uuid.New().String()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)",
		id, username, hash, role)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// createTestAPIKey inserts an API key bound to userID and returns the raw key
// that the caller sends as the X-API-Key header.
func createTestAPIKey(t *testing.T, d *sql.DB, userID string) string {
	t.Helper()
	raw := uuid.New().String() + uuid.New().String()
	hash := sha256.Sum256([]byte(raw))
	keyHash := fmt.Sprintf("%x", hash)
	_, err := d.Exec("INSERT INTO api_keys (id, user_id, name, key_hash) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), userID, "test-key", keyHash)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// setupLogsTestRouter wires a router whose /api/log routes are reachable via a
// real API key (the routes sit behind APIKeyAuth, which rejects requests
// without an X-API-Key header).
func setupLogsTestRouter(t *testing.T, d *sql.DB) (chi.Router, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()
	userID := createTestUser(t, d, "logsuser", "testpass")
	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil, nil)
	key := createTestAPIKey(t, d, userID)
	return r, key
}

// setupE2ETestRouter wires a router and returns the JWT token (for authed
// routes) plus a valid API key (for /api/log ingestion routes).
func setupE2ETestRouter(t *testing.T, d *sql.DB, hub *ws.Hub) (chi.Router, string, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()
	userID := createTestUser(t, d, "testuser", "testpass")
	api.SetupRoutes(r, d, jwtSecret, "*", hub, nil, nil, nil)
	token, _, err := auth.GenerateToken(userID, "admin", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	key := createTestAPIKey(t, d, userID)
	return r, token, key
}

func TestLogin_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"testuser","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == "" {
		t.Error("expected non-empty token")
	}
	if resp["expires_at"] == "" {
		t.Error("expected non-empty expires_at")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"testuser","password":"wrongpass"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

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

func TestLogin_NonexistentUser(t *testing.T) {
	d := testutil.OpenTestDB(t)

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"nobody","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

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

func TestLogin_RateLimit(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"admin","password":"wrong"}`
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Login(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after rate limit, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestLogin_BannedIP(t *testing.T) {
	d := testutil.OpenTestDB(t)
	_, err := d.Exec("INSERT INTO bans (id, ip, reason) VALUES ($1, $2, $3)",
		uuid.New().String(), "192.0.2.1", "manual ban")
	if err != nil {
		t.Fatal(err)
	}

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:54321"
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestLogin_MissingFields(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	tests := []struct {
		name string
		body string
	}{
		{"empty username", `{"username":"","password":"pass"}`},
		{"empty password", `{"username":"user","password":""}`},
		{"both empty", `{"username":"","password":""}`},
		{"no fields", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.Login(w, req)

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
		})
	}
}

func TestForgotPassword_ValidUser(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ForgotPassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == "" {
		t.Error("expected non-empty token")
	}
	if resp["message"] == "" {
		t.Error("expected message")
	}
}

func TestForgotPassword_InvalidUser(t *testing.T) {
	d := testutil.OpenTestDB(t)

	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"nobody"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ForgotPassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (no enumeration), got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] != nil {
		t.Error("should not return token for nonexistent user")
	}
	if resp["message"] == "" {
		t.Error("expected message")
	}
}

func TestForgotPassword_EnumerationPrevention(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "realuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	// Call with valid user
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password",
		bytes.NewReader([]byte(`{"username":"realuser"}`)))
	req1.Header.Set("Content-Type", "application/json")
	handler.ForgotPassword(w1, req1)

	// Call with invalid user
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password",
		bytes.NewReader([]byte(`{"username":"fakeuser"}`)))
	req2.Header.Set("Content-Type", "application/json")
	handler.ForgotPassword(w2, req2)

	// Both must return 200 with the same message
	if w1.Code != w2.Code {
		t.Fatalf("status codes differ: %d vs %d", w1.Code, w2.Code)
	}

	var r1, r2 map[string]any
	json.Unmarshal(w1.Body.Bytes(), &r1)
	json.Unmarshal(w2.Body.Bytes(), &r2)

	if r1["message"] != r2["message"] {
		t.Fatalf("messages differ — enables enumeration: %q vs %q", r1["message"], r2["message"])
	}
}

// requestResetCode calls ForgotPassword and extracts the one-time code from
// the slog warning the handler logs when Telegram is not configured. The
// endpoint deliberately does NOT return the code in the response body
// (anti-enumeration), so tests must capture it from the log line.
func requestResetCode(t *testing.T, handler *api.AuthHandler, username string) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password",
		bytes.NewReader([]byte(`{"username":"`+username+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	handler.ForgotPassword(w, req)

	// log line: ... msg="password reset code (no Telegram configured)" user=... code=<hex>
	m := regexp.MustCompile(`code=([0-9a-f]{64})`).FindStringSubmatch(buf.String())
	if m == nil {
		t.Fatalf("no reset code in handler log; body=%s log=%q", w.Body.String(), buf.String())
	}
	return m[1]
}

func TestResetPassword_ValidToken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	userID := createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	// First, get a reset token (captured from the log — the endpoint
	// deliberately does not return it, see requestResetCode)
	token := requestResetCode(t, handler, "testuser")

	// Now reset the password
	w2 := httptest.NewRecorder()
	resetBody := fmt.Sprintf(`{"token":"%s","new_password":"newpass12345"}`, token)
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
		bytes.NewReader([]byte(resetBody)))
	req2.Header.Set("Content-Type", "application/json")
	handler.ResetPassword(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp["message"] != "Password reset successfully" {
		t.Errorf("unexpected message: %s", resp["message"])
	}

	// Verify auth_sessions were cleared (check before any new logins)
	var count int
	d.QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE user_id = $1", userID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 auth_sessions after reset, got %d", count)
	}

	// Verify old password no longer works
	w3 := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		bytes.NewReader([]byte(`{"username":"testuser","password":"secret123"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	handler.Login(w3, loginReq)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("old password should fail: got %d", w3.Code)
	}

	// Verify new password works
	w4 := httptest.NewRecorder()
	loginReq2 := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		bytes.NewReader([]byte(`{"username":"testuser","password":"newpass12345"}`)))
	loginReq2.Header.Set("Content-Type", "application/json")
	handler.Login(w4, loginReq2)
	if w4.Code != http.StatusOK {
		t.Errorf("new password should work: got %d: %s", w4.Code, w4.Body.String())
	}
}

func TestResetPassword_UsedToken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	// Get a reset token (captured from the log)
	token := requestResetCode(t, handler, "testuser")

	// Use the token once
	resetBody := fmt.Sprintf(`{"token":"%s","new_password":"newpass12345"}`, token)
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
		bytes.NewReader([]byte(resetBody)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ResetPassword(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("first reset should succeed: %d", w2.Code)
	}

	// Try using the same token again
	req3 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
		bytes.NewReader([]byte(resetBody)))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	handler.ResetPassword(w3, req3)

	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused token, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	userID := createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	// Insert an already-expired reset token directly
	resetID := uuid.New().String()
	tokenBytes := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	tokenHash := fmt.Sprintf("%x", sha256.Sum256(tokenBytes))
	d.Exec("INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
		resetID, userID, tokenHash, "2020-01-01T00:00:00Z")

	// Try resetting with the expired token
	resetBody := fmt.Sprintf(`{"token":"%x","new_password":"newpass12345"}`, tokenBytes)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
		bytes.NewReader([]byte(resetBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ResetPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResetPassword_ShortPassword(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "testuser", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")

	// Get a reset token (captured from the log)
	token := requestResetCode(t, handler, "testuser")

	// Try resetting with a short password
	resetBody := fmt.Sprintf(`{"token":"%s","new_password":"short"}`, token)
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
		bytes.NewReader([]byte(resetBody)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ResetPassword(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d: %s", w2.Code, w2.Body.String())
	}
}
