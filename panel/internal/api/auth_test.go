package api_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/ws"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mirage-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

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
	_, err = d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
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
	_, err := d.Exec("INSERT INTO api_keys (id, user_id, name, key_hash) VALUES (?, ?, ?, ?)",
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
	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil)
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
	api.SetupRoutes(r, d, jwtSecret, "*", hub, nil, nil)
	token, _, err := auth.GenerateToken(userID, "admin", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	key := createTestAPIKey(t, d, userID)
	return r, token, key
}

func TestLogin_Success(t *testing.T) {
	d := openTestDB(t)
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
	d := openTestDB(t)
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
	d := openTestDB(t)

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
	d := openTestDB(t)
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
	d := openTestDB(t)
	_, err := d.Exec("INSERT INTO bans (id, ip, reason) VALUES (?, ?, ?)",
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
	d := openTestDB(t)
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
