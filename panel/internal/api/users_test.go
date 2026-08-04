package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/auth"
)

func setupUsersRouter(t *testing.T, d *sql.DB) (chi.Router, string, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()

	adminID := createTestUser(t, d, "adminuser", "adminpass")
	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil, db.ProviderSQLite, nil)

	adminToken, _, err := auth.GenerateToken(adminID, "admin", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}

	workerID := uuid.New().String()
	hash, err := auth.HashPassword("workerpass")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		workerID, "workeruser", hash, "worker")
	if err != nil {
		t.Fatal(err)
	}
	workerToken, _, err := auth.GenerateToken(workerID, "worker", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}

	return r, adminToken, workerToken
}

func TestUsers_List(t *testing.T) {
	d := openTestDB(t)
	r, adminToken, _ := setupUsersRouter(t, d)

	for i := 0; i < 3; i++ {
		id := uuid.New().String()
		hash, err := auth.HashPassword(fmt.Sprintf("pass%d", i))
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
			id, fmt.Sprintf("user%d", i), hash, "worker")
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var users []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}

	if len(users) < 4 {
		t.Errorf("expected at least 4 users, got %d", len(users))
	}

	found := false
	for _, u := range users {
		if u["username"] == "adminuser" {
			found = true
			if u["role"] != "admin" {
				t.Errorf("expected role admin, got %v", u["role"])
			}
			break
		}
	}
	if !found {
		t.Error("adminuser should be in the list")
	}
}

func TestUsers_ListForbidden(t *testing.T) {
	d := openTestDB(t)
	r, _, workerToken := setupUsersRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+workerToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_CreateInvite(t *testing.T) {
	d := openTestDB(t)
	r, adminToken, _ := setupUsersRouter(t, d)

	body := `{"role":"worker","tier":"starter","max_uses":5}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	code, ok := resp["code"].(string)
	if !ok || code == "" {
		t.Fatal("expected non-empty invite code")
	}

	// Verify it was stored in the database
	var stored string
	err := d.QueryRow("SELECT code FROM invite_codes WHERE code = ?", code).Scan(&stored)
	if err != nil {
		t.Fatalf("invite code not found in database: %v", err)
	}
}

func TestUsers_RegisterWithValidCode(t *testing.T) {
	d := openTestDB(t)
	r, adminToken, _ := setupUsersRouter(t, d)

	// Create an invite code
	inviteReq := `{"role":"worker","tier":"starter","max_uses":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", bytes.NewReader([]byte(inviteReq)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("failed to create invite: %d", w.Code)
	}

	var inviteResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &inviteResp)
	code := inviteResp["code"].(string)

	// Register with the code
	registerBody := fmt.Sprintf(`{"username":"newuser","password":"securepass","invite_code":"%s"}`, code)
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(registerBody)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["username"] != "newuser" {
		t.Errorf("expected username 'newuser', got %v", resp["username"])
	}
	if resp["role"] != "worker" {
		t.Errorf("expected role 'worker', got %v", resp["role"])
	}

	// Verify used_count was incremented
	var usedCount int
	err := d.QueryRow("SELECT used_count FROM invite_codes WHERE code = ?", code).Scan(&usedCount)
	if err != nil {
		t.Fatal(err)
	}
	if usedCount != 1 {
		t.Errorf("expected used_count=1, got %d", usedCount)
	}
}

func TestUsers_RegisterExpiredCode(t *testing.T) {
	d := openTestDB(t)

	// Create admin user for FK constraint
	adminID := createTestUser(t, d, "inviteadmin", "pass")

	// Insert an expired invite code directly
	code := "EXPIRED-CODE-12345"
	_, err := d.Exec(
		`INSERT INTO invite_codes (id, code, role, tier, max_uses, used_count, expires_at, created_by, created_at)
		 VALUES (?, ?, 'worker', 'starter', 1, 0, ?, ?, datetime('now'))`,
		uuid.New().String(), code, time.Now().Add(-1*time.Hour).Format("2006-01-02 15:04:05"), adminID,
	)
	if err != nil {
		t.Fatal(err)
	}

	r, _, _ := setupUsersRouter(t, d)

	registerBody := fmt.Sprintf(`{"username":"expireduser","password":"pass","invite_code":"%s"}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(registerBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410 for expired code, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestUsers_RegisterUsedUpCode(t *testing.T) {
	d := openTestDB(t)

	// Create admin user for FK constraint
	adminID := createTestUser(t, d, "inviteadmin2", "pass")

	code := "USED-UP-CODE-67890"
	_, err := d.Exec(
		`INSERT INTO invite_codes (id, code, role, tier, max_uses, used_count, created_by, created_at)
		 VALUES (?, ?, 'worker', 'starter', 1, 1, ?, datetime('now'))`,
		uuid.New().String(), code, adminID,
	)
	if err != nil {
		t.Fatal(err)
	}

	r, _, _ := setupUsersRouter(t, d)

	registerBody := fmt.Sprintf(`{"username":"usedupuser","password":"pass","invite_code":"%s"}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(registerBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for used-up code, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}
