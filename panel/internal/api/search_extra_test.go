package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestSearch_EmptyQuery_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=", nil)
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 0 {
		t.Errorf("expected total=0, got %v", total)
	}
}

func TestSearch_NoResults_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=zzzznope", nil)
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 0 {
		t.Errorf("expected total=0, got %v", total)
	}
	results, _ := resp["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_Found_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'tester', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'example.com', 'alice', 'p@ss', 'chrome')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=example", nil)
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1, got %v", total)
	}
}

func TestSearchAdvanced_Basic(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'tester', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'test.com', 'bob', 'secret123', 'firefox')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?q=test.com", nil)
	w := httptest.NewRecorder()
	handler.AdvancedSearch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1, got %v", total)
	}
}

func TestSearchAdvanced_WithFilters(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'macos', 'tester', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'macsite.com', 'carol', 'mypass', 'safari')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?os=macos&browser=safari", nil)
	w := httptest.NewRecorder()
	handler.AdvancedSearch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1, got %v", total)
	}
}

func TestSearchAdvanced_Facets(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'linux', 'tester', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'facet.com', 'dave', 'pass', 'chromium')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	cid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO cookies (id, session_id, name, domain, value)
		VALUES ($1, $2, 'session', 'facet.com', 'xyz')`, cid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced", nil)
	w := httptest.NewRecorder()
	handler.AdvancedSearch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	facets, ok := resp["facets"].(map[string]any)
	if !ok {
		t.Fatal("expected facets in response")
	}

	browsers, _ := facets["browsers"].(map[string]any)
	if browsers["chromium"] != float64(1) {
		t.Errorf("expected chromium in browsers facet, got %v", browsers)
	}

	osmap, _ := facets["os"].(map[string]any)
	if osmap["linux"] != float64(1) {
		t.Errorf("expected linux in os facet, got %v", osmap)
	}
}

func TestSearchAdvanced_OwnerIsolation(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	uid := createTestUserWithRole(t, d, "searchowner", "pass", "user")

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'owneruser', '1.2.3.4', 'US', $2, CURRENT_TIMESTAMP)`, sid, uid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'private.com', 'owner', 'secret', 'chrome')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search/advanced?q=private.com", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.AdvancedSearch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1 for owner, got %v", total)
	}
}

func TestSearch_Router(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'routeruser', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'router.com', 'router', 'pass', 'chrome')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=router.com", nil)
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
	total, _ := resp["total"].(float64)
	if total == 0 {
		t.Error("expected at least 1 result")
	}
}

func TestSearch_TypeFilter_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'tfuser', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'typefilter.com', 'tf', 'pass', 'chrome')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	// Query with type=passwords alias
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=typefilter&type=passwords", nil)
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1, got %v", total)
	}

	// Query with type=wallet should find nothing
	req2 := httptest.NewRequest(http.MethodGet, "/api/search?q=typefilter&type=wallet", nil)
	w2 := httptest.NewRecorder()
	handler.Search(w2, req2)

	var resp2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	total2, _ := resp2["total"].(float64)
	if total2 != 0 {
		t.Errorf("expected total=0 for wallet type, got %v", total2)
	}
}

func TestSearch_Pagination_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	// Insert 3 sessions with matching passwords
	for i := 0; i < 3; i++ {
		sid := uuid.New().String()
		if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
			VALUES ($1, 'b1', 'hw1', 'win10', 'pguser', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid); err != nil {
			t.Fatal(err)
		}
		pid := uuid.New().String()
		if _, err := d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
			VALUES ($1, $2, 'paginate.com', 'pg', 'pass', 'chrome')`, pid, sid); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=paginate&per_page=1", nil)
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 3 {
		t.Errorf("expected total=3, got %v", total)
	}
	results, _ := resp["results"].([]any)
	if len(results) != 1 {
		t.Errorf("expected 1 result on page, got %d", len(results))
	}
	perPage, _ := resp["perPage"].(float64)
	if perPage != 1 {
		t.Errorf("perPage = %v, want 1", perPage)
	}
}

func TestSearch_OwnerIsolation(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewSearchHandler(d)

	uid := createTestUserWithRole(t, d, "sown", "pass", "user")

	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'sownuser', '1.2.3.4', 'US', $2, CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'own.com', 'own', 'secret', 'chrome')`, pid, sid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=own.com", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Search(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("expected total=1 for owner, got %v", total)
	}

	// A different user should not see it
	other := createTestUserWithRole(t, d, "sown2", "pass", "user")
	req2 := httptest.NewRequest(http.MethodGet, "/api/search?q=own.com", nil)
	claims2 := &auth.Claims{UserID: other, Role: "user"}
	req2 = req2.WithContext(middleware.ContextWithClaims(req2.Context(), claims2))
	w2 := httptest.NewRecorder()
	handler.Search(w2, req2)

	var resp2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	total2, _ := resp2["total"].(float64)
	if total2 != 0 {
		t.Errorf("expected total=0 for other user, got %v", total2)
	}
}
