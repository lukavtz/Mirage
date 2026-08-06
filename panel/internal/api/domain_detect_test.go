package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/testutil"
)

// TestAutoTag_OwnerForbidden verifies a worker cannot run AutoTag on a session
// owned by another user: 403 and no tags written.
func TestAutoTag_OwnerForbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, _ := setupTestRouter(t, d, nil)

	tokenA, ownerA := workerToken(t, d, "owner-a")
	tokenB, _ := workerToken(t, d, "worker-b")

	sid := uuid.New().String()
	insertSessionWithOwner(t, d, sid, ownerA)

	_, err := d.Exec("INSERT INTO domain_detect (id, domain, tag, color) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), "example.com", "Test", "#00FF00")
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ($1, $2, 'https://example.com/login', 'alice', 'secret', 'chrome')`, uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/auto-tag", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	if err := d.QueryRow("SELECT COUNT(*) FROM session_tags WHERE session_id = $1", sid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 tags on foreign session, got %d", count)
	}

	// owner can still auto-tag their own session
	req2 := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/auto-tag", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenA)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("owner auto-tag: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var tags []any
	if err := json.Unmarshal(w2.Body.Bytes(), &tags); err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 {
		t.Errorf("owner auto-tag: expected 1 tag, got %d", len(tags))
	}
}
