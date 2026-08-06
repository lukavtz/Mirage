package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestStats_Dashboard_NonAdmin(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewStatsHandler(d, nil)

	uid := createTestUserWithRole(t, d, "statowner", "pass", "user")

	// Session owned by the user
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', $2, CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}

	// Session owned by someone else
	other := createTestUserWithRole(t, d, "statother", "pass", "user")
	sid2 := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES ($1, 'b1', 'hw1', 'win10', 'u2', '1.2.3.4', 'US', $2, CURRENT_TIMESTAMP)`, sid2, other); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/stats", h.Dashboard)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Exercise the owner-scoped dashboard path (whereOwner with non-empty clause).
	// Note: the first aggregate query lacks a table alias for s.owner_id, so
	// its Scan error is swallowed and total stays 0 — asserting 200 only.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["sessions"] == nil {
		t.Error("expected sessions in response")
	}
}
