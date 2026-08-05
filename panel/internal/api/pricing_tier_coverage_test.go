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
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestPricing_CheckTierAccess(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "tieraccess", "pass")

	claims := &auth.Claims{UserID: uid, Role: "user"}
	if !api.CheckTierAccess(d, db.ProviderSQLite, claims, "smart_filters") {
		t.Error("expected tier access for user")
	}
	adminClaims := &auth.Claims{UserID: uid, Role: "admin"}
	if !api.CheckTierAccess(d, db.ProviderSQLite, adminClaims, "postgresql") {
		t.Error("expected tier access for admin")
	}
}

func TestPricing_CheckBotLimit(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "botlimit", "pass")
	claims := &auth.Claims{UserID: uid, Role: "user"}

	// No builds -> 0 current, max from starter tier (1)
	current, max, err := api.CheckBotLimit(d, db.ProviderSQLite, claims)
	if err != nil {
		t.Fatalf("CheckBotLimit: %v", err)
	}
	if current != 0 {
		t.Errorf("current = %d, want 0", current)
	}
	if max <= 0 {
		t.Errorf("max = %d, want > 0", max)
	}

	// Add a build owned by user and a session for it
	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}', ?)`, buildID, uid); err != nil {
		t.Fatal(err)
	}
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, ?, 'hw1', 'win10', 'u', '1.2.3.4', 'US', datetime('now'))`, sid, buildID); err != nil {
		t.Fatal(err)
	}

	current, _, err = api.CheckBotLimit(d, db.ProviderSQLite, claims)
	if err != nil {
		t.Fatalf("CheckBotLimit: %v", err)
	}
	if current != 1 {
		t.Errorf("current = %d, want 1", current)
	}
}

func TestPricing_CheckTierRateLimit(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "ratelimit", "pass")
	claims := &auth.Claims{UserID: uid, Role: "user"}

	// Seeded starter features have api_limited=true -> 30
	if got := api.CheckTierRateLimit(d, db.ProviderSQLite, claims); got != 30 {
		t.Errorf("starter rate limit = %d, want 30", got)
	}

	// Give the user a pro purchase (APILimited) -> 30
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES (?, ?, ?, ?, ?)",
		pid, "Pro", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES (?, ?, ?, ?, 'pro', '{}', datetime('now', '+30 days'), datetime('now'))",
		uuid.New().String(), uid, pid, "rl-key",
	); err != nil {
		t.Fatal(err)
	}

	if got := api.CheckTierRateLimit(d, db.ProviderSQLite, claims); got != 30 {
		t.Errorf("pro rate limit = %d, want 30", got)
	}

	// Team has api_limited=false -> 100 (newest purchase wins, use later timestamp)
	if _, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES (?, ?, ?, ?, 'team', '{}', datetime('now', '+30 days'), datetime('now', '+1 minute'))",
		uuid.New().String(), uid, pid, "rl-team-key",
	); err != nil {
		t.Fatal(err)
	}
	if got := api.CheckTierRateLimit(d, db.ProviderSQLite, claims); got != 100 {
		t.Errorf("team rate limit = %d, want 100", got)
	}
}

func TestTierLimit_CheckBots_NoClaims(t *testing.T) {
	d := openTestDB(t)
	mw := api.NewTierLimitMiddleware(d, db.ProviderSQLite)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	w := httptest.NewRecorder()
	mw.CheckBots(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called without claims")
	}
}

func TestTierLimit_CheckBots_Admin(t *testing.T) {
	d := openTestDB(t)
	mw := api.NewTierLimitMiddleware(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "admintier", "pass")

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw.CheckBots(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("handler should be called for admin")
	}
}

func TestTierLimit_CheckBots_UnderLimit(t *testing.T) {
	d := openTestDB(t)
	mw := api.NewTierLimitMiddleware(d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "underlimit", "pass", "user")

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw.CheckBots(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("handler should be called when under limit")
	}
}

func TestTierLimit_CheckBots_AtLimit(t *testing.T) {
	d := openTestDB(t)
	mw := api.NewTierLimitMiddleware(d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "atlimit", "pass", "user")

	// Starter tier max is 1; add 1 build + 1 session to hit the limit
	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}', ?)`, buildID, uid); err != nil {
		t.Fatal(err)
	}
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, ?, 'hw1', 'win10', 'u', '1.2.3.4', 'US', datetime('now'))`, sid, buildID); err != nil {
		t.Fatal(err)
	}

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw.CheckBots(next).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called at limit")
	}
}

func TestPricing_DefaultFeatures_InvalidSetting(t *testing.T) {
	d := openTestDB(t)
	// Corrupt the pricing_starter setting so LoadTierFeatures falls back to defaults
	if _, err := d.Exec("UPDATE settings SET value = 'not-json' WHERE key = 'pricing_starter'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE settings SET value = 'not-json' WHERE key = 'pricing_pro'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE settings SET value = 'not-json' WHERE key = 'pricing_team'"); err != nil {
		t.Fatal(err)
	}

	h := api.NewPricingHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Get("/api/pricing", h.ListTiers)

	req := httptest.NewRequest(http.MethodGet, "/api/pricing", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	starter, ok := resp["starter"]
	if !ok {
		t.Fatal("expected starter tier in response")
	}
	if starter["max_bots"] != float64(1) {
		t.Errorf("starter max_bots = %v, want 1 (default)", starter["max_bots"])
	}
	pro, ok := resp["pro"]
	if !ok {
		t.Fatal("expected pro tier in response")
	}
	if pro["max_bots"] != float64(7) {
		t.Errorf("pro max_bots = %v, want 7 (default)", pro["max_bots"])
	}
	team, ok := resp["team"]
	if !ok {
		t.Fatal("expected team tier in response")
	}
	if team["max_bots"] != float64(15) {
		t.Errorf("team max_bots = %v, want 15 (default)", team["max_bots"])
	}
}

func TestPricing_MyFeatures_TrialUser(t *testing.T) {
	d := openTestDB(t)
	h := api.NewPricingHandler(d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "trialpricing", "pass", "user")
	if _, err := d.Exec(`INSERT INTO license_trials (id, user_id, ip, machine_id, tier, max_sessions, expires_at)
		VALUES (?, ?, '1.2.3.4', 'm1', 'pro', 7, datetime('now', '+7 days'))`,
		uuid.New().String(), uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/license/features", h.MyFeatures)

	req := httptest.NewRequest(http.MethodGet, "/api/license/features", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["tier"] != "pro" {
		t.Errorf("tier = %v, want pro", resp["tier"])
	}
}
