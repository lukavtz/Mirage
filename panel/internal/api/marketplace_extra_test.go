package api_test

import (
	"bytes"
	"encoding/json"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestMarketplace_RenewLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "renewer", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Renewable", "Can renew", 1999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "renew-license-key-001"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	purchaseID := uuid.New().String()
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		purchaseID, uid, pid, licenseKey, "starter", `{"max_sessions":50}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", handler.RenewLicense)

	body := `{"license_key":"` + licenseKey + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["message"] != "license renewed" {
		t.Errorf("message = %q, want %q", resp["message"], "license renewed")
	}
	if resp["expires_at"] == "" {
		t.Error("expected expires_at")
	}
}

func TestMarketplace_RenewLicense_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "renewfail", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", handler.RenewLicense)

	body := `{"license_key":"does-not-exist"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_RenewLicense_Lifetime(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "lifetimeuser", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Lifetime", "Lifetime license", 9999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "lifetime-license-key"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(100 * 365 * 24 * time.Hour).Format(time.RFC3339)
	purchaseID := uuid.New().String()
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		purchaseID, uid, pid, licenseKey, "lifetime", `{"max_sessions":-1}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", handler.RenewLicense)

	body := `{"license_key":"` + licenseKey + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_LicenseStatus(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "statuscheck", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "StatusMod", "Check status", 1499, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "status-license-key"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	purchaseID := uuid.New().String()
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		purchaseID, uid, pid, licenseKey, "starter", `{"max_sessions":50}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/marketplace/license-status", handler.LicenseStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/license-status?license_key="+licenseKey, nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.LicenseInfo
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Tier != "starter" {
		t.Errorf("tier = %q, want %q", resp.Tier, "starter")
	}
	if resp.DaysRemaining == 0 {
		t.Error("expected non-zero days_remaining")
	}
}

func TestMarketplace_LicenseStatus_NoLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "nolicense", "pass")

	r := chi.NewRouter()
	r.Get("/api/marketplace/license-status", handler.LicenseStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/license-status", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.LicenseInfo
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Tier != "none" {
		t.Errorf("tier = %q, want %q", resp.Tier, "none")
	}
}

func TestMarketplace_Upgrade(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "upgrader", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "UpgradeMod", "Can upgrade", 2999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "upgrade-license-key"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	purchaseID := uuid.New().String()
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		purchaseID, uid, pid, licenseKey, "starter", `{"max_sessions":50}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	body := `{"license_key":"` + licenseKey + `","new_tier":"pro"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var upgradeResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &upgradeResp); err != nil {
		t.Fatal(err)
	}
	if upgradeResp["tier"] != "pro" {
		t.Errorf("tier = %q, want %q", upgradeResp["tier"], "pro")
	}
}

func TestMarketplace_Upgrade_NoLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "noupgrade", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	body := `{"license_key":"nonexistent","new_tier":"pro"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Upgrade_InvalidTier(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "badtier", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	body := `{"license_key":"x","new_tier":"invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Upgrade_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "badjson", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_StartTrial(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "trialuser", "pass")

	r := chi.NewRouter()
	r.Post("/api/auth/start-trial", handler.StartTrial)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/start-trial?machine_id=m1", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["tier"] != "starter" {
		t.Errorf("tier = %q, want %q", resp["tier"], "starter")
	}
	if resp["max_sessions"] != "50" {
		t.Errorf("max_sessions = %q, want %q", resp["max_sessions"], "50")
	}
}

func TestMarketplace_StartTrial_AlreadyUsed(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "trialused", "pass")

	_, err := d.Exec(`INSERT INTO license_trials (id, user_id, ip, machine_id, tier, max_sessions, expires_at)
		VALUES ($1, $2, '1.2.3.4', 'm1', 'starter', 50, CURRENT_TIMESTAMP + INTERVAL '7 days')`,
		uuid.New().String(), uid)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/auth/start-trial", handler.StartTrial)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/start-trial", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_RenewLicense_Forbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	owner := createTestUser(t, d, "licowner", "pass")
	other := createTestUser(t, d, "licother", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "LicMod", "desc", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "forbidden-license"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), owner, pid, licenseKey, "starter", `{}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", handler.RenewLicense)

	body := `{"license_key":"` + licenseKey + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Upgrade_Forbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	owner := createTestUser(t, d, "upowner", "pass")
	other := createTestUser(t, d, "upother", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "UpMod", "desc", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "forbidden-upgrade"
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), owner, pid, licenseKey, "starter", `{}`, expires, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	body := `{"license_key":"` + licenseKey + `","new_tier":"pro"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_LicenseStatus_Expired(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "expireduser", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "ExpMod", "desc", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "expired-license"
	now := time.Now().UTC().Format(time.RFC3339)
	expired := time.Now().UTC().Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), uid, pid, licenseKey, "starter", `{}`, expired, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/marketplace/license-status", handler.LicenseStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/license-status?license_key="+licenseKey, nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.LicenseInfo
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DaysRemaining != 0 {
		t.Errorf("days_remaining = %d, want 0", resp.DaysRemaining)
	}
}

func TestMarketplace_Purchase_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", handler.Purchase)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", strings.NewReader(`{"product_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Purchase_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "badpurchase", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", handler.Purchase)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Purchase_InvalidTier(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "badtierbuyer", "pass")
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "TierMod", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", handler.Purchase)

	body := `{"product_id":"` + pid + `","tier":"platinum"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Activate_Forbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	owner := createTestUser(t, d, "actowner", "pass")
	other := createTestUser(t, d, "actother", "pass")
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "ActMod", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}

	licenseKey := "forbidden-activate"
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), owner, pid, licenseKey, "starter", `{}`, now, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", handler.Activate)

	body := `{"license_key":"` + licenseKey + `","hwid":"hw-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_RenewLicense_MissingKey(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "missingkey", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", handler.RenewLicense)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Upgrade_SameTier(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "sametier", "pass")
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "SameTier", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}

	licenseKey := "same-tier-key"
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), uid, pid, licenseKey, "pro", `{}`, now, now,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", handler.UpgradeLicense)

	// Upgrading pro -> pro should 400 (not higher)
	body := `{"license_key":"` + licenseKey + `","new_tier":"pro"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLicenseMiddleware_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called without claims")
	}
}

func TestLicenseMiddleware_NoLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUserWithRole(t, d, "nolic", "pass", "user")

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called without license")
	}
}

func TestLicenseMiddleware_Admin(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUser(t, d, "adminlic", "pass")

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("handler should be called for admin")
	}
}

func TestLicenseMiddleware_ValidLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUserWithRole(t, d, "validlic", "pass", "user")
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Lic", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}

	future := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), uid, pid, "valid-key", "starter", `{}`, future, future,
	); err != nil {
		t.Fatal(err)
	}

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("handler should be called with valid license")
	}
}

func TestLicenseMiddleware_ExpiredLicense(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUserWithRole(t, d, "explics", "pass", "user")
	pid := uuid.New().String()
	if _, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Lic", "desc", 999, "module",
	); err != nil {
		t.Fatal(err)
	}

	past := time.Now().UTC().Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(), uid, pid, "expired-key", "starter", `{}`, past, past,
	); err != nil {
		t.Fatal(err)
	}

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called with expired license")
	}
}

func TestLicenseMiddleware_ActiveTrial(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUserWithRole(t, d, "trialuser2", "pass", "user")
	if _, err := d.Exec(`INSERT INTO license_trials (id, user_id, ip, machine_id, tier, max_sessions, expires_at)
		VALUES ($1, $2, '1.2.3.4', 'm1', 'starter', 50, CURRENT_TIMESTAMP + INTERVAL '7 days')`,
		uuid.New().String(), uid); err != nil {
		t.Fatal(err)
	}

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("handler should be called with active trial")
	}
}

func TestLicenseMiddleware_ExpiredTrial(t *testing.T) {
	d := testutil.OpenTestDB(t)
	mw := api.LicenseMiddleware(d)

	uid := createTestUserWithRole(t, d, "exptrial", "pass", "user")
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if _, err := d.Exec(`INSERT INTO license_trials (id, user_id, ip, machine_id, tier, max_sessions, expires_at)
		VALUES ($1, $2, '1.2.3.4', 'm1', 'starter', 50, $3)`,
		uuid.New().String(), uid, past); err != nil {
		t.Fatal(err)
	}

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("handler should not be called with expired trial")
	}
}
