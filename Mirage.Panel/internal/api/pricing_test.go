package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/user/mirage-panel/internal/api"
	"github.com/user/mirage-panel/internal/auth"
)

func TestPricing_ListTiers_Public(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewPricingHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/pricing", nil)
	w := httptest.NewRecorder()
	handler.ListTiers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	for _, tier := range []string{"starter", "pro", "team", "lifetime"} {
		if _, ok := resp[tier]; !ok {
			t.Errorf("expected tier %q in response", tier)
		}
	}
}

func TestPricing_MyFeatures_Unauthenticated(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewPricingHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/api/license/features", nil)
	w := httptest.NewRecorder()
	handler.MyFeatures(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPricing_MyFeatures_Authenticated(t *testing.T) {
	d := openTestDB(t)
	r, token := setupPricingTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/license/features", nil)
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
	if resp["tier"] == nil {
		t.Error("expected tier in response")
	}
	if resp["features"] == nil {
		t.Error("expected features in response")
	}
}

func TestReferral_GetCode(t *testing.T) {
	d := openTestDB(t)
	r, token := setupPricingTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/referrals/code", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["code"] == "" {
		t.Error("expected non-empty code")
	}
}

func TestReferral_Apply_InvalidCode(t *testing.T) {
	d := openTestDB(t)
	r, token := setupPricingTestRouter(t, d)

	body := `{"code":"invalid123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReferral_Stats(t *testing.T) {
	d := openTestDB(t)
	r, token := setupPricingTestRouter(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/referrals/stats", nil)
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
	if resp["code"] == nil {
		t.Error("expected code in response")
	}
}

func setupPricingTestRouter(t *testing.T, d *sql.DB) (chi.Router, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()
	uid := createTestUser(t, d, "pricinguser", "pass")
	token, _, err := auth.GenerateToken(uid, "admin", jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil)
	return r, token
}
