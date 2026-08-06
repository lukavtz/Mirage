package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestReferral_Apply_InvalidCode_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewReferralHandler(d)

	uid := createTestUser(t, d, "refbad", "pass")

	r := chi.NewRouter()
	r.Post("/api/referrals/apply", handler.Apply)

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", strings.NewReader(`{"code":"NOPE"}`))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReferral_Apply_SelfReferral(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewReferralHandler(d)

	uid := createTestUser(t, d, "refself", "pass")
	if _, err := d.Exec("UPDATE users SET referral_code = 'SELF99' WHERE id = $1", uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/referrals/apply", handler.Apply)

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", strings.NewReader(`{"code":"SELF99"}`))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReferral_Apply_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewReferralHandler(d)

	r := chi.NewRouter()
	r.Post("/api/referrals/apply", handler.Apply)

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", strings.NewReader(`{"code":"X"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReferral_Apply_MissingCode(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewReferralHandler(d)

	uid := createTestUser(t, d, "refmiss", "pass")

	r := chi.NewRouter()
	r.Post("/api/referrals/apply", handler.Apply)

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReferral_Apply_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewReferralHandler(d)

	uid := createTestUser(t, d, "refjson", "pass")

	r := chi.NewRouter()
	r.Post("/api/referrals/apply", handler.Apply)

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
