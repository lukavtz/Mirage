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
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
	"zialfi-panel/internal/testutil"
)

func TestMarketplaceCreateProduct(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/products", h.CreateProduct)
	r.Get("/api/marketplace/purchases", h.MyPurchases)
	r.Post("/api/marketplace/activate", h.Activate)

	uid := "mp-user"
	// create product
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/products", bytes.NewReader([]byte(`{"name":"Pro","price_cents":299900,"description":"Pro tier","product_type":"subscription"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create product: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// list purchases (should be empty)
	req = httptest.NewRequest(http.MethodGet, "/api/marketplace/purchases", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("purchases: expected 200, got %d", w.Code)
	}
}

func TestUsersList(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewUsersHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Get("/api/users", h.List)

	uid := "ul-user"
	createTestUser(t, d, "user1", "pass1")
	createTestUser(t, d, "user2", "pass2")

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("users list: expected 200, got %d", w.Code)
	}
	var list []map[string]any
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) < 2 {
		t.Fatalf("users list: expected >=2, got %d", len(list))
	}
}

func TestLogsProcessSSP(t *testing.T) {
	d := testutil.OpenTestDB(t)
	logProc := services.NewLogProcessor(d, nil)
	h := api.NewSSPHandler(logProc)
	r := chi.NewRouter()
	r.Post("/api/log/ssp", h.ProcessSSP)

	req := httptest.NewRequest(http.MethodPost, "/api/log/ssp", bytes.NewReader([]byte(`{"ssp":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ssp empty: expected 400, got %d", w.Code)
	}
}

func TestReferralListStats(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewReferralHandler(d)
	r := chi.NewRouter()
	r.Get("/api/referrals/stats", h.Stats)
	uid := "rl-user"
	d.Exec("INSERT INTO referral_codes (id, user_id, code) VALUES ($1, $2, $3)", uuid.New().String(), uid, "MYCODE")
	d.Exec("INSERT INTO referral_redemptions (id, referrer_id, redeemed_by, code) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), uid, "other", "MYCODE")

	req := httptest.NewRequest(http.MethodGet, "/api/referrals/stats", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stats: expected 200, got %d", w.Code)
	}

}
