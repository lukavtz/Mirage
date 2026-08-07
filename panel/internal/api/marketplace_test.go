package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestMarketplace_ListProducts(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		uuid.New().String(), "Test Module", "A test module", 1999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/marketplace/products", handler.ListProducts)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/products", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var products []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &products); err != nil {
		t.Fatal(err)
	}
	if len(products) == 0 {
		t.Fatal("expected at least 1 product")
	}
	if products[0]["name"] != "Test Module" {
		t.Errorf("name = %v, want %q", products[0]["name"], "Test Module")
	}
	if products[0]["price_cents"] != float64(1999) {
		t.Errorf("price_cents = %v, want %d", products[0]["price_cents"], 1999)
	}
}

func TestMarketplace_ListProductsEmpty(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	r := chi.NewRouter()
	r.Get("/api/marketplace/products", handler.ListProducts)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/products", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var products []any
	if err := json.Unmarshal(w.Body.Bytes(), &products); err != nil {
		t.Fatal(err)
	}
	if len(products) != 0 {
		t.Errorf("expected empty list, got %d items", len(products))
	}
}

func TestMarketplace_Purchase(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "buyer", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Premium Module", "Premium description", 4999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", handler.Purchase)

	body := `{"product_id":"` + pid + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["license_key"] == "" {
		t.Error("expected license_key")
	}
	if resp["expires_at"] == "" {
		t.Error("expected expires_at")
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM purchases WHERE user_id = $1 AND product_id = $2", uid, pid).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 purchase, got %d", count)
	}
}

func TestMarketplace_PurchaseProductNotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "buyer2", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", handler.Purchase)

	body := `{"product_id":"` + uuid.New().String() + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Activate(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "activator", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Test Module", "Test desc", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	licenseKey := "test-license-123"
	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), uid, pid, licenseKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", handler.Activate)

	body := `{"license_key":"test-license-123","hwid":"hw-abc-456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var activatedAt *string
	d.QueryRow("SELECT activated_at FROM purchases WHERE license_key = $1", licenseKey).Scan(&activatedAt)
	if activatedAt == nil {
		t.Error("expected activated_at to be set")
	}
}

func TestMarketplace_ActivateAlreadyActivated(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "activator2", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Test Module", "Test desc", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, activated_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)",
		uuid.New().String(), uid, pid, "already-active-key",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", handler.Activate)

	body := `{"license_key":"already-active-key","hwid":"hw-xyz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_MyPurchases(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "purchaser", "pass")
	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Some Module", "Description", 2999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), uid, pid, "my-license-key",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/marketplace/purchases", handler.MyPurchases)

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/purchases", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var purchases []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &purchases); err != nil {
		t.Fatal(err)
	}
	if len(purchases) != 1 {
		t.Fatalf("expected 1 purchase, got %d", len(purchases))
	}
	if purchases[0]["license_key"] != "my-license-key" {
		t.Errorf("license_key = %v, want %q", purchases[0]["license_key"], "my-license-key")
	}
}

func TestMarketplace_CreateProduct(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	r := chi.NewRouter()
	r.Post("/api/marketplace/products", handler.CreateProduct)

	body := `{"name":"New Product","description":"A brand new product","price_cents":1499,"product_type":"module"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/products", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["name"] != "New Product" {
		t.Errorf("name = %v, want %q", resp["name"], "New Product")
	}
	if resp["price_cents"] != float64(1499) {
		t.Errorf("price_cents = %v, want %d", resp["price_cents"], 1499)
	}
}

func TestMarketplace_CreateProductValidation(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	r := chi.NewRouter()
	r.Post("/api/marketplace/products", handler.CreateProduct)

	body := `{"name":"","description":"","price_cents":0,"product_type":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/products", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_DeleteProduct(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	pid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, $3, $4, $5)",
		pid, "Delete Me", "To be deleted", 999, "module",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/marketplace/products/{id}", handler.DeleteProduct)

	req := httptest.NewRequest(http.MethodDelete, "/api/marketplace/products/"+pid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM products WHERE id = $1", pid).Scan(&count)
	if count != 0 {
		t.Error("expected product to be deleted")
	}
}

func TestMarketplace_DeleteProductNotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	r := chi.NewRouter()
	r.Delete("/api/marketplace/products/{id}", handler.DeleteProduct)

	req := httptest.NewRequest(http.MethodDelete, "/api/marketplace/products/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_ActivateNotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewMarketplaceHandler(d)

	uid := createTestUser(t, d, "activator3", "pass")

	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", handler.Activate)

	body := `{"license_key":"nonexistent-key","hwid":"hw-test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
