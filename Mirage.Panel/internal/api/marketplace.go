package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/middleware"
)

type MarketplaceHandler struct {
	db *sql.DB
}

func NewMarketplaceHandler(db *sql.DB) *MarketplaceHandler {
	return &MarketplaceHandler{db: db}
}

type Product struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	PriceCents  int    `json:"price_cents"`
	ProductType string `json:"product_type"`
	CreatedAt   string `json:"created_at"`
}

type Purchase struct {
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	ProductID   string  `json:"product_id"`
	LicenseKey  string  `json:"license_key"`
	ActivatedAt *string `json:"activated_at"`
	ExpiresAt   *string `json:"expires_at"`
	CreatedAt   string  `json:"created_at"`
}

func generateLicenseKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *MarketplaceHandler) ListProducts(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, name, description, price_cents, product_type, created_at FROM products ORDER BY created_at DESC")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query products")
		return
	}
	defer rows.Close()

	products := make([]Product, 0)
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.PriceCents, &p.ProductType, &p.CreatedAt); err != nil {
			continue
		}
		products = append(products, p)
	}

	writeJSON(w, http.StatusOK, products)
}

func (h *MarketplaceHandler) Purchase(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		ProductID string `json:"product_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ProductID == "" {
		writeError(w, http.StatusBadRequest, "product_id is required")
		return
	}

	var product Product
	err := h.db.QueryRow(
		"SELECT id, name, description, price_cents, product_type, created_at FROM products WHERE id = ?", req.ProductID,
	).Scan(&product.ID, &product.Name, &product.Description, &product.PriceCents, &product.ProductType, &product.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "product not found")
		return
	}

	id := uuid.New().String()
	licenseKey := generateLicenseKey()
	now := time.Now().UTC().Format(time.RFC3339)
	expiresAt := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)

	_, err = h.db.Exec(
		"INSERT INTO purchases (id, user_id, product_id, license_key, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, claims.UserID, req.ProductID, licenseKey, expiresAt, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create purchase")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"license_key": licenseKey,
		"expires_at":  expiresAt,
	})
}

func (h *MarketplaceHandler) Activate(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.LicenseKey == "" || req.HWID == "" {
		writeError(w, http.StatusBadRequest, "license_key and hwid are required")
		return
	}

	var purchaseID, userID string
	var activatedAt *string
	err := h.db.QueryRow(
		"SELECT id, user_id, activated_at FROM purchases WHERE license_key = ?", req.LicenseKey,
	).Scan(&purchaseID, &userID, &activatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "license key not found")
		return
	}

	if userID != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "license key does not belong to this user")
		return
	}

	if activatedAt != nil {
		writeError(w, http.StatusBadRequest, "license key is already activated")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = h.db.Exec("UPDATE purchases SET activated_at = ? WHERE id = ?", now, purchaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to activate license")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "license activated"})
}

func (h *MarketplaceHandler) MyPurchases(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	rows, err := h.db.Query(
		"SELECT id, user_id, product_id, license_key, activated_at, expires_at, created_at FROM purchases WHERE user_id = ? ORDER BY created_at DESC",
		claims.UserID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query purchases")
		return
	}
	defer rows.Close()

	purchases := make([]Purchase, 0)
	for rows.Next() {
		var p Purchase
		if err := rows.Scan(&p.ID, &p.UserID, &p.ProductID, &p.LicenseKey, &p.ActivatedAt, &p.ExpiresAt, &p.CreatedAt); err != nil {
			continue
		}
		purchases = append(purchases, p)
	}

	writeJSON(w, http.StatusOK, purchases)
}

func (h *MarketplaceHandler) CreateProduct(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		PriceCents  int    `json:"price_cents"`
		ProductType string `json:"product_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" || req.Description == "" || req.ProductType == "" {
		writeError(w, http.StatusBadRequest, "name, description, and product_type are required")
		return
	}
	if req.PriceCents <= 0 {
		writeError(w, http.StatusBadRequest, "price_cents must be positive")
		return
	}

	id := uuid.New().String()
	_, err := h.db.Exec(
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES (?, ?, ?, ?, ?)",
		id, req.Name, req.Description, req.PriceCents, req.ProductType,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create product")
		return
	}

	var p Product
	err = h.db.QueryRow(
		"SELECT id, name, description, price_cents, product_type, created_at FROM products WHERE id = ?", id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.PriceCents, &p.ProductType, &p.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back product")
		return
	}

	writeJSON(w, http.StatusCreated, p)
}

func (h *MarketplaceHandler) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM products WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete product")
		return
	}

	rows, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check result")
		return
	}
	if rows == 0 {
		writeError(w, http.StatusNotFound, "product not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "product deleted"})
}
