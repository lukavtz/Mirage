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
	"zialfi-panel/internal/middleware"

	"zialfi-panel/internal/db"
)

type MarketplaceHandler struct {
	db *sql.DB
	provider     db.ProviderType

}

func NewMarketplaceHandler(db *sql.DB, provider db.ProviderType) *MarketplaceHandler {
	return &MarketplaceHandler{db: db, provider: provider}
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
	Tier        string  `json:"tier"`
	Features    string  `json:"features,omitempty"`
	ActivatedAt *string `json:"activated_at"`
	ExpiresAt   *string `json:"expires_at"`
	CreatedAt   string  `json:"created_at"`
}

type LicenseInfo struct {
	Tier          string `json:"tier"`
	ExpiresAt     string `json:"expires_at"`
	Features      string `json:"features"`
	DaysRemaining int    `json:"days_remaining"`
}

func generateLicenseKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *MarketplaceHandler) ListProducts(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(h.db, h.provider, "SELECT id, name, description, price_cents, product_type, created_at FROM products ORDER BY created_at DESC")
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
		Tier      string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ProductID == "" {
		writeError(w, http.StatusBadRequest, "product_id is required")
		return
	}
	if req.Tier == "" {
		req.Tier = "starter"
	}

	var product Product
	err := db.QueryRow(h.db, h.provider, 
		"SELECT id, name, description, price_cents, product_type, created_at FROM products WHERE id = ?", req.ProductID,
	).Scan(&product.ID, &product.Name, &product.Description, &product.PriceCents, &product.ProductType, &product.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "product not found")
		return
	}

	validTiers := map[string]bool{"starter": true, "pro": true, "team": true, "lifetime": true}
	if !validTiers[req.Tier] {
		writeError(w, http.StatusBadRequest, "invalid tier, must be: starter, pro, team, or lifetime")
		return
	}

	id := uuid.New().String()
	licenseKey := generateLicenseKey()
	now := time.Now().UTC().Format(time.RFC3339)

	var expiresAt string
	switch req.Tier {
	case "lifetime":
		expiresAt = time.Now().UTC().Add(100 * 365 * 24 * time.Hour).Format(time.RFC3339)
	case "pro":
		expiresAt = time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	case "team":
		expiresAt = time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	default:
		expiresAt = time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	}

	features := map[string]any{"max_sessions": 50}
	if req.Tier == "pro" {
		features["max_sessions"] = 200
	} else if req.Tier == "team" {
		features["max_sessions"] = 1000
	} else if req.Tier == "lifetime" {
		features["max_sessions"] = -1
	}
	featuresJSON, _ := json.Marshal(features)

	_, err = db.Exec(h.db, h.provider, 
		"INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, claims.UserID, req.ProductID, licenseKey, req.Tier, string(featuresJSON), expiresAt, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create purchase")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"license_key": licenseKey,
		"tier":        req.Tier,
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
	err := db.QueryRow(h.db, h.provider, 
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
	_, err = db.Exec(h.db, h.provider, "UPDATE purchases SET activated_at = ? WHERE id = ?", now, purchaseID)
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

	rows, err := db.Query(h.db, h.provider, 
		"SELECT id, user_id, product_id, license_key, tier, COALESCE(features,'{}'), activated_at, expires_at, created_at FROM purchases WHERE user_id = ? ORDER BY created_at DESC",
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
		if err := rows.Scan(&p.ID, &p.UserID, &p.ProductID, &p.LicenseKey, &p.Tier, &p.Features, &p.ActivatedAt, &p.ExpiresAt, &p.CreatedAt); err != nil {
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
	_, err := db.Exec(h.db, h.provider, 
		"INSERT INTO products (id, name, description, price_cents, product_type) VALUES (?, ?, ?, ?, ?)",
		id, req.Name, req.Description, req.PriceCents, req.ProductType,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create product")
		return
	}

	var p Product
	err = db.QueryRow(h.db, h.provider, 
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

	result, err := db.Exec(h.db, h.provider, "DELETE FROM products WHERE id = ?", id)
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

func (h *MarketplaceHandler) RenewLicense(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.LicenseKey == "" {
		writeError(w, http.StatusBadRequest, "license_key is required")
		return
	}

	var purchaseID, userID, tier, expiresAt string
	err := db.QueryRow(h.db, h.provider, 
		"SELECT id, user_id, tier, COALESCE(expires_at, '') FROM purchases WHERE license_key = ?",
		req.LicenseKey,
	).Scan(&purchaseID, &userID, &tier, &expiresAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "license key not found")
		return
	}

	if userID != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "license key does not belong to this user")
		return
	}

	if tier == "lifetime" {
		writeError(w, http.StatusBadRequest, "lifetime licenses do not need renewal")
		return
	}

	baseTime := time.Now().UTC()
	if expiresAt != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil && t.After(baseTime) {
			baseTime = t
		}
	}

	duration := 365 * 24 * time.Hour
	if tier == "starter" {
		duration = 30 * 24 * time.Hour
	}
	newExpires := baseTime.Add(duration).Format(time.RFC3339)

	_, err = db.Exec(h.db, h.provider, "UPDATE purchases SET expires_at = ? WHERE id = ?", newExpires, purchaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to renew license")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":    "license renewed",
		"expires_at": newExpires,
	})
}

func (h *MarketplaceHandler) UpgradeLicense(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		NewTier    string `json:"new_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validTiers := map[string]bool{"starter": true, "pro": true, "team": true, "lifetime": true}
	if !validTiers[req.NewTier] {
		writeError(w, http.StatusBadRequest, "invalid tier, must be: starter, pro, team, or lifetime")
		return
	}

	var purchaseID, userID, currentTier string
	err := db.QueryRow(h.db, h.provider, 
		"SELECT id, user_id, tier FROM purchases WHERE license_key = ?",
		req.LicenseKey,
	).Scan(&purchaseID, &userID, &currentTier)
	if err != nil {
		writeError(w, http.StatusNotFound, "license key not found")
		return
	}

	if userID != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "license key does not belong to this user")
		return
	}

	tierOrder := map[string]int{"starter": 0, "pro": 1, "team": 2, "lifetime": 3}
	if tierOrder[req.NewTier] <= tierOrder[currentTier] {
		writeError(w, http.StatusBadRequest, "new tier must be higher than current tier")
		return
	}

	features := map[string]any{"max_sessions": 50}
	switch req.NewTier {
	case "pro":
		features["max_sessions"] = 200
	case "team":
		features["max_sessions"] = 1000
	case "lifetime":
		features["max_sessions"] = -1
	}
	featuresJSON, _ := json.Marshal(features)

	newExpires := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	if req.NewTier == "lifetime" {
		newExpires = time.Now().UTC().Add(100 * 365 * 24 * time.Hour).Format(time.RFC3339)
	}

	_, err = db.Exec(h.db, h.provider, 
		"UPDATE purchases SET tier = ?, features = ?, expires_at = ? WHERE id = ?",
		req.NewTier, string(featuresJSON), newExpires, purchaseID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to upgrade license")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":    "license upgraded",
		"tier":       req.NewTier,
		"expires_at": newExpires,
	})
}

func (h *MarketplaceHandler) LicenseStatus(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var licenseKey string
	if lk := r.URL.Query().Get("license_key"); lk != "" {
		licenseKey = lk
	}

	info := LicenseInfo{Tier: "none", ExpiresAt: "", Features: "{}", DaysRemaining: 0}

	if licenseKey != "" {
		var tier, expiresAt, features string
		err := db.QueryRow(h.db, h.provider, 
			"SELECT tier, COALESCE(expires_at, ''), COALESCE(features, '{}') FROM purchases WHERE license_key = ? AND user_id = ?",
			licenseKey, claims.UserID,
		).Scan(&tier, &expiresAt, &features)
		if err == nil {
			info.Tier = tier
			info.Features = features
			info.ExpiresAt = expiresAt
			if expiresAt != "" {
				if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
					info.DaysRemaining = int(time.Until(t).Hours() / 24)
					if info.DaysRemaining < 0 {
						info.DaysRemaining = 0
					}
				}
			}
			writeJSON(w, http.StatusOK, info)
			return
		}
	}

	if licenseKey == "" {
		rows, err := db.Query(h.db, h.provider, 
			"SELECT tier, COALESCE(expires_at, ''), COALESCE(features, '{}') FROM purchases WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
			claims.UserID,
		)
		if err == nil {
			defer rows.Close()
			if rows.Next() {
				rows.Scan(&info.Tier, &info.ExpiresAt, &info.Features)
				if info.ExpiresAt != "" {
					if t, err := time.Parse(time.RFC3339, info.ExpiresAt); err == nil {
						info.DaysRemaining = int(time.Until(t).Hours() / 24)
						if info.DaysRemaining < 0 {
							info.DaysRemaining = 0
						}
					}
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, info)
}

func (h *MarketplaceHandler) StartTrial(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var existing int
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM license_trials WHERE user_id = ?", claims.UserID).Scan(&existing)
	if existing > 0 {
		writeError(w, http.StatusBadRequest, "trial already used")
		return
	}

	ip := extractIP(r)
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM license_trials WHERE ip = ?", ip).Scan(&existing)
	if existing > 0 {
		var machineID string
		if q := r.URL.Query().Get("machine_id"); q != "" {
			machineID = q
		}
		if machineID != "" {
			db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM license_trials WHERE machine_id = ?", machineID).Scan(&existing)
			if existing > 0 {
				writeError(w, http.StatusBadRequest, "trial already used on this machine")
				return
			}
		}
	}

	id := uuid.New().String()
	trialExpiry := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	machineID := r.URL.Query().Get("machine_id")

	_, err := db.Exec(h.db, h.provider, 
		`INSERT INTO license_trials (id, user_id, ip, machine_id, tier, max_sessions, expires_at) VALUES (?, ?, ?, ?, 'starter', 50, ?)`,
		id, claims.UserID, ip, machineID, trialExpiry,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start trial")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message":      "trial started",
		"tier":         "starter",
		"max_sessions": "50",
		"expires_at":   trialExpiry,
	})
}

func LicenseMiddleware(d *sql.DB, provider db.ProviderType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			if claims.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			var hasLicense bool
			var expiresAt *string
			var licenseCount int
			var trialCount int
			err := db.QueryRow(d, provider,
				"SELECT COUNT(*), MAX(expires_at) FROM purchases WHERE user_id = ?",
				claims.UserID,
			).Scan(&licenseCount, &expiresAt)
			hasLicense = licenseCount > 0
			if err != nil {
				hasLicense = false
			}

			if !hasLicense {
				db.QueryRow(d, provider, "SELECT COUNT(*) FROM license_trials WHERE user_id = ?", claims.UserID).Scan(&trialCount)
				if trialCount == 0 {
					writeJSON(w, http.StatusPaymentRequired, map[string]string{
						"error": "no active license",
						"code":  "LICENSE_REQUIRED",
					})
					return
				}

				var trialExpiresAt string
				db.QueryRow(d, provider, "SELECT expires_at FROM license_trials WHERE user_id = ?", claims.UserID).Scan(&trialExpiresAt)

				if trialExpiresAt != "" {
					if t, err := time.Parse(time.RFC3339, trialExpiresAt); err == nil && time.Now().UTC().After(t) {
						writeJSON(w, http.StatusPaymentRequired, map[string]string{
							"error": "trial expired",
							"code":  "TRIAL_EXPIRED",
						})
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}

			if expiresAt != nil && *expiresAt != "" {
				if t, err := time.Parse(time.RFC3339, *expiresAt); err == nil && time.Now().UTC().After(t) {
					writeJSON(w, http.StatusPaymentRequired, map[string]string{
						"error": "license expired",
						"code":  "LICENSE_EXPIRED",
					})
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
