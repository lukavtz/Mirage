package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

type Tier string

const (
	TierStarter  Tier = "starter"
	TierPro      Tier = "pro"
	TierTeam     Tier = "team"
	TierLifetime Tier = "lifetime"
)

type TierFeatures struct {
	MaxBots       int  `json:"max_bots"`
	MaxUsers      int  `json:"max_users"`
	SmartFilters  bool `json:"smart_filters"`
	APILimited    bool `json:"api_limited"`
	PostgreSQL    bool `json:"postgresql"`
	ClipperModule bool `json:"clipper_module"`
	LoaderModule  bool `json:"loader_module"`
	PriceMonthly  int  `json:"price_monthly"`
	PriceLifetime int  `json:"price_lifetime"`
}

func LoadTierFeatures(d *sql.DB, provider db.ProviderType, tier Tier) *TierFeatures {
	var raw string
	err := db.QueryRow(d, provider, "SELECT value FROM settings WHERE key = ?", "pricing_"+string(tier)).Scan(&raw)
	if err != nil {
		return defaultFeatures(tier)
	}
	var f TierFeatures
	if json.Unmarshal([]byte(raw), &f) != nil {
		return defaultFeatures(tier)
	}
	return &f
}

type PricingHandler struct {
	db       *sql.DB
	provider db.ProviderType
}

func NewPricingHandler(dbConn *sql.DB, provider db.ProviderType) *PricingHandler {
	return &PricingHandler{db: dbConn, provider: provider}
}

func defaultFeatures(tier Tier) *TierFeatures {
	switch tier {
	case TierStarter:
		return &TierFeatures{MaxBots: 1, MaxUsers: 1, PriceMonthly: 7000, PriceLifetime: 70000}
	case TierPro:
		return &TierFeatures{MaxBots: 7, MaxUsers: 5, SmartFilters: true, APILimited: true, ClipperModule: true, LoaderModule: true, PriceMonthly: 15000, PriceLifetime: 150000}
	case TierTeam:
		return &TierFeatures{MaxBots: 15, MaxUsers: 20, SmartFilters: true, PostgreSQL: true, ClipperModule: true, LoaderModule: true, PriceMonthly: 35000, PriceLifetime: 350000}
	case TierLifetime:
		return &TierFeatures{MaxBots: 15, MaxUsers: 20, SmartFilters: true, PostgreSQL: true, ClipperModule: true, LoaderModule: true, PriceLifetime: 350000}
	}
	return &TierFeatures{}
}

func (h *PricingHandler) ListTiers(w http.ResponseWriter, r *http.Request) {
	tiers := []Tier{TierStarter, TierPro, TierTeam, TierLifetime}
	result := make(map[string]*TierFeatures)
	for _, t := range tiers {
		result[string(t)] = LoadTierFeatures(h.db, h.provider, t)
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *PricingHandler) MyFeatures(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tier, features := resolveUserTier(h.db, h.provider, claims)
	writeJSON(w, http.StatusOK, map[string]any{
		"tier":     tier,
		"features": features,
	})
}

func resolveUserTier(dbConn *sql.DB, provider db.ProviderType, claims *auth.Claims) (Tier, *TierFeatures) {
	if claims.Role == "admin" {
		return TierTeam, LoadTierFeatures(dbConn, provider, TierTeam)
	}

	var tier string
	trialQuery := db.Placeholders(provider, "SELECT tier FROM purchases WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
	err := dbConn.QueryRow(trialQuery, claims.UserID).Scan(&tier)
	if err != nil {
		var trialTier string
		trialQuery := db.Placeholders(provider,
			"SELECT tier FROM license_trials WHERE user_id = ? AND expires_at > "+db.Now(provider)+" LIMIT 1")
		err = dbConn.QueryRow(trialQuery, claims.UserID).Scan(&trialTier)
		if err != nil {
			return TierStarter, LoadTierFeatures(dbConn, provider, TierStarter)
		}
		return Tier(trialTier), LoadTierFeatures(dbConn, provider, Tier(trialTier))
	}

	return Tier(tier), LoadTierFeatures(dbConn, provider, Tier(tier))
}

func CheckTierAccess(db *sql.DB, provider db.ProviderType, claims *auth.Claims, feature string) bool {
	_, _ = resolveUserTier(db, provider, claims)
	return true
}

func CheckBotLimit(dbConn *sql.DB, provider db.ProviderType, claims *auth.Claims) (int, int, error) {
	_, features := resolveUserTier(dbConn, provider, claims)

	var count int
	err := db.QueryRow(dbConn, provider, "SELECT COUNT(*) FROM sessions WHERE build_id IN (SELECT id FROM builds WHERE user_id = ?)", claims.UserID).Scan(&count)
	if err != nil {
		return 0, features.MaxBots, err
	}

	return count, features.MaxBots, nil
}

func CheckTierRateLimit(dbConn *sql.DB, provider db.ProviderType, claims *auth.Claims) int {
	_, features := resolveUserTier(dbConn, provider, claims)
	if features.APILimited {
		return 30
	}
	return 100
}

type TierLimitMiddleware struct {
	db       *sql.DB
	provider db.ProviderType
}
func NewTierLimitMiddleware(db *sql.DB, provider db.ProviderType) *TierLimitMiddleware {
	return &TierLimitMiddleware{db: db, provider: provider}
}

func (m *TierLimitMiddleware) CheckBots(next http.Handler) http.Handler {
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

		current, max, err := CheckBotLimit(m.db, m.provider, claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to check bot limit")
			return
		}
		if current >= max {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":  "bot limit reached for your tier",
				"code":   "TIER_BOT_LIMIT",
				"limit":  max,
				"active": current,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
