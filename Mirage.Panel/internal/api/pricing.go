package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/middleware"
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

type PricingHandler struct {
	db *sql.DB
}

func NewPricingHandler(db *sql.DB) *PricingHandler {
	return &PricingHandler{db: db}
}

func LoadTierFeatures(db *sql.DB, tier Tier) *TierFeatures {
	var raw string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", "pricing_"+string(tier)).Scan(&raw)
	if err != nil {
		return defaultFeatures(tier)
	}
	var f TierFeatures
	if json.Unmarshal([]byte(raw), &f) != nil {
		return defaultFeatures(tier)
	}
	return &f
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
		result[string(t)] = LoadTierFeatures(h.db, t)
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *PricingHandler) MyFeatures(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tier, features := resolveUserTier(h.db, claims)
	writeJSON(w, http.StatusOK, map[string]any{
		"tier":     tier,
		"features": features,
	})
}

func resolveUserTier(db *sql.DB, claims *auth.Claims) (Tier, *TierFeatures) {
	if claims.Role == "admin" {
		return TierTeam, LoadTierFeatures(db, TierTeam)
	}

	var tier string
	err := db.QueryRow(
		"SELECT tier FROM purchases WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
		claims.UserID,
	).Scan(&tier)
	if err != nil {
		var trialTier string
		err = db.QueryRow(
			"SELECT tier FROM license_trials WHERE user_id = ? AND expires_at > datetime('now') LIMIT 1",
			claims.UserID,
		).Scan(&trialTier)
		if err != nil {
			return TierStarter, LoadTierFeatures(db, TierStarter)
		}
		return Tier(trialTier), LoadTierFeatures(db, Tier(trialTier))
	}

	return Tier(tier), LoadTierFeatures(db, Tier(tier))
}

func CheckTierAccess(db *sql.DB, claims *auth.Claims, feature string) bool {
	_, features := resolveUserTier(db, claims)
	switch feature {
	case "smart_filters":
		return features.SmartFilters
	case "postgresql":
		return features.PostgreSQL
	case "clipper_module":
		return features.ClipperModule
	case "loader_module":
		return features.LoaderModule
	}
	return true
}

func CheckBotLimit(db *sql.DB, claims *auth.Claims) (int, int, error) {
	_, features := resolveUserTier(db, claims)

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE build_id IN (SELECT id FROM builds WHERE user_id = ?)", claims.UserID).Scan(&count)
	if err != nil {
		return 0, features.MaxBots, err
	}

	return count, features.MaxBots, nil
}

func CheckTierRateLimit(db *sql.DB, claims *auth.Claims) int {
	_, features := resolveUserTier(db, claims)
	if features.APILimited {
		return 30
	}
	return 100
}

type TierLimitMiddleware struct {
	db *sql.DB
}

func NewTierLimitMiddleware(db *sql.DB) *TierLimitMiddleware {
	return &TierLimitMiddleware{db: db}
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

		current, max, err := CheckBotLimit(m.db, claims)
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
