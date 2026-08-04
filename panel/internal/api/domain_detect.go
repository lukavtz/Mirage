package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/db"
)

type DomainDetectHandler struct {
	d        *sql.DB
	provider db.ProviderType
}

func NewDomainDetectHandler(d *sql.DB, provider db.ProviderType) *DomainDetectHandler {
	return &DomainDetectHandler{d: d, provider: provider}
}
func (h *DomainDetectHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(h.d, h.provider, "SELECT id, domain, tag, color, created_at FROM domain_detect ORDER BY domain")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query domain detections")
		return
	}
	defer rows.Close()

	items := make([]db.DomainDetect, 0)
	for rows.Next() {
		var item db.DomainDetect
		if rows.Scan(&item.ID, &item.Domain, &item.Tag, &item.Color, &item.CreatedAt) == nil {
			items = append(items, item)
		}
	}

	writeJSON(w, http.StatusOK, items)
}

func (h *DomainDetectHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Tag    string `json:"tag"`
		Color  string `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	req.Tag = strings.TrimSpace(req.Tag)
	if req.Domain == "" || req.Tag == "" {
		writeError(w, http.StatusBadRequest, "domain and tag required")
		return
	}
	if req.Color == "" {
		req.Color = "#5865F2"
	}

	id := uuid.New().String()
	_, err := db.Exec(h.d, h.provider, 
		"INSERT INTO domain_detect (id, domain, tag, color) VALUES (?, ?, ?, ?)",
		id, req.Domain, req.Tag, req.Color,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create domain detection")
		return
	}

	var item db.DomainDetect
	db.QueryRow(h.d, h.provider, 
		"SELECT id, domain, tag, color, created_at FROM domain_detect WHERE id = ?", id,
	).Scan(&item.ID, &item.Domain, &item.Tag, &item.Color, &item.CreatedAt)

	writeJSON(w, http.StatusCreated, item)
}

func (h *DomainDetectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := db.Exec(h.d, h.provider, "DELETE FROM domain_detect WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (h *DomainDetectHandler) AutoTag(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	// tenant guard: workers may only auto-tag their own sessions (admins bypass)
	if !sessionOwnedBy(h.d, r, sessionID) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	rules, err := db.Query(h.d, h.provider, "SELECT id, domain, tag, color FROM domain_detect")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query rules")
		return
	}
	defer rules.Close()

	type rule struct {
		id     string
		domain string
		tag    string
		color  string
	}
	var ruleList []rule
	for rules.Next() {
		var r rule
		if rules.Scan(&r.id, &r.domain, &r.tag, &r.color) == nil {
			ruleList = append(ruleList, r)
		}
	}

	passwords, err := db.Query(h.d, h.provider, 
		"SELECT url FROM passwords WHERE session_id = ?", sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query passwords")
		return
	}
	defer passwords.Close()

	tagged := make(map[string]string)
	for passwords.Next() {
		var pwdURL string
		if passwords.Scan(&pwdURL) != nil {
			continue
		}
		parsed, err := url.Parse(pwdURL)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if host == "" {
			continue
		}
		for _, r := range ruleList {
			if strings.Contains(host, r.domain) || strings.HasSuffix(host, "."+r.domain) {
				tagged[r.tag] = r.color
			}
		}
	}

	for tag, color := range tagged {
		tagID := uuid.New().String()
		// session_tags unique key is (session_id, tag) per migration 015.
		// PG has no INSERT OR IGNORE; ON CONFLICT (session_id, tag) DO NOTHING
		// is the dialect-correct equivalent.
		q := db.Placeholders(h.provider,
			"INSERT INTO session_tags (id, session_id, tag, color) VALUES (?, ?, ?, ?) ON CONFLICT (session_id, tag) DO NOTHING")
		db.Exec(h.d, h.provider, q, tagID, sessionID, tag, color)
	}

	var result []db.SessionTag
	rows, err := db.Query(h.d, h.provider, 
		"SELECT id, session_id, tag, color, created_at FROM session_tags WHERE session_id = ? ORDER BY created_at",
		sessionID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var st db.SessionTag
			if rows.Scan(&st.ID, &st.SessionID, &st.Tag, &st.Color, &st.CreatedAt) == nil {
				result = append(result, st)
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}
