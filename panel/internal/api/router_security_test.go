package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/testutil"
)

func securityRouter(t *testing.T) (chi.Router, string, string) {
	t.Helper()
	d := testutil.OpenTestDB(t)
	adminID := createTestUserWithRole(t, d, "admin-user", "security-test-password", "admin")
	workerID := createTestUserWithRole(t, d, "worker-user", "security-test-password", "worker")
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "security-test-secret", "*", nil, nil, nil, nil)
	adminToken, _, err := auth.GenerateToken(adminID, "admin", "security-test-secret", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	workerToken, _, err := auth.GenerateToken(workerID, "worker", "security-test-secret", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return r, adminToken, workerToken
}

func securityRequest(t *testing.T, r chi.Router, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSecurity_NonAdminCannotReadSettingsOrManageTelegramBots(t *testing.T) {
	r, _, workerToken := securityRouter(t)
	requests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/settings", ""},
		{http.MethodGet, "/api/telegram/bots", ""},
		{http.MethodPost, "/api/telegram/bots", `{}`},
		{http.MethodPut, "/api/telegram/bots/id", `{}`},
		{http.MethodDelete, "/api/telegram/bots/id", ""},
		{http.MethodPost, "/api/telegram/bots/id/test", ""},
		{http.MethodGet, "/api/telegram/filters", ""},
		{http.MethodPost, "/api/telegram/filters", `{}`},
		{http.MethodDelete, "/api/telegram/filters/id", ""},
	}
	for _, tc := range requests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := securityRequest(t, r, workerToken, tc.method, tc.path, tc.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSecurity_AdminCanReachSettingsAndTelegramBotRoutes(t *testing.T) {
	r, adminToken, _ := securityRouter(t)
	requests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/settings", ""},
		{http.MethodGet, "/api/telegram/bots", ""},
		{http.MethodPost, "/api/telegram/bots", `{}`},
		{http.MethodPut, "/api/telegram/bots/id", `{}`},
		{http.MethodDelete, "/api/telegram/bots/id", ""},
		{http.MethodPost, "/api/telegram/bots/id/test", ""},
		{http.MethodGet, "/api/telegram/filters", ""},
		{http.MethodPost, "/api/telegram/filters", `{}`},
		{http.MethodDelete, "/api/telegram/filters/id", ""},
	}
	for _, tc := range requests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := securityRequest(t, r, adminToken, tc.method, tc.path, tc.body)
			if w.Code == http.StatusForbidden {
				t.Fatalf("admin route unexpectedly forbidden: %s", w.Body.String())
			}
		})
	}
}

func TestAuthMiddleware_RevokesTokenAfterVersionBump(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "revoked-user", "secret123")
	token, _, err := auth.GenerateToken(uid, "admin", "security-test-secret", "session-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE users SET token_version = 1 WHERE id = $1", uid); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(api.AuthMiddleware("security-test-secret", d))
	r.Get("/protected", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked token to be rejected, got %d", w.Code)
	}
}
