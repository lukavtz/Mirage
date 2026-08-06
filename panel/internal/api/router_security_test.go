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
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "security-test-secret", "*", nil, nil, nil, nil)
	adminToken, _, err := auth.GenerateToken("admin-user", "admin", "security-test-secret", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	workerToken, _, err := auth.GenerateToken("worker-user", "worker", "security-test-secret", "", 0)
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
