package ws_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/google/uuid"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/testutil"
	"zialfi-panel/internal/ws"
)

func createWSUser(t *testing.T, d *sql.DB, username string) string {
	t.Helper()
	id := uuid.New().String()
	hash, err := auth.HashPassword("ws-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, 'worker')",
		id, username, hash); err != nil {
		t.Fatal(err)
	}
	return id
}

func wsServer(t *testing.T, d *sql.DB, hub *ws.Hub) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, d, jwtSecret, "*"))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}
func dialWS(t *testing.T, srv *httptest.Server, token string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + token
	return testDialer.Dial(url, testHeader())
}

func dialErr(t *testing.T, srv *httptest.Server, token string) (int, string) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + token
	_, resp, err := testDialer.Dial(url, testHeader())
	if err == nil {
		t.Fatalf("expected rejected handshake, got connection")
	}
	if resp == nil {
		t.Fatalf("handshake error without response: %v", err)
	}
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	return resp.StatusCode, string(body[:n])
}

func TestServeWs_TokenVersionMatch(t *testing.T) {
	d := testutil.OpenTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	srv := wsServer(t, d, hub)

	userID := createWSUser(t, d, "ws-version-ok")
	token, _, err := auth.GenerateToken(userID, "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, resp, err := dialWS(t, srv, token)
	if err != nil || conn == nil {
		t.Fatalf("valid token + matching version rejected: %v", err)
	}
	defer conn.Close()
	if resp != nil {
		resp.Body.Close()
	}
}

func TestServeWs_RevokedTokenVersion(t *testing.T) {
	d := testutil.OpenTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	srv := wsServer(t, d, hub)

	userID := createWSUser(t, d, "ws-revoked")
	if _, err := d.Exec("UPDATE users SET token_version = 2 WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	// Valid signature, but the DB version (2) is ahead of the claims (0).
	token, _, err := auth.GenerateToken(userID, "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	code, body := dialErr(t, srv, token)
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked token: status = %d, want 401", code)
	}
	if !strings.Contains(body, "revoked") {
		t.Fatalf("revoked token: body = %q, want revoked message", body)
	}
}

func TestServeWs_MissingTokenStill401(t *testing.T) {
	d := testutil.OpenTestDB(t)
	hub := ws.NewHub()
	srv := wsServer(t, d, hub)

	code, body := dialErr(t, srv, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("missing token: status = %d, want 401", code)
	}
	if !strings.Contains(body, "missing") {
		t.Fatalf("missing token: body = %q", body)
	}
}

func TestServeWs_UnknownUser401(t *testing.T) {
	d := testutil.OpenTestDB(t)
	hub := ws.NewHub()
	srv := wsServer(t, d, hub)

	token, _, err := auth.GenerateToken("ghost-user", "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := dialErr(t, srv, token)
	if code != http.StatusUnauthorized {
		t.Fatalf("unknown user: status = %d, want 401", code)
	}
}

func TestServeWs_RevokedWhileConnected(t *testing.T) {
	d := testutil.OpenTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	srv := wsServer(t, d, hub)

	userID := createWSUser(t, d, "ws-live-revoked")
	token, _, err := auth.GenerateToken(userID, "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, resp, err := dialWS(t, srv, token)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if resp != nil {
		resp.Body.Close()
	}

	// Revoke: bump the DB version out from under the live socket.
	if _, err := d.Exec("UPDATE users SET token_version = 3 WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}

	// Shrink the revalidation interval so the tick fires promptly.
	ws.SetRevalidateInterval(100 * time.Millisecond)
	defer ws.SetRevalidateInterval(5 * time.Minute)

	// The socket must be closed by the periodic revalidation.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := conn.ReadMessage(); err != nil {
			return // closed = revoked picked up
		}
	}
	t.Fatal("live socket was not closed within deadline after revocation")
}
