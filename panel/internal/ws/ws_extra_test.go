package ws_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/ws"
)

// TestEvents_NewChatEvent verifies NewChatEvent emits a chat_message event
// with the full ChatMessage payload, including omitempty fields.
func TestEvents_NewChatEvent(t *testing.T) {
	payload := ws.ChatMessage{
		ID:          "chat-1",
		UserID:      "user-1",
		Username:    "alice",
		Message:     "hello",
		ParentID:    "chat-0",
		MessageType: "text",
		CreatedAt:   "2026-08-04T12:00:00Z",
	}
	data := ws.NewChatEvent(payload)

	var ev ws.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Type != "chat_message" {
		t.Errorf("type = %q, want %q", ev.Type, "chat_message")
	}

	b, _ := json.Marshal(ev.Data)
	var got ws.ChatMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got != payload {
		t.Errorf("payload = %+v, want %+v", got, payload)
	}

	// omitempty: empty ParentID must be absent from the wire
	noParent := ws.NewChatEvent(ws.ChatMessage{ID: "chat-2", Message: "hi"})
	if strings.Contains(string(noParent), "parent_id") {
		t.Errorf("empty ParentID should be omitted, got %s", noParent)
	}
}

// TestServeWs_DisallowedOrigin verifies a 403 is returned when the Origin
// header is not in the allowed list.
func TestServeWs_DisallowedOrigin(t *testing.T) {
	hub := ws.NewHub()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "http://allowed.example"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	token, _, err := auth.GenerateToken("user-a", "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Send a raw websocket upgrade request; the server's CheckOrigin must
	// reject it with 403 before any upgrade happens.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/ws?token="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for disallowed origin, got %d", resp.StatusCode)
	}
}

// TestServeWs_MissingOrigin verifies a missing Origin header is rejected.
func TestServeWs_MissingOrigin(t *testing.T) {
	hub := ws.NewHub()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "http://allowed.example"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	token, _, err := auth.GenerateToken("user-a", "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + token
	_, _, err = testDialer.Dial(url, nil)
	if err == nil {
		t.Fatal("expected handshake failure for missing origin")
	}
}

// TestServeWs_AllowedOrigin verifies an Origin inside the allow list upgrades
// successfully and receives broadcasts.
func TestServeWs_AllowedOrigin(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "http://allowed.example"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	token, _, err := auth.GenerateToken("user-a", "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + token
	conn, _, err := testDialer.Dial(url, http.Header{"Origin": {"http://allowed.example"}})
	if err != nil {
		t.Fatalf("dial with allowed origin: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	hub.Broadcast("chat:user-a", []byte(`{"type":"test","data":"origin-ok"}`))
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != `{"type":"test","data":"origin-ok"}` {
		t.Errorf("allowed-origin client should receive broadcast, got %q ok=%v", got, ok)
	}
}

// TestServeWs_NotWebSocket verifies the upgrade-failure branch: a plain HTTP
// GET (no websocket handshake headers) must not crash and must not hijack.
func TestServeWs_NotWebSocket(t *testing.T) {
	hub := ws.NewHub()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "*"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	token, _, err := auth.GenerateToken("user-1", "admin", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/ws?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// gorilla Upgrader returns 400 on a non-websocket request.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for non-websocket request, got %d", resp.StatusCode)
	}
}

// TestServeWs_SubprotocolTokenDial verifies the end-to-end handshake succeeds
// when the token is carried in Sec-WebSocket-Protocol instead of the query
// string.
func TestServeWs_SubprotocolTokenDial(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := testDialer.Dial(url, http.Header{
		"Origin":                {"http://test"},
		"Sec-WebSocket-Protocol": {"jwt-" + token},
	})
	if err != nil {
		t.Fatalf("dial with subprotocol token: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	hub.Broadcast("chat:user-1", []byte(`{"type":"test","data":"proto-ok"}`))
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != `{"type":"test","data":"proto-ok"}` {
		t.Errorf("subprotocol-token client should receive broadcast, got %q ok=%v", got, ok)
	}
}

// TestServeWs_AuthorizationTokenDial verifies the handshake succeeds when the
// token is carried in the Authorization: Bearer header.
func TestServeWs_AuthorizationTokenDial(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := testDialer.Dial(url, http.Header{
		"Origin":        {"http://test"},
		"Authorization": {"Bearer " + token},
	})
	if err != nil {
		t.Fatalf("dial with Authorization token: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	hub.Broadcast("chat:user-1", []byte(`{"type":"test","data":"auth-ok"}`))
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != `{"type":"test","data":"auth-ok"}` {
		t.Errorf("Authorization-token client should receive broadcast, got %q ok=%v", got, ok)
	}
}

// TestClient_WriteReadRoundTrip exercises the readPump and writePump happy
// paths end to end: the server broadcasts to a channel the client subscribed
// to, the client reads it, then closes and the server tears down cleanly.
func TestClient_WriteReadRoundTrip(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	conn := connectWS(t, srv, token)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// writePump: TextMessage path
	msg := []byte(`{"type":"chat_message","data":"round-trip"}`)
	hub.Broadcast("chat:user-1", msg)
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != string(msg) {
		t.Fatalf("round-trip message mismatch, got %q ok=%v", got, ok)
	}

	// client closes: readPump hits the ReadMessage error branch and
	// unregisters the client; the hub removes it from its channel.
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	hub.Broadcast("chat:user-1", []byte("after-close"))
	// If the client were still registered, sending to a dead conn would
	// block writePump — this broadcast must return without hanging, and a
	// later client on the same channel must still receive messages.
	conn2 := connectWS(t, srv, token)
	defer conn2.Close()
	time.Sleep(50 * time.Millisecond)
	hub.Broadcast("chat:user-1", []byte("second-client"))
	if got, ok := readWithTimeout(t, conn2); !ok || string(got) != "second-client" {
		t.Errorf("second client should receive broadcast, got %q ok=%v", got, ok)
	}
}

