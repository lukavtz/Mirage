package ws_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/ws"
)

const jwtSecret = "test-secret-12345"

var testDialer = &websocket.Dialer{
	HandshakeTimeout: 45 * time.Second,
}

func testHeader() http.Header {
	return http.Header{"Origin": {"http://test"}}
}

func setupTestServer(t *testing.T, hub *ws.Hub) (*httptest.Server, string) {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "*"))
	srv := httptest.NewServer(r)
	token, _, err := auth.GenerateToken("user-1", "admin", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return srv, token
}

func connectWS(t *testing.T, srv *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + token
	conn, _, err := testDialer.Dial(url, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestHub_NewHub(t *testing.T) {
	hub := ws.NewHub()
	if hub == nil {
		t.Fatal("NewHub() returned nil")
	}
}

func TestHub_RunAndBroadcast(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	conn1 := connectWS(t, srv, token)
	defer conn1.Close()
	conn2 := connectWS(t, srv, token)
	defer conn2.Close()

	// give time for registration
	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"test","data":"hello"}`)
	hub.Broadcast("chat:all", msg)

	var received sync.WaitGroup
	received.Add(2)

	go func() {
		defer received.Done()
		_, got, err := conn1.ReadMessage()
		if err != nil {
			t.Errorf("conn1 read error: %v", err)
			return
		}
		if string(got) != string(msg) {
			t.Errorf("conn1 got %q, want %q", got, msg)
		}
	}()

	go func() {
		defer received.Done()
		_, got, err := conn2.ReadMessage()
		if err != nil {
			t.Errorf("conn2 read error: %v", err)
			return
		}
		if string(got) != string(msg) {
			t.Errorf("conn2 got %q, want %q", got, msg)
		}
	}()

	received.Wait()
}

func TestHub_RegisterUnregister(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	conn := connectWS(t, srv, token)

	time.Sleep(50 * time.Millisecond)

	hub.Broadcast("chat:all", []byte("ping"))
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("client should receive broadcast before disconnect: %v", err)
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	hub.Broadcast("chat:all", []byte("after-close"))
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Error("expected error reading from closed connection")
	}
}

func TestHub_BroadcastSkipsSlowClient(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	conn := connectWS(t, srv, token)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// flood the send buffer so subsequent sends are dropped
	for i := 0; i < 65; i++ {
		hub.Broadcast("chat:all", []byte("flood"))
	}

	// broadcast should not block even though client is slow
	done := make(chan struct{})
	go func() {
		hub.Broadcast("chat:all", []byte("should-not-block"))
		close(done)
	}()

	select {
	case <-done:
		// ok — did not block
	case <-time.After(2 * time.Second):
		t.Fatal("broadcast blocked on slow client")
	}
}

func TestHub_SlowClientEvictionClosesConnection(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()
	conn := connectWS(t, srv, token)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 66; i++ {
		hub.Broadcast("chat:all", []byte("flood"))
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

func TestHub_ConcurrentBroadcast(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	var clients []*websocket.Conn
	for i := 0; i < 5; i++ {
		c := connectWS(t, srv, token)
		defer c.Close()
		clients = append(clients, c)
	}

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hub.Broadcast("chat:all", []byte(`{"type":"concurrent","seq":`+strconv.Itoa(n)+`}`))
		}(i)
	}
	wg.Wait()

	// drain all messages so we can tell nothing panicked
	for _, c := range clients {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				break
			}
		}
	}
}

func TestServeWs_NoToken(t *testing.T) {
	hub := ws.NewHub()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "*"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	_, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestServeWs_InvalidToken(t *testing.T) {
	hub := ws.NewHub()
	r := chi.NewRouter()
	r.Get("/ws", ws.ServeWs(hub, jwtSecret, "*"))
	srv := httptest.NewServer(r)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=badtoken"
	_, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestServeWs_ValidToken(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, token := setupTestServer(t, hub)
	defer srv.Close()

	conn := connectWS(t, srv, token)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"test","data":"hello"}`)
	hub.Broadcast("chat:all", msg)

	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("should receive broadcast: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestEvents_StatsEvent(t *testing.T) {
	payload := ws.StatsPayload{SessionsTotal: 10, SessionsToday: 3, PasswordsTotal: 100}
	data := ws.NewStatsEvent(payload)

	var ev ws.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "stats_update" {
		t.Errorf("type = %q, want %q", ev.Type, "stats_update")
	}

	b, _ := json.Marshal(ev.Data)
	var got ws.StatsPayload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.SessionsTotal != 10 || got.SessionsToday != 3 || got.PasswordsTotal != 100 {
		t.Errorf("unexpected payload: %+v", got)
	}
}

func TestEvents_NewSessionEvent(t *testing.T) {
	payload := ws.NewSessionPayload{ID: "abc123", CountryCode: "US", PasswordsCount: 5}
	data := ws.NewSessionEvent(payload)

	var ev ws.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != "new_session" {
		t.Errorf("type = %q, want %q", ev.Type, "new_session")
	}

	b, _ := json.Marshal(ev.Data)
	var got ws.NewSessionPayload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "abc123" || got.CountryCode != "US" || got.PasswordsCount != 5 {
		t.Errorf("unexpected payload: %+v", got)
	}
}

// readWithTimeout reads one WS message, failing the test on timeout.
func readWithTimeout(t *testing.T, conn *websocket.Conn) ([]byte, bool) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, got, err := conn.ReadMessage()
	if err != nil {
		return nil, false
	}
	return got, true
}

// TestServeWs_WorkerSubscribesPerUser verifies a non-admin client is subscribed
// only to its own per-user channels, not to other users' or the global ones.
func TestServeWs_WorkerSubscribesPerUser(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, _ := setupTestServer(t, hub)
	defer srv.Close()

	workerToken, _, err := auth.GenerateToken("user-a", "worker", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	conn := connectWS(t, srv, workerToken)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// own channel: delivered
	hub.Broadcast("sessions:user-a", []byte(`{"type":"new_session","id":"own"}`))
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != `{"type":"new_session","id":"own"}` {
		t.Errorf("worker should receive own-channel session event, got %q ok=%v", got, ok)
	}

	// other tenant's channel: must NOT be delivered
	hub.Broadcast("sessions:user-b", []byte(`{"type":"new_session","id":"other"}`))
	if got, ok := readWithTimeout(t, conn); ok {
		t.Errorf("worker must not receive another tenant's session event, got %q", got)
	}

	// global all-sessions channel: worker is not admin, must NOT receive
	hub.Broadcast("sessions:all", []byte(`{"type":"new_session","id":"global"}`))
	if got, ok := readWithTimeout(t, conn); ok {
		t.Errorf("worker must not receive sessions:all event, got %q", got)
	}
}

// TestServeWs_AdminGetsAllSessions verifies an admin client receives the
// global sessions channel but not per-tenant channels.
func TestServeWs_AdminGetsAllSessions(t *testing.T) {
	hub := ws.NewHub()
	go hub.Run()

	srv, adminToken := setupTestServer(t, hub)
	defer srv.Close()

	conn := connectWS(t, srv, adminToken)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// global channel: delivered
	hub.Broadcast("sessions:all", []byte(`{"type":"new_session","id":"global"}`))
	if got, ok := readWithTimeout(t, conn); !ok || string(got) != `{"type":"new_session","id":"global"}` {
		t.Errorf("admin should receive sessions:all event, got %q ok=%v", got, ok)
	}

	// per-tenant channel: must NOT be delivered to admin
	hub.Broadcast("sessions:user-a", []byte(`{"type":"new_session","id":"tenant"}`))
	if got, ok := readWithTimeout(t, conn); ok {
		t.Errorf("admin must not receive per-tenant session event, got %q", got)
	}
}
