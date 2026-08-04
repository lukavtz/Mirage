package services

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// mockBroadcaster records every Broadcast call for assertion.
type mockBroadcaster struct {
	mu      sync.Mutex
	entries []broadcastEntry
}

type broadcastEntry struct {
	channel string
	data    []byte
}

func (m *mockBroadcaster) Broadcast(channel string, message []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, broadcastEntry{channel: channel, data: append([]byte(nil), message...)})
}

func (m *mockBroadcaster) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *mockBroadcaster) last() (string, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) == 0 {
		return "", nil, false
	}
	e := m.entries[len(m.entries)-1]
	return e.channel, e.data, true
}

// jsonMarshalEnvelope mirrors PGNotifier.Broadcast's payload encoding.
func jsonMarshalEnvelope(channel string, data []byte) (string, error) {
	b, err := json.Marshal(struct {
		Channel string `json:"channel"`
		Data    []byte `json:"data"`
	}{Channel: channel, Data: data})
	return string(b), err
}

func unmarshalEnvelope(payload string, out any) error {
	return json.Unmarshal([]byte(payload), out)
}

// TestPGNotifier_LiveRoundTrip verifies NOTIFY → LISTEN → hub forwarding
// against a real PostgreSQL. Skipped unless DATABASE_URL is set, e.g.:
//
//	docker run -d --name pg-mirage-test -p 5432:5432 \
//	  -e POSTGRES_USER=mirage -e POSTGRES_PASSWORD=test -e POSTGRES_DB=mirage \
//	  postgres:16-alpine
//	DATABASE_URL='postgres://mirage:test@localhost:5432/mirage?sslmode=disable' \
//	  go test ./internal/services/ -run TestPGNotifier -count=1 -v
func TestPGNotifier_LiveRoundTrip(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping live PG notifier test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

	mock := &mockBroadcaster{}
	notifier, err := NewPGNotifier(ctx, dsn, mock)
	if err != nil {
		t.Fatalf("NewPGNotifier: %v", err)
	}
	defer func() {
		cancel() // stop Listen first (graceful exit), then close the conn
		notifier.Close(ctx)
	}()

	go func() {
		if err := notifier.Listen(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("Listen: %v", err)
		}
	}()

	// Give LISTEN a moment to register before we publish.
	time.Sleep(500 * time.Millisecond)

	// A second connection publishes on behalf of a remote panel worker.
	pub, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect(publisher): %v", err)
	}
	defer pub.Close(ctx)

	// Publish the same envelope PGNotifier.Broadcast would send.
	wantData := []byte(`{"id":"test-session","country_code":"RU","passwords_count":3}`)
	payload, err := jsonMarshalEnvelope("sessions:all", wantData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Exec(ctx, "SELECT pg_notify('sessions_new', $1)", payload); err != nil {
		t.Fatalf("pg_notify: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ch, data, ok := mock.last()
		if ok && ch == "sessions:all" {
			if string(data) != string(wantData) {
				t.Fatalf("payload mismatch: got %s want %s", data, wantData)
			}
			return // success
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for forwarded broadcast; got %d entries", mock.count())
}

// TestPGNotifier_BroadcastEnvelope checks the envelope shape Broadcast
// produces, without a live DB: a round-trip through the JSON payload
// must preserve channel and data verbatim.
func TestPGNotifier_BroadcastEnvelope(t *testing.T) {
	payload, err := jsonMarshalEnvelope("sessions:test-owner", []byte(`{"id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Channel string `json:"channel"`
		Data    []byte `json:"data"`
	}
	if err := unmarshalEnvelope(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Channel != "sessions:test-owner" {
		t.Fatalf("channel = %q, want sessions:test-owner", got.Channel)
	}
	if string(got.Data) != `{"id":"x"}` {
		t.Fatalf("data = %q, want {\"id\":\"x\"}", got.Data)
	}
}
