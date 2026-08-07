package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Broadcaster fans out a session event to the panel's live viewers.
// *ws.Hub satisfies this interface directly (in-process fan-out);
// PGNotifier is the PostgreSQL-backed implementation (NOTIFY + LISTEN
// goroutine forwarding into the hub), which lets multiple panel workers
// stay in sync without a shared in-process broadcast bus.
type Broadcaster interface {
	Broadcast(channel string, message []byte)
}

// PGNotifier publishes session events to the "sessions_new" PostgreSQL
// channel and runs a LISTEN goroutine that forwards notifications into
// the local hub. Use it instead of the bare *ws.Hub when provider is
// ProviderPostgres so every panel instance sees every session event.
type PGNotifier struct {
	listenConn   *pgx.Conn
	publishConn  *pgx.Conn
	hub          Broadcaster
	mu           sync.Mutex
	listenDone   chan struct{}
	listenCancel context.CancelFunc
	listening    bool
	closed       bool
}

// NewPGNotifier opens a dedicated PostgreSQL connection for LISTEN and
// wraps the local hub. The caller owns the returned notifier: it must
// call Listen (in a goroutine) and Close when done.
func NewPGNotifier(ctx context.Context, dsn string, hub Broadcaster) (*PGNotifier, error) {
	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	publishConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		listenConn.Close(ctx)
		return nil, err
	}
	return &PGNotifier{listenConn: listenConn, publishConn: publishConn, hub: hub, listenDone: make(chan struct{})}, nil
}

// Broadcast sends the event to PostgreSQL via NOTIFY sessions_new.
// The payload is a tiny JSON envelope {channel, data} so the LISTEN
// side knows which hub channel to forward to. Best-effort: a failed
// NOTIFY must not fail the log ingest that triggered it.
func (n *PGNotifier) Broadcast(channel string, message []byte) {
	payload, err := json.Marshal(struct {
		Channel string `json:"channel"`
		Data    []byte `json:"data"`
	}{Channel: channel, Data: message})
	if err != nil {
		slog.Warn("pg notifier: marshal payload", "err", err)
		return
	}
	if _, err := n.publishConn.Exec(context.Background(), "NOTIFY sessions_new, $1", string(payload)); err != nil {
		// ponytail: broadcast is best-effort; a dropped notification is
		// acceptable when the DB is briefly unreachable — the dashboard
		// still polls, and LISTEN reconnects on the next event.
		slog.Warn("pg notifier: NOTIFY failed", "err", err)
	}
}

// Listen blocks until ctx is cancelled, forwarding every session event
// published by any panel instance into the local hub. Returns the first
// error (e.g. connection loss); the caller may retry with backoff.
func (n *PGNotifier) Listen(ctx context.Context) error {
	listenCtx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	if n.closed || n.listening {
		n.mu.Unlock()
		cancel()
		return context.Canceled
	}
	n.listening = true
	n.listenCancel = cancel
	done := n.listenDone
	n.mu.Unlock()
	defer func() {
		cancel()
		n.mu.Lock()
		n.listening = false
		n.listenCancel = nil
		close(done)
		n.mu.Unlock()
	}()

	if _, err := n.listenConn.Exec(listenCtx, "LISTEN sessions_new"); err != nil {
		return err
	}
	for {
		notif, err := n.listenConn.WaitForNotification(listenCtx)
		if err != nil {
			if listenCtx.Err() != nil {
				return nil
			}
			return err
		}
		var msg struct {
			Channel string `json:"channel"`
			Data    []byte `json:"data"`
		}
		if err := json.Unmarshal([]byte(notif.Payload), &msg); err != nil {
			slog.Warn("pg notifier: bad payload", "err", err)
			continue
		}
		n.hub.Broadcast(msg.Channel, msg.Data)
	}
}

// Close releases the LISTEN connection.
func (n *PGNotifier) Close(ctx context.Context) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	cancel := n.listenCancel
	listening := n.listening
	done := n.listenDone
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listening {
		<-done
	}
	if err := n.listenConn.Close(ctx); err != nil {
		return err
	}
	return n.publishConn.Close(ctx)
}
