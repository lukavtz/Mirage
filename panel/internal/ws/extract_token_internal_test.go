package ws

import (
	"net/http"
	"testing"
)

// TestExtractToken_Priority verifies token sources are tried in order:
// query param beats subprotocol beats Authorization header.
func TestExtractToken_Priority(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example/ws?token=query-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-WebSocket-Protocol", "jwt-proto-token")
	req.Header.Set("Authorization", "Bearer auth-token")

	if got := extractToken(req); got != "query-token" {
		t.Errorf("query param should win, got %q", got)
	}
}

// TestExtractToken_Subprotocol verifies the jwt- prefixed subprotocol entry
// is picked out of a comma-separated Sec-WebSocket-Protocol list.
func TestExtractToken_Subprotocol(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-WebSocket-Protocol", "graphql-ws, jwt-subproto-token")

	if got := extractToken(req); got != "subproto-token" {
		t.Errorf("got %q, want %q", got, "subproto-token")
	}
}

// TestExtractToken_Authorization verifies the Bearer token is extracted from
// the Authorization header when no query or subprotocol token is present.
func TestExtractToken_Authorization(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer auth-token")

	if got := extractToken(req); got != "auth-token" {
		t.Errorf("got %q, want %q", got, "auth-token")
	}
}

// TestExtractToken_None verifies an empty string is returned when no token
// source is present.
func TestExtractToken_None(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := extractToken(req); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
