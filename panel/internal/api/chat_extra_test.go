package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestChat_Send_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewChatHandler(d, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/chat/send", bytes.NewReader([]byte(`{"message":"hi"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Send(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChat_Send_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewChatHandler(d, nil)

	uid := createTestUser(t, d, "chatbad", "pass")

	req := httptest.NewRequest(http.MethodPost, "/api/chat/send", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Send(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChat_Send_UserNotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewChatHandler(d, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/chat/send", bytes.NewReader([]byte(`{"message":"hi"}`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: "ghost-user", Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Send(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}
