package services_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/services"
)

const testBotToken = "test:token"

func newTestBot(t *testing.T) *services.SupportBot {
	t.Helper()
	// Use httptest server so tests don't hit real Telegram API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)

	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.SetAPIBase(ts.URL)
	return bot
}

func TestSupportBot_HandleStart(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/start"))
}

func TestSupportBot_HandleBuy(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy pro"))
}

func TestSupportBot_HandleBuy_NoTier(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy"))
}

func TestSupportBot_HandleBuy_InvalidTier(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy nonexistent"))
}

func TestSupportBot_HandleLicense_NotFound(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/license INVALID-KEY"))
}

func TestSupportBot_HandleHelp(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/help"))
}

func TestSupportBot_HandleUnknown(t *testing.T) {
	bot := newTestBot(t)
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/random"))
}

func marshalUpdate(t *testing.T, chatID int64, username, text string) []byte {
	t.Helper()
	upd := map[string]any{
		"message": map[string]any{
			"chat": map[string]any{"id": chatID},
			"from": map[string]any{"id": chatID, "username": username},
			"text": text,
		},
	}
	data, err := json.Marshal(upd)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
