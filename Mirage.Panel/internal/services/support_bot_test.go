package services_test

import (
	"encoding/json"
	"testing"

	"github.com/user/mirage-panel/internal/services"
)

const testBotToken = "test:token"

func TestSupportBot_HandleStart(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/start"))
}

func TestSupportBot_HandleBuy(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy pro"))
}

func TestSupportBot_HandleBuy_NoTier(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy"))
}

func TestSupportBot_HandleBuy_InvalidTier(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/buy nonexistent"))
}

func TestSupportBot_HandleLicense_NotFound(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/license INVALID-KEY"))
}

func TestSupportBot_HandleHelp(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
	bot.HandleUpdate(marshalUpdate(t, 12345, "testuser", "/help"))
}

func TestSupportBot_HandleUnknown(t *testing.T) {
	bot := services.NewSupportBot(testBotToken, openTestDB(t))
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
