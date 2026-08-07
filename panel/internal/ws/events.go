package ws

import "encoding/json"

type StatsPayload struct {
	SessionsTotal  int `json:"sessions_total"`
	SessionsToday  int `json:"sessions_today"`
	PasswordsTotal int `json:"passwords_total"`
}

type NewSessionPayload struct {
	ID             string `json:"id"`
	CountryCode    string `json:"country_code"`
	PasswordsCount int    `json:"passwords_count"`
}

type ChatMessage struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	Message     string `json:"message"`
	ParentID    string `json:"parent_id,omitempty"`
	MessageType string `json:"message_type"`
	CreatedAt   string `json:"created_at"`
}

type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

func newEvent(eventType string, data interface{}) []byte {
	ev := Event{Type: eventType, Data: data}
	b, _ := json.Marshal(ev)
	return b
}

func NewStatsEvent(payload StatsPayload) []byte {
	return newEvent("stats_update", payload)
}

func NewSessionEvent(payload NewSessionPayload) []byte {
	return newEvent("new_session", payload)
}

func NewChatEvent(msg ChatMessage) []byte {
	return newEvent("chat_message", msg)
}

// NewSessionUpdateEvent broadcasts a mutation on an existing session
// (lock, unlock, mark-viewed, delete). The frontend SessionDetail page
// subscribes to "session_update" and refetches when session_id matches.
func NewSessionUpdateEvent(sessionID string) []byte {
	return newEvent("session_update", map[string]string{"session_id": sessionID})
}
