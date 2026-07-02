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
	return newEvent("stats", payload)
}

func NewSessionEvent(payload NewSessionPayload) []byte {
	return newEvent("new_session", payload)
}
