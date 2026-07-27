package ws

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"zialfi-panel/internal/auth"
)

func ServeWs(hub *Hub, jwtSecret string, allowedOrigins string) http.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range strings.Split(allowedOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			allowed[o] = true
		}
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return false
			}
			if allowedOrigins == "*" {
				return true
			}
			return allowed[origin]
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		var authMsg struct {
			Type  string `json:"type"`
			Token string `json:"token"`
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil || json.Unmarshal(msg, &authMsg) != nil || authMsg.Type != "auth" || authMsg.Token == "" {
			conn.Close()
			return
		}
		conn.SetReadDeadline(time.Time{})

		claims, err := auth.ValidateToken(authMsg.Token, jwtSecret)
		if err != nil {
			conn.Close()
			return
		}

		client := &Client{
			hub:    hub,
			conn:   conn,
			send:   make(chan []byte, sendBufSize),
			userID: claims.UserID,
			channels: []string{
				"chat",
				"sessions",
				"stats",
			},
		}

		hub.register <- client

		go client.writePump()
		go client.readPump()
	}
}
