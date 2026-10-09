package ws

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"zialfi-panel/internal/auth"
)

// extractToken pulls a JWT from the upgrade request using three sources,
// checked in order:
//  1. Query parameter   ?token=<jwt>
//  2. Sub-protocol header  Sec-WebSocket-Protocol: jwt-<token>
//  3. Authorization header  Authorization: Bearer <token>
//
// Returns empty string when no token is found.
func extractToken(r *http.Request) string {
	// 1. query parameter
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}

	// 2. Sec-WebSocket-Protocol — comma-separated list, first entry prefixed with "jwt-"
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		for _, p := range strings.Split(proto, ",") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "jwt-") {
				return strings.TrimPrefix(p, "jwt-")
			}
		}
	}

	// 3. Authorization: Bearer <token>
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}

	return ""
}

func ServeWs(hub *Hub, dbConn *sql.DB, jwtSecret string, allowedOrigins string) http.HandlerFunc {
	hub.dbConn = dbConn // for readPump's periodic revalidation
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
		token := extractToken(r)
		if token == "" {
			http.Error(w, "missing auth token", http.StatusUnauthorized)
			return
		}

		claims, err := auth.ValidateToken(token, jwtSecret)
		if err != nil {
			http.Error(w, "invalid auth token", http.StatusUnauthorized)
			return
		}

		// Same revocation check as AuthMiddleware: token_version must match
		// the DB or the JWT (valid signature or not) is stale. Skipped when
		// no DB handle is wired (nil DB = no revocation surface).
		if dbConn != nil {
			var dbVersion int
			if err := dbConn.QueryRow("SELECT COALESCE(token_version, 0) FROM users WHERE id = $1", claims.UserID).Scan(&dbVersion); err != nil {
				http.Error(w, "user not found", http.StatusUnauthorized)
				return
			}
			if claims.TokenVersion != dbVersion {
				http.Error(w, "token has been revoked", http.StatusUnauthorized)
				return
			}
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		client := &Client{
			hub:    hub,
			conn:   conn,
			send:   make(chan []byte, sendBufSize),
			userID: claims.UserID,
			// token_version snapshot; 0 when no DB is wired (check skipped).
			dbVersion: claims.TokenVersion,
			channels: []string{
				"sessions:" + claims.UserID,
				"stats:" + claims.UserID,
				"chat:" + claims.UserID,
			},
		}
		if claims.Role == "admin" {
			client.channels = append(client.channels, "sessions:all", "chat:all")
		}

		hub.register <- client

		go client.writePump()
		go client.readPump()
		go client.revalidationLoop()
	}
}
