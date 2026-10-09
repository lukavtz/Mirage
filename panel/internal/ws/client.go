package ws

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 4096
	sendBufSize    = 64
)

// wsRevalidateInterval is how often a connected socket re-checks
// token_version in the DB. Periodic chosen over event-driven: no event
// bus exists in the panel, and 5 minutes of staleness is acceptable for
// a C2 panel. Package-level so tests can shrink it.
var wsRevalidateInterval = 5 * time.Minute
type Client struct {
	hub       *Hub
	conn      *websocket.Conn
	send      chan []byte
	userID    string
	dbVersion int   // token_version at upgrade time; checked periodically
	channels  []string
	sendClose sync.Once
}

func (c *Client) close() {
	_ = c.conn.Close()
}
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// revalidationLoop periodically re-checks token_version and closes the
// socket when the client's token has been revoked. The actual unregister
// happens via readPump's deferred handler once the conn closes.
func (c *Client) revalidationLoop() {
	if c.hub.dbConn == nil {
		return
	}
	ticker := time.NewTicker(revalidateInterval())
	defer ticker.Stop()
	for range ticker.C {
		if !c.revalidate() {
			c.close()
			return
		}
	}
}

// revalidate returns false when token_version changed in the DB since
// upgrade (revocation).
func (c *Client) revalidate() bool {
	var dbVersion int
	if err := c.hub.dbConn.QueryRow("SELECT COALESCE(token_version, 0) FROM users WHERE id = $1", c.userID).Scan(&dbVersion); err != nil {
		return true // DB hiccup: keep the socket, next tick retries
	}
	return dbVersion == c.dbVersion
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
