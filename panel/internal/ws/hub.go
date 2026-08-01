package ws

type Hub struct {
	clients    map[*Client]bool
	channels   map[string]map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan *channelMessage
}

type channelMessage struct {
	channel string
	data    []byte
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		channels:   make(map[string]map[*Client]bool),
		broadcast:  make(chan *channelMessage, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			for _, ch := range client.channels {
				if h.channels[ch] == nil {
					h.channels[ch] = make(map[*Client]bool)
				}
				h.channels[ch][client] = true
			}

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				for _, ch := range client.channels {
					delete(h.channels[ch], client)
				}
				delete(h.clients, client)
				close(client.send)
			}

		case msg := <-h.broadcast:
			for client := range h.channels[msg.channel] {
				select {
				case client.send <- msg.data:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

func (h *Hub) Broadcast(channel string, message []byte) {
	h.broadcast <- &channelMessage{channel: channel, data: message}
}

