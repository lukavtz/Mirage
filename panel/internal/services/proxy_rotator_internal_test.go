package services

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// startSocks5Server runs a minimal SOCKS5 proxy on localhost that accepts
// the handshake and connect requests, replying with success.
func startSocks5Server(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2)
				if _, err := c.Read(buf); err != nil {
					return
				}
				methods := make([]byte, buf[1])
				if _, err := c.Read(methods); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00})
				cbuf := make([]byte, 4)
				if _, err := c.Read(cbuf); err != nil {
					return
				}
				switch cbuf[3] {
				case 0x01:
					c.Read(make([]byte, 4))
				case 0x03:
					lb := make([]byte, 1)
					c.Read(lb)
					c.Read(make([]byte, lb[0]))
				case 0x04:
					c.Read(make([]byte, 16))
				}
				c.Read(make([]byte, 2))
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90})
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestSOCKS5Transport_Valid(t *testing.T) {
	tr, err := SOCKS5Transport("127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestProxyRotator_testProxy_Success(t *testing.T) {
	host, port := startSocks5Server(t)
	entry := ProxyEntry{Host: host, Port: port}
	if !testProxy(entry) {
		t.Error("expected proxy to be alive")
	}
}

func TestProxyRotator_testProxy_Unreachable(t *testing.T) {
	entry := ProxyEntry{Host: "127.0.0.1", Port: 1}
	if testProxy(entry) {
		t.Error("expected unreachable proxy to be dead")
	}
}

func TestProxyRotator_HealthCheck_MarksDead(t *testing.T) {
	host, port := startSocks5Server(t)
	entries := []ProxyEntry{
		{ID: "live", Host: host, Port: port},
		{ID: "dead", Host: "127.0.0.1", Port: 1},
	}
	r := NewProxyRotator(entries)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.HealthCheck(ctx, 10*time.Millisecond)
	list := r.List()
	alive := map[string]bool{}
	for _, e := range list {
		alive[e.ID] = e.Alive
	}
	if !alive["live"] {
		t.Error("reachable proxy should be marked alive")
	}
	if alive["dead"] {
		t.Error("unreachable proxy should be marked dead")
	}
}