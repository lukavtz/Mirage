package services

import (
	"net"
	"strings"
	"testing"
)

// pipeServer returns the client end of a net.Pipe with a goroutine
// running the handler on the server end. The client is cleaned up
// when the test finishes.
func pipeServer(t *testing.T, handler func(net.Conn)) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go func() {
		defer server.Close()
		handler(server)
	}()
	return client
}

// fakeSocks5Server returns a handler that reads a SOCKS5 handshake,
// responds with the given authMethod, and optionally does password
// auth sub-negotiation, then reads the connect request and writes
// connectResp followed by the bndHandler.
func fakeSocks5Server(t *testing.T, authMethod byte, authValid bool, connectResp []byte, bndHandler func(net.Conn)) func(net.Conn) {
	t.Helper()
	return func(conn net.Conn) {
		buf := make([]byte, 2)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		nm := int(buf[1])
		methods := make([]byte, nm)
		if _, err := conn.Read(methods); err != nil {
			return
		}
		conn.Write([]byte{0x05, authMethod})

		if authMethod == 0x02 {
			abuf := make([]byte, 2)
			if _, err := conn.Read(abuf); err != nil {
				return
			}
			ulen := int(abuf[1])
			user := make([]byte, ulen)
			conn.Read(user)
			plen := make([]byte, 1)
			conn.Read(plen)
			pass := make([]byte, plen[0])
			conn.Read(pass)
			if authValid {
				conn.Write([]byte{0x01, 0x00})
			} else {
				conn.Write([]byte{0x01, 0x01})
				return
			}
		}

		cbuf := make([]byte, 4)
		if _, err := conn.Read(cbuf); err != nil {
			return
		}
		atyp := cbuf[3]
		switch atyp {
		case 0x01:
			conn.Read(make([]byte, 4))
		case 0x03:
			lbuf := make([]byte, 1)
			conn.Read(lbuf)
			conn.Read(make([]byte, lbuf[0]))
		case 0x04:
			conn.Read(make([]byte, 16))
		}
		conn.Read(make([]byte, 2))
		conn.Write(connectResp)
		if bndHandler != nil {
			bndHandler(conn)
		}
	}
}

func TestProxyConfig_Addr(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"1.2.3.4", 1080, "1.2.3.4:1080"},
		{"::1", 8080, "[::1]:8080"},
		{"localhost", 443, "localhost:443"},
	}
	for _, tc := range tests {
		pc := ProxyConfig{Host: tc.host, Port: tc.port}
		if got := pc.Addr(); got != tc.want {
			t.Errorf("Addr(%s,%d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestSocks5Handshake_NoAuth(t *testing.T) {
	conn := pipeServer(t, fakeSocks5Server(t, 0x00, true, nil, nil))
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5Handshake_AuthPassword(t *testing.T) {
	conn := pipeServer(t, fakeSocks5Server(t, 0x02, true, nil, nil))
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5Handshake_WriteError(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Close()
	})
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1})
	if err == nil {
		t.Fatal("expected error on closed pipe")
	}
}

func TestSocks5Handshake_ReadError(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		buf := make([]byte, 2)
		conn.Read(buf)
		nm := int(buf[1])
		methods := make([]byte, nm)
		conn.Read(methods)
		conn.Close()
	})
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1})
	if err == nil {
		t.Fatal("expected error on closed pipe during read")
	}
}

func TestSocks5Handshake_WrongVersion(t *testing.T) {
	conn := pipeServer(t, fakeSocks5Server(t, 0x04, true, nil, nil))
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1})
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestSocks5Handshake_UnsupportedMethod(t *testing.T) {
	conn := pipeServer(t, fakeSocks5Server(t, 0xff, true, nil, nil))
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1})
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestSocks5AuthPassword_Success(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		buf := make([]byte, 2)
		conn.Read(buf)
		ulen := int(buf[1])
		user := make([]byte, ulen)
		conn.Read(user)
		plen := make([]byte, 1)
		conn.Read(plen)
		pass := make([]byte, plen[0])
		conn.Read(pass)
		conn.Write([]byte{0x01, 0x00})
	})
	err := socks5AuthPassword(conn, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5AuthPassword_Failure(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Read(make([]byte, 2))
		conn.Read(make([]byte, 4))
		conn.Read(make([]byte, 1))
		conn.Read(make([]byte, 4))
		conn.Write([]byte{0x01, 0x01})
	})
	err := socks5AuthPassword(conn, "user", "pass")
	if err == nil {
		t.Fatal("expected auth failure error")
	}
}

func TestSocks5AuthPassword_WriteError(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Close()
	})
	err := socks5AuthPassword(conn, "user", "pass")
	if err == nil {
		t.Fatal("expected write error on closed pipe")
	}
}

// connectServer returns a handler that reads only the SOCKS5 connect
// request (no handshake) and writes connectResp.
func connectServer(t *testing.T, connectResp []byte) func(net.Conn) {
	t.Helper()
	return func(conn net.Conn) {
		cbuf := make([]byte, 4)
		if _, err := conn.Read(cbuf); err != nil {
			return
		}
		atyp := cbuf[3]
		switch atyp {
		case 0x01:
			conn.Read(make([]byte, 4))
		case 0x03:
			lbuf := make([]byte, 1)
			conn.Read(lbuf)
			conn.Read(make([]byte, lbuf[0]))
		case 0x04:
			conn.Read(make([]byte, 16))
		}
		conn.Read(make([]byte, 2))
		conn.Write(connectResp)
	}
}

func TestSocks5Connect_Domain(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90}))
	err := socks5Connect(conn, "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5Connect_IPv4(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x05, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x50}))
	err := socks5Connect(conn, "10.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5Connect_IPv6(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x05, 0x00, 0x00, 0x04,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x50}))
	err := socks5Connect(conn, "[2001:db8::1]:80")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5Connect_ErrorCode(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))
	err := socks5Connect(conn, "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("expected connection refused error, got: %v", err)
	}
}

func TestSocks5Connect_BadVersion(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))
	err := socks5Connect(conn, "example.com:80")
	if err == nil {
		t.Fatal("expected error for bad version in response")
	}
}

func TestSocks5Connect_UnknownErrorCode(t *testing.T) {
	conn := pipeServer(t, connectServer(t, []byte{0x05, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))
	err := socks5Connect(conn, "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "0x09") {
		t.Fatalf("expected error containing code 0x09, got: %v", err)
	}
}

func TestSocks5Connect_ReadError(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		cbuf := make([]byte, 4)
		conn.Read(cbuf)
		atyp := cbuf[3]
		switch atyp {
		case 0x01:
			conn.Read(make([]byte, 4))
		case 0x03:
			lbuf := make([]byte, 1)
			conn.Read(lbuf)
			conn.Read(make([]byte, lbuf[0]))
		case 0x04:
			conn.Read(make([]byte, 16))
		}
		conn.Read(make([]byte, 2))
		conn.Close()
	})
	err := socks5Connect(conn, "example.com:80")
	if err == nil {
		t.Fatal("expected error on closed pipe during connect response read")
	}
}

func TestSocks5Connect_BadHostPort(t *testing.T) {
	conn := pipeServer(t, func(net.Conn) {})
	err := socks5Connect(conn, "bad-addr")
	if err == nil {
		t.Fatal("expected error for bad addr")
	}
}

func TestParseSOCKS5Addr_IPv4(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Write([]byte{0x7f, 0x00, 0x00, 0x01})
		conn.Write([]byte{0x1f, 0x90})
	})
	got := parseSOCKS5Addr(conn, 0x01)
	want := "127.0.0.1:8080"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSOCKS5Addr_Domain(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Write([]byte{0x07})
		conn.Write([]byte("example"))
		conn.Write([]byte{0x00, 0x50})
	})
	got := parseSOCKS5Addr(conn, 0x03)
	want := "example:80"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSOCKS5Addr_IPv6(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		conn.Write([]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
		conn.Write([]byte{0x00, 0x50})
	})
	got := parseSOCKS5Addr(conn, 0x04)
	want := "[2001:db8::1]:80"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSOCKS5Addr_Unknown(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {})
	got := parseSOCKS5Addr(conn, 0xff)
	if got != "" {
		t.Errorf("expected empty for unknown atyp, got %q", got)
	}
}

func TestSOCKS5TransportDial(t *testing.T) {
	proxy := ProxyConfig{Host: "127.0.0.1", Port: 9999}
	dial := SOCKS5TransportDial(proxy)
	if dial == nil {
		t.Fatal("expected non-nil dial func")
	}
	_, err := dial("tcp", "1.2.3.4:80")
	if err == nil {
		t.Fatal("expected dial error for unreachable proxy")
	}
}

func TestParseProxyConfig_Socks5Full(t *testing.T) {
	pc, err := ParseProxyConfig("socks5://user:pass@host:1080")
	if err != nil {
		t.Fatal(err)
	}
	if pc.Type != "socks5" {
		t.Errorf("Type = %q, want socks5", pc.Type)
	}
	if pc.Host != "host" {
		t.Errorf("Host = %q, want host", pc.Host)
	}
	if pc.Port != 1080 {
		t.Errorf("Port = %d, want 1080", pc.Port)
	}
	if pc.Username != "user" {
		t.Errorf("Username = %q, want user", pc.Username)
	}
	if pc.Password != "pass" {
		t.Errorf("Password = %q, want pass", pc.Password)
	}
}

func TestParseProxyConfig_Socks5NoCreds(t *testing.T) {
	pc, err := ParseProxyConfig("socks5://proxy.example.com:2080")
	if err != nil {
		t.Fatal(err)
	}
	if pc.Host != "proxy.example.com" {
		t.Errorf("Host = %q", pc.Host)
	}
	if pc.Port != 2080 {
		t.Errorf("Port = %d", pc.Port)
	}
	if pc.Username != "" || pc.Password != "" {
		t.Error("expected empty credentials")
	}
}

func TestParseProxyConfig_HostPort(t *testing.T) {
	pc, err := ParseProxyConfig("10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if pc.Type != "socks5" {
		t.Errorf("Type = %q", pc.Type)
	}
	if pc.Host != "10.0.0.1" {
		t.Errorf("Host = %q", pc.Host)
	}
	if pc.Port != 1080 {
		t.Errorf("Port = %d", pc.Port)
	}
}

func TestParseProxyConfig_Errors(t *testing.T) {
	cases := []string{
		"",
		"host",
		"socks5://host",
		"socks5://host:notaport",
		"host:notaport",
	}
	for _, raw := range cases {
		_, err := ParseProxyConfig(raw)
		if err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestConnectViaSOCKS5_EndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 2)
		conn.Read(buf)
		nm := int(buf[1])
		methods := make([]byte, nm)
		conn.Read(methods)
		conn.Write([]byte{0x05, 0x00})

		cbuf := make([]byte, 4)
		conn.Read(cbuf)
		atyp := cbuf[3]
		switch atyp {
		case 0x01:
			conn.Read(make([]byte, 4))
		case 0x03:
			lbuf := make([]byte, 1)
			conn.Read(lbuf)
			conn.Read(make([]byte, lbuf[0]))
		case 0x04:
			conn.Read(make([]byte, 16))
		}
		conn.Read(make([]byte, 2))
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90})
	}()

	addr := ln.Addr().(*net.TCPAddr)
	proxy := ProxyConfig{Host: "127.0.0.1", Port: addr.Port}
	conn, err := ConnectViaSOCKS5("example.com", 80, proxy)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-done
}

func TestConnectViaSOCKS5_DialError(t *testing.T) {
	proxy := ProxyConfig{Host: "127.0.0.1", Port: 1}
	_, err := ConnectViaSOCKS5("example.com", 80, proxy)
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestSocks5Handshake_AuthReadError(t *testing.T) {
	conn := pipeServer(t, func(conn net.Conn) {
		buf := make([]byte, 2)
		conn.Read(buf)
		nm := int(buf[1])
		methods := make([]byte, nm)
		conn.Read(methods)
		conn.Write([]byte{0x05, 0x02})
		conn.Read(make([]byte, 2))
		conn.Close()
	})
	err := socks5Handshake(conn, ProxyConfig{Host: "h", Port: 1, Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("expected error on closed pipe during auth read")
	}
}

func TestParseProxyConfig_Socks5UserNoPass(t *testing.T) {
	pc, err := ParseProxyConfig("socks5://justuser@host:1080")
	if err != nil {
		t.Fatal(err)
	}
	if pc.Username != "" || pc.Password != "" {
		t.Error("expected empty credentials when no colon in creds part")
	}
}
