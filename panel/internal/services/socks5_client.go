package services

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ProxyConfig struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (p ProxyConfig) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

func ConnectViaSOCKS5(target string, port int, proxy ProxyConfig) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Addr(), err)
	}

	if err := socks5Handshake(conn, proxy); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake: %w", err)
	}

	targetAddr := net.JoinHostPort(target, strconv.Itoa(port))
	if err := socks5Connect(conn, targetAddr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect %s: %w", targetAddr, err)
	}

	return conn, nil
}

func socks5Handshake(conn net.Conn, proxy ProxyConfig) error {
	methods := []byte{0x00}
	if proxy.Username != "" {
		methods = []byte{0x02}
	}

	msg := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write methods: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("read method response: %w", err)
	}
	if resp[0] != 0x05 {
		return errors.New("unsupported SOCKS version")
	}

	switch resp[1] {
	case 0x00:
	case 0x02:
		if err := socks5AuthPassword(conn, proxy.Username, proxy.Password); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported auth method: 0x%02x", resp[1])
	}
	return nil
}

func socks5AuthPassword(conn net.Conn, username, password string) error {
	msg := []byte{0x01, byte(len(username))}
	msg = append(msg, []byte(username)...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, []byte(password)...)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("SOCKS5 auth failed")
	}
	return nil
}

func socks5Connect(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	port, _ := strconv.Atoi(portStr)

	var atyp byte = 0x03
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = 0x01
			addr = ip4
		} else {
			atyp = 0x04
			addr = ip.To16()
		}
	} else {
		addr = []byte(host)
	}

	msg := []byte{0x05, 0x01, 0x00, atyp}
	if atyp == 0x03 {
		msg = append(msg, byte(len(addr)))
	}
	msg = append(msg, addr...)
	msg = append(msg, byte(port>>8), byte(port))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write connect: %w", err)
	}

	resp := make([]byte, 4)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		code := "general_failure"
		if resp[1] < byte(len(socksErrors)) {
			code = socksErrors[resp[1]]
		}
		return fmt.Errorf("SOCKS5 connect failed: %s (0x%02x)", code, resp[1])
	}

	bnd := parseSOCKS5Addr(conn, resp[3])
	_ = bnd
	return nil
}

var socksErrors = []string{
	0x00: "success",
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

func parseSOCKS5Addr(conn net.Conn, atyp byte) string {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		conn.Read(b)
		addr := net.IP(b).String()
		p := make([]byte, 2)
		conn.Read(p)
		return net.JoinHostPort(addr, strconv.Itoa(int(p[0])<<8|int(p[1])))
	case 0x03:
		b := make([]byte, 1)
		conn.Read(b)
		host := make([]byte, b[0])
		conn.Read(host)
		p := make([]byte, 2)
		conn.Read(p)
		return net.JoinHostPort(string(host), strconv.Itoa(int(p[0])<<8|int(p[1])))
	case 0x04:
		b := make([]byte, 16)
		conn.Read(b)
		addr := net.IP(b).String()
		p := make([]byte, 2)
		conn.Read(p)
		return net.JoinHostPort(addr, strconv.Itoa(int(p[0])<<8|int(p[1])))
	}
	return ""
}

func SOCKS5TransportDial(proxy ProxyConfig) func(string, string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		return ConnectViaSOCKS5(host, port, proxy)
	}
}

func ParseProxyConfig(raw string) (ProxyConfig, error) {
	if !strings.HasPrefix(raw, "socks5://") {
		parts := strings.Split(raw, ":")
		if len(parts) >= 2 {
			host := parts[0]
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				return ProxyConfig{Type: "socks5", Host: host, Port: port}, nil
			}
		}
		return ProxyConfig{}, errors.New("invalid proxy format, expected socks5://user:pass@host:port or host:port")
	}

	trimmed := strings.TrimPrefix(raw, "socks5://")
	atIdx := strings.LastIndex(trimmed, "@")
	creds := ""
	hostPort := trimmed
	if atIdx != -1 {
		creds = trimmed[:atIdx]
		hostPort = trimmed[atIdx+1:]
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("invalid proxy address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("invalid proxy port: %w", err)
	}

	pc := ProxyConfig{Type: "socks5", Host: host, Port: port}
	if creds != "" {
		sep := strings.IndexByte(creds, ':')
		if sep != -1 {
			pc.Username = creds[:sep]
			pc.Password = creds[sep+1:]
		}
	}
	return pc, nil
}
