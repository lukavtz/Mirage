package services

import (
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/net/proxy"
)

type ProxyRotator struct {
	proxies []string
	current int
	mu      sync.Mutex
}

func NewProxyRotator(proxies []string) *ProxyRotator {
	return &ProxyRotator{proxies: proxies}
}

func (r *ProxyRotator) Next() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return ""
	}

	proxy := r.proxies[r.current]
	r.current = (r.current + 1) % len(r.proxies)
	return proxy
}

func SOCKS5Transport(proxyAddr string) (*http.Transport, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	return &http.Transport{
		Dial: dialer.Dial,
	}, nil
}
