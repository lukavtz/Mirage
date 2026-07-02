package services_test

import (
	"testing"

	"github.com/user/mirage-panel/internal/services"
)

func TestProxyRotator_RoundRobin(t *testing.T) {
	proxies := []string{"socks5://proxy1:1080", "socks5://proxy2:1080", "socks5://proxy3:1080"}
	r := services.NewProxyRotator(proxies)

	expected := []string{"socks5://proxy1:1080", "socks5://proxy2:1080", "socks5://proxy3:1080"}
	for i := 0; i < 5; i++ {
		got := r.Next()
		want := expected[i%3]
		if got != want {
			t.Errorf("call %d: got %q, want %q", i+1, got, want)
		}
	}
}

func TestProxyRotator_SingleProxy(t *testing.T) {
	proxies := []string{"socks5://user:pass@host:1080"}
	r := services.NewProxyRotator(proxies)

	for i := 0; i < 3; i++ {
		got := r.Next()
		if got != "socks5://user:pass@host:1080" {
			t.Errorf("call %d: got %q, want single proxy", i+1, got)
		}
	}
}

func TestProxyRotator_Empty(t *testing.T) {
	r := services.NewProxyRotator(nil)
	if got := r.Next(); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}

	r2 := services.NewProxyRotator([]string{})
	if got := r2.Next(); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
