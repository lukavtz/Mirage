package services_test

import (
	"testing"

	"github.com/user/mirage-panel/internal/services"
)

func TestProxyRotator_RoundRobin(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "1", Host: "proxy1", Port: 1080},
		{ID: "2", Host: "proxy2", Port: 1080},
		{ID: "3", Host: "proxy3", Port: 1080},
	}
	r := services.NewProxyRotator(entries)

	for i := 0; i < 5; i++ {
		got := r.Next()
		if got == nil {
			t.Fatalf("call %d: got nil", i+1)
		}
		expectedID := [5]string{"1", "2", "3", "1", "2"}[i]
		if got.ID != expectedID {
			t.Errorf("call %d: got id %q, want %q", i+1, got.ID, expectedID)
		}
	}
}

func TestProxyRotator_SingleProxy(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "1", Host: "host", Port: 1080, Username: "user", Password: "pass"},
	}
	r := services.NewProxyRotator(entries)

	for i := 0; i < 3; i++ {
		got := r.Next()
		if got == nil {
			t.Fatal("got nil")
		}
		if got.ID != "1" {
			t.Errorf("call %d: got id %q, want '1'", i+1, got.ID)
		}
	}
}

func TestProxyRotator_Empty(t *testing.T) {
	r := services.NewProxyRotator(nil)
	if got := r.Next(); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}

	r2 := services.NewProxyRotator([]services.ProxyEntry{})
	if got := r2.Next(); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}
