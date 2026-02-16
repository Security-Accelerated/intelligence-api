package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func setup(t *testing.T) (*RedisCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := NewRedisCache(mr.Addr(), "", 0)
	return rc, mr
}

func TestCacheKey(t *testing.T) {
	got := cacheKey("example.com")
	want := "domain:example.com"
	if got != want {
		t.Errorf("cacheKey() = %q, want %q", got, want)
	}
}

func TestGet_Miss(t *testing.T) {
	rc, _ := setup(t)
	data, err := rc.Get(context.Background(), "nonexistent.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil on cache miss, got %v", data)
	}
}

func TestGet_Hit(t *testing.T) {
	rc, mr := setup(t)
	mr.Set("domain:example.com", `{"domain":"example.com","whois":{"domain_name":"example.com"}}`)

	data, err := rc.Get(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	want := `{"domain":"example.com","whois":{"domain_name":"example.com"}}`
	if string(data) != want {
		t.Errorf("data = %q, want %q", string(data), want)
	}
}

func TestSetThenGet_RoundTrip(t *testing.T) {
	rc, _ := setup(t)
	ctx := context.Background()

	original := []byte(`{"domain":"roundtrip.com","whois":{"domain_name":"roundtrip.com","registrar":"TestRegistrar"}}`)

	if err := rc.Set(ctx, "roundtrip.com", original, 5*time.Minute); err != nil {
		t.Fatalf("unexpected Set error: %v", err)
	}

	got, err := rc.Get(ctx, "roundtrip.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil data after Set")
	}
	if string(got) != string(original) {
		t.Errorf("data = %q, want %q", string(got), string(original))
	}
}
