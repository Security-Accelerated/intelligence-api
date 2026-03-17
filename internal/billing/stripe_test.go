package billing

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
}

type notifyCall struct {
	title    string
	message  string
	priority int
}

func (m *mockNotifier) Send(_ context.Context, title, message string, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, notifyCall{title, message, priority})
	return nil
}

func (m *mockNotifier) getCalls() []notifyCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]notifyCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

func TestStripeService_Notify(t *testing.T) {
	n := &mockNotifier{}
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "Test Title", "Test message")

	// notify is async, give it a moment
	time.Sleep(50 * time.Millisecond)

	calls := n.getCalls()
	if len(calls) != 1 {
		t.Fatalf("got %d notify calls, want 1", len(calls))
	}
	if calls[0].title != "Test Title" {
		t.Errorf("title = %q, want %q", calls[0].title, "Test Title")
	}
	if calls[0].message != "Test message" {
		t.Errorf("message = %q, want %q", calls[0].message, "Test message")
	}
	if calls[0].priority != 0 {
		t.Errorf("priority = %d, want 0", calls[0].priority)
	}
}

func TestStripeService_NotifyMultiple(t *testing.T) {
	n := &mockNotifier{}
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "New Subscriber", "user@example.com signed up for basic")
	svc.notify(context.Background(), "Subscription Cancelled", "Customer cus_123 cancelled")

	time.Sleep(50 * time.Millisecond)

	calls := n.getCalls()
	if len(calls) != 2 {
		t.Fatalf("got %d notify calls, want 2", len(calls))
	}
}

func TestNewStripeService_SetsNotifier(t *testing.T) {
	n := &mockNotifier{}
	svc := NewStripeService("sk_test_123", "whsec_123", map[string]string{"price_1": "basic"}, nil, nil, n)

	if svc.notifier == nil {
		t.Fatal("notifier should not be nil")
	}
	if svc.webhookSecret != "whsec_123" {
		t.Errorf("webhookSecret = %q, want %q", svc.webhookSecret, "whsec_123")
	}
	if svc.priceToplan["price_1"] != "basic" {
		t.Errorf("priceToplan[price_1] = %q, want %q", svc.priceToplan["price_1"], "basic")
	}
}
