package notifications

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockNotifier struct {
	mu    sync.Mutex
	calls []mockCall
}

type mockCall struct {
	title    string
	message  string
	priority int
}

func (m *mockNotifier) Send(_ context.Context, title, message string, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{title, message, priority})
	return nil
}

func (m *mockNotifier) getCalls() []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]mockCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

func testConfig() AlerterConfig {
	return AlerterConfig{
		ThrottleThreshold: 3,
		ThrottleWindow:    5 * time.Minute,
		SpikeThreshold:    50, // high to avoid interfering with throttle tests
		SpikeWindow:       5 * time.Minute,
		Cooldown:          15 * time.Minute,
	}
}

func TestAlerter_ThrottleThreshold_NotReached(t *testing.T) {
	mock := &mockNotifier{}
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Record 2 errors (below threshold of 3)
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	// Allow async goroutines to complete
	time.Sleep(50 * time.Millisecond)

	if len(mock.getCalls()) != 0 {
		t.Errorf("expected no notifications, got %d", len(mock.getCalls()))
	}
}

func TestAlerter_ThrottleThreshold_Reached(t *testing.T) {
	mock := &mockNotifier{}
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	a.RecordLookupError("whois")
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	time.Sleep(50 * time.Millisecond)

	calls := mock.getCalls()
	found := false
	for _, c := range calls {
		if c.title == "Upstream Throttle" {
			found = true
		}
	}
	if !found {
		t.Error("expected Upstream Throttle notification")
	}
}

func TestAlerter_ThrottleCooldown(t *testing.T) {
	mock := &mockNotifier{}
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Trigger throttle alert
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	time.Sleep(50 * time.Millisecond)

	initialCalls := len(mock.getCalls())

	// Record more errors immediately — cooldown should suppress
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	time.Sleep(50 * time.Millisecond)

	if len(mock.getCalls()) != initialCalls {
		t.Errorf("expected cooldown to suppress duplicate, got %d calls (was %d)", len(mock.getCalls()), initialCalls)
	}

	// Advance past cooldown
	now = now.Add(16 * time.Minute)
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	time.Sleep(50 * time.Millisecond)

	calls := mock.getCalls()
	throttleCount := 0
	for _, c := range calls {
		if c.title == "Upstream Throttle" {
			throttleCount++
		}
	}
	if throttleCount != 2 {
		t.Errorf("expected 2 throttle notifications after cooldown, got %d", throttleCount)
	}
}

func TestAlerter_PerLookupIsolation(t *testing.T) {
	mock := &mockNotifier{}
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// 2 whois errors + 2 dns errors = below threshold for each
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")
	a.RecordLookupError("dns")
	a.RecordLookupError("dns")

	time.Sleep(50 * time.Millisecond)

	calls := mock.getCalls()
	for _, c := range calls {
		if c.title == "Upstream Throttle" {
			t.Error("expected no throttle notification when each lookup is below threshold")
		}
	}
}

func TestAlerter_SpikeThreshold(t *testing.T) {
	mock := &mockNotifier{}
	cfg := testConfig()
	cfg.SpikeThreshold = 5 // override for this test
	a := NewAlerter(mock, cfg)
	now := time.Now()
	a.now = func() time.Time { return now }

	// Spread errors across different lookups to hit spike threshold (5)
	a.RecordLookupError("whois")
	a.RecordLookupError("dns")
	a.RecordLookupError("ssl")
	a.RecordLookupError("headers")
	a.RecordLookupError("bgp")

	time.Sleep(50 * time.Millisecond)

	calls := mock.getCalls()
	found := false
	for _, c := range calls {
		if c.title == "Error Spike" {
			found = true
		}
	}
	if !found {
		t.Error("expected Error Spike notification")
	}
}

func TestAlerter_WindowExpiry(t *testing.T) {
	mock := &mockNotifier{}
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Record 2 errors
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	// Advance past the window so those errors expire
	now = now.Add(6 * time.Minute)

	// Record 1 more — total in window is 1, below threshold
	a.RecordLookupError("whois")

	time.Sleep(50 * time.Millisecond)

	calls := mock.getCalls()
	for _, c := range calls {
		if c.title == "Upstream Throttle" {
			t.Error("expected no throttle notification after window expiry")
		}
	}
}

func TestNoopRecorder(t *testing.T) {
	r := &NoopRecorder{}
	// Should not panic
	r.RecordLookupError("whois")
}
