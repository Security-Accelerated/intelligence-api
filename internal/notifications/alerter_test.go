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
	sent  chan struct{}
}

type mockCall struct {
	title    string
	message  string
	priority int
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{sent: make(chan struct{}, 64)}
}

func (m *mockNotifier) Send(_ context.Context, title, message string, priority int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{title, message, priority})
	m.mu.Unlock()
	// Non-blocking signal so the mock never deadlocks if a test doesn't drain.
	select {
	case m.sent <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockNotifier) getCalls() []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]mockCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

// waitForCalls blocks until at least n notifications beyond startCount have
// arrived, or fails the test on timeout. Returns the full call list.
func (m *mockNotifier) waitForCalls(t *testing.T, startCount, n int) []mockCall {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if len(m.getCalls())-startCount >= n {
			return m.getCalls()
		}
		select {
		case <-m.sent:
		case <-deadline:
			t.Fatalf("timed out waiting for %d notifications, got %d", n, len(m.getCalls())-startCount)
		}
	}
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
	mock := newMockNotifier()
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Record 2 errors (below threshold of 3) — no goroutines spawn, so we can
	// assert immediately.
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	if len(mock.getCalls()) != 0 {
		t.Errorf("expected no notifications, got %d", len(mock.getCalls()))
	}
}

func TestAlerter_ThrottleThreshold_Reached(t *testing.T) {
	mock := newMockNotifier()
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	a.RecordLookupError("whois")
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	calls := mock.waitForCalls(t, 0, 1)
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
	mock := newMockNotifier()
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Trigger throttle alert
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	mock.waitForCalls(t, 0, 1)
	initialCalls := len(mock.getCalls())

	// Record more errors immediately — cooldown should suppress, no goroutines
	// spawn so we can assert immediately.
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	if len(mock.getCalls()) != initialCalls {
		t.Errorf("expected cooldown to suppress duplicate, got %d calls (was %d)", len(mock.getCalls()), initialCalls)
	}

	// Advance past cooldown
	now = now.Add(16 * time.Minute)
	for i := 0; i < 3; i++ {
		a.RecordLookupError("dns")
	}
	mock.waitForCalls(t, initialCalls, 1)

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
	mock := newMockNotifier()
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// 2 whois errors + 2 dns errors = below threshold for each — no goroutines spawn.
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")
	a.RecordLookupError("dns")
	a.RecordLookupError("dns")

	for _, c := range mock.getCalls() {
		if c.title == "Upstream Throttle" {
			t.Error("expected no throttle notification when each lookup is below threshold")
		}
	}
}

func TestAlerter_SpikeThreshold(t *testing.T) {
	mock := newMockNotifier()
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

	calls := mock.waitForCalls(t, 0, 1)
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
	mock := newMockNotifier()
	a := NewAlerter(mock, testConfig())
	now := time.Now()
	a.now = func() time.Time { return now }

	// Record 2 errors
	a.RecordLookupError("whois")
	a.RecordLookupError("whois")

	// Advance past the window so those errors expire
	now = now.Add(6 * time.Minute)

	// Record 1 more — total in window is 1, below threshold, no goroutine spawns.
	a.RecordLookupError("whois")

	for _, c := range mock.getCalls() {
		if c.title == "Upstream Throttle" {
			t.Error("expected no throttle notification after window expiry")
		}
	}
}

// TestNoopRecorder pins that the no-op path is safe to call. Not panicking is
// the whole assertion, so the test takes no *testing.T.
func TestNoopRecorder(_ *testing.T) {
	r := &NoopRecorder{}
	r.RecordLookupError("whois")
}
