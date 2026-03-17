package usage

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestUsageLogger_RecordAndStop(t *testing.T) {
	// Use nil db — we can't actually INSERT, but we can verify channel/stop
	// behavior without a database. The flush will log an error, which is fine.
	logger := NewUsageLogger(nil, 16, 50*time.Millisecond, zap.NewNop())

	logger.Record(UsageEntry{Method: "POST", Path: "/v1/domain/lookup", StatusCode: 200, LatencyMs: 100})
	logger.Record(UsageEntry{Method: "GET", Path: "/v1/hello", StatusCode: 200, LatencyMs: 5})

	// Stop should drain without hanging.
	done := make(chan struct{})
	go func() {
		logger.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2 seconds")
	}
}

func TestUsageLogger_DropWhenFull(t *testing.T) {
	logger := NewUsageLogger(nil, 2, time.Hour, zap.NewNop())

	// Fill the buffer.
	logger.Record(UsageEntry{Method: "POST", Path: "/a", StatusCode: 200})
	logger.Record(UsageEntry{Method: "POST", Path: "/b", StatusCode: 200})

	// This should be silently dropped, not block.
	done := make(chan struct{})
	go func() {
		logger.Record(UsageEntry{Method: "POST", Path: "/c", StatusCode: 200})
		close(done)
	}()

	select {
	case <-done:
		// OK — non-blocking drop
	case <-time.After(time.Second):
		t.Fatal("Record blocked on full channel")
	}

	logger.Stop()
}

func TestNoopRecorder(t *testing.T) {
	var r NoopRecorder
	// Should not panic.
	r.Record(UsageEntry{Method: "GET", Path: "/v1/hello", StatusCode: 200})
}
