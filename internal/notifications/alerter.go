package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// ErrorRecorder tracks lookup errors and triggers alerts when thresholds are exceeded.
// Implementations must be safe for concurrent use.
type ErrorRecorder interface {
	RecordLookupError(lookupName string)
}

// AlerterConfig holds thresholds and timing for the alerter.
type AlerterConfig struct {
	ThrottleThreshold int           // errors per lookup type to trigger throttle alert
	ThrottleWindow    time.Duration // time window for throttle detection
	SpikeThreshold    int           // total errors across all lookups to trigger spike alert
	SpikeWindow       time.Duration // time window for spike detection
	Cooldown          time.Duration // minimum time between duplicate alerts
}

// Alerter tracks error rates and sends notifications when thresholds are exceeded.
type Alerter struct {
	notifier Notifier
	cfg      AlerterConfig

	mu           sync.Mutex
	lookupErrors map[string]*errorWindow
	globalErrors *errorWindow
	lastAlert    map[string]time.Time

	// now is a function that returns the current time. Overridable for testing.
	now func() time.Time
}

// NewAlerter creates an alerter with the given notifier and config.
func NewAlerter(notifier Notifier, cfg AlerterConfig) *Alerter {
	return &Alerter{
		notifier:     notifier,
		cfg:          cfg,
		lookupErrors: make(map[string]*errorWindow),
		globalErrors: &errorWindow{},
		lastAlert:    make(map[string]time.Time),
		now:          time.Now,
	}
}

// RecordLookupError records a lookup failure and checks alert thresholds.
func (a *Alerter) RecordLookupError(lookupName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()

	// Record per-lookup error
	w, ok := a.lookupErrors[lookupName]
	if !ok {
		w = &errorWindow{}
		a.lookupErrors[lookupName] = w
	}
	w.record(now)

	// Record global error
	a.globalErrors.record(now)

	// Check per-lookup throttle threshold
	throttleKey := "throttle:" + lookupName
	count := w.count(a.cfg.ThrottleWindow, now)
	if count >= a.cfg.ThrottleThreshold && a.cooldownElapsed(throttleKey, now) {
		a.lastAlert[throttleKey] = now
		title := "Upstream Throttle"
		msg := fmt.Sprintf("%s has failed %d times in the last %s", lookupName, count, a.cfg.ThrottleWindow)
		a.sendAsync(title, msg, 1)
	}

	// Check global spike threshold
	globalCount := a.globalErrors.count(a.cfg.SpikeWindow, now)
	if globalCount >= a.cfg.SpikeThreshold && a.cooldownElapsed("error_spike", now) {
		a.lastAlert["error_spike"] = now
		title := "Error Spike"
		msg := fmt.Sprintf("%d lookup errors in the last %s", globalCount, a.cfg.SpikeWindow)
		a.sendAsync(title, msg, 1)
	}
}

// cooldownElapsed returns true if enough time has passed since the last alert
// for the given key. Must be called with a.mu held.
func (a *Alerter) cooldownElapsed(key string, now time.Time) bool {
	last, ok := a.lastAlert[key]
	if !ok {
		return true
	}
	return now.Sub(last) >= a.cfg.Cooldown
}

// sendAsync fires a notification in a background goroutine so it never blocks
// the request path.
func (a *Alerter) sendAsync(title, message string, priority int) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.notifier.Send(ctx, title, message, priority); err != nil {
			logging.Logger().Error("failed to send notification",
				zap.String("title", title),
				zap.Error(err),
			)
		}
	}()
}

// errorWindow tracks timestamps of errors for sliding window counting.
type errorWindow struct {
	timestamps []time.Time
}

func (w *errorWindow) record(now time.Time) {
	w.timestamps = append(w.timestamps, now)
}

// count returns the number of errors within the window and prunes expired entries.
func (w *errorWindow) count(window time.Duration, now time.Time) int {
	cutoff := now.Add(-window)
	i := 0
	for i < len(w.timestamps) && w.timestamps[i].Before(cutoff) {
		i++
	}
	// Prune expired entries
	w.timestamps = w.timestamps[i:]
	return len(w.timestamps)
}

// NoopRecorder discards all error recordings. Used when alerting is disabled.
type NoopRecorder struct{}

func (n *NoopRecorder) RecordLookupError(_ string) {}
