package domain

import (
	"context"
	"testing"
	"time"
)

// TestWSURLReadTimeout covers the startup budget handed to chromedp. The value
// itself is never asserted against a hardcoded number — only against the
// caller's deadline — because the point of the policy is that the deadline, not
// a constant, decides.
func TestWSURLReadTimeout(t *testing.T) {
	t.Run("no deadline leaves chromedp's default in place", func(t *testing.T) {
		if _, ok := wsURLReadTimeout(context.Background()); ok {
			t.Fatal("a context with no deadline must not override chromedp's default")
		}
	})

	t.Run("tracks the remaining budget", func(t *testing.T) {
		const budget = 30 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()

		got, ok := wsURLReadTimeout(ctx)
		if !ok {
			t.Fatal("a context with a deadline must override chromedp's default")
		}
		// Bounded either side: it must not exceed the budget, and the slack
		// allows only for the microseconds spent building the context.
		if got > budget || got < budget-time.Second {
			t.Errorf("got %v, want the remaining budget (~%v)", got, budget)
		}
	})

	t.Run("a budget longer than chromedp's default is not clamped", func(t *testing.T) {
		// The regression this guards: chromedp's fixed 20s wall meant a caller
		// with room to spare still failed at 20s. A cold or CPU-starved machine
		// has been seen taking longer than that to launch Chrome.
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		got, _ := wsURLReadTimeout(ctx)
		if got <= 20*time.Second {
			t.Errorf("got %v, want more than chromedp's 20s default", got)
		}
	})

	t.Run("an expired budget fires immediately", func(t *testing.T) {
		// chromedp feeds this to time.After, where a non-positive duration
		// fires at once — the right answer for a budget already spent, rather
		// than waiting 20s to report a failure that was already certain.
		ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
		defer cancel()

		got, ok := wsURLReadTimeout(ctx)
		if !ok {
			t.Fatal("an expired context still has a deadline")
		}
		if got > 0 {
			t.Errorf("got %v, want a non-positive duration", got)
		}
	})
}
