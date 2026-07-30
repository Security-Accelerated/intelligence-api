package service

import (
	"encoding/json"
	"sync"

	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"go.uber.org/zap"
)

// Helpers for services that still cache and coalesce a whole response document
// rather than individual lookups. The domain service moved to per-lookup
// runners (see domain.go); the IP service still works this way, since an IP
// profile is fetched and cached as a single unit.

// copyViaJSON deep-copies a response struct so coalesced singleflight callers
// never share (and mutate) the same value. Returns nil if the round-trip fails.
func copyViaJSON[T any](v *T) *T {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	out := new(T)
	if err := json.Unmarshal(data, out); err != nil {
		return nil
	}
	return out
}

// goLookup runs a lookup goroutine with panic recovery. gin.Recovery only
// covers handler goroutines — without this, one panicking lookup (malformed
// cert, bad regex) would kill the entire process. A panic degrades to a
// sanitized lookup error on the response, consistent with partial-failure
// tolerance.
func goLookup(wg *sync.WaitGroup, mu *sync.Mutex, errs *[]domain.LookupError, alerter notifications.ErrorRecorder, lookupName, target string, fn func()) {
	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Logger().Error("lookup panicked",
					zap.String("lookup", lookupName),
					zap.String("target", target),
					zap.Any("panic", r),
					zap.Stack("stack"),
				)
				mu.Lock()
				defer mu.Unlock()
				*errs = append(*errs, domain.LookupError{Lookup: lookupName, Message: "internal error"})
				alerter.RecordLookupError(lookupName)
			}
		}()
		fn()
	})
}
