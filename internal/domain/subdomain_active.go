package domain

import (
	"context"
	"sync"
	"time"
)

// CheckSubdomainActive performs DNS and HTTP liveness checks on each subdomain
// entry using bounded concurrency. It populates Registered and Live fields in-place.
// Reuses isDNSRegistered and isHTTPLive from typosquatting_active.go.
func CheckSubdomainActive(ctx context.Context, entries []SubdomainEntry, concurrency int) {
	if concurrency <= 0 {
		concurrency = 20
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range entries {
		wg.Add(1)
		go func(e *SubdomainEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			checkSubdomain(ctx, e)
		}(&entries[i])
	}

	wg.Wait()
}

func checkSubdomain(ctx context.Context, e *SubdomainEntry) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	registered := isDNSRegistered(ctx, e.Domain)
	e.Registered = &registered

	if !registered {
		return
	}

	live := isHTTPLive(ctx, e.Domain)
	e.Live = &live
}
