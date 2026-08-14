package domain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// crtShNoResults reports that crt.sh has no certificates for a query.
//
// crt.sh answers 404 with an empty body when it holds no certificates for a
// name, rather than 200 with an empty array. Treating that as a lookup failure
// was wrong in the case that matters most: a freshly registered typosquat
// domain has no certificates yet, so the domains a customer is most likely to
// be triaging returned an error instead of the correct and useful answer, "no
// certificates found".
var errCrtShNoResults = errors.New("crt.sh has no certificates for this name")

// crtShRetryDelay separates the two attempts made before concluding a 404 means
// "no results".
var crtShRetryDelay = time.Second

// fetchCrtSh performs a crt.sh request and returns the response body.
//
// crt.sh is unreliable enough that a single attempt is not evidence of
// anything: three consecutive uncached probes returned a 502 and two timeouts.
// Because successful lookups are cached for 24h and failures are not, this
// shows up as a lookup that fails on a cold cache and passes on the retry —
// which reads as flaky tooling rather than a flaky upstream.
//
// Two behaviors follow from that:
//
//   - A fast failure (404 or 5xx) is retried once. Both are cheap to repeat,
//     and one retry converts most of crt.sh's noise into a usable answer.
//   - Two 404s mean the name genuinely has no certificates, reported as
//     crtShNoResults rather than an error. Concluding that from a *single* 404
//     would be wrong often enough to matter: crt.sh 404s names it does hold
//     certificates for, and telling a security tool "no certificates" when
//     there are plenty is worse than telling it the lookup failed.
//
// Timeouts are deliberately not retried. They are the expensive failure, and a
// second full timeout would consume the rest of the request's budget.
func fetchCrtSh(ctx context.Context, client *http.Client, url, userAgent string, maxBytes int64) ([]byte, error) {
	var lastStatus, notFound int

	for attempt := range 2 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(crtShRetryDelay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("crt.sh request: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
			resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read crt.sh response: %w", readErr)
			}
			return body, nil
		}

		// Drained in full, not merely to maxBytes: an unread remainder stops
		// the connection returning to the keep-alive pool, and the retry a
		// moment later is to the same host. The client's Timeout bounds the
		// drain, so a pathological error body cannot hold this open forever.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusNotFound {
			notFound++
		}

		// Retry a 404 or a 5xx once; anything else (429, 4xx) is a real
		// answer that repeating will not change.
		retryable := resp.StatusCode == http.StatusNotFound || resp.StatusCode >= 500
		if !retryable {
			return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
		}
	}

	// Absence requires BOTH attempts to have answered 404. Checking only the
	// final status let a 502 followed by a 404 report "no certificates" on the
	// strength of a single 404 — precisely the single-404 conclusion the retry
	// exists to rule out.
	if notFound == 2 {
		return nil, errCrtShNoResults
	}
	return nil, fmt.Errorf("crt.sh returned status %d", lastStatus)
}
