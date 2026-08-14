package domain

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fastCrtShRetries shrinks the retry pause so these tests run in milliseconds.
func fastCrtShRetries(t *testing.T) {
	t.Helper()
	orig := crtShRetryDelay
	crtShRetryDelay = time.Millisecond
	t.Cleanup(func() { crtShRetryDelay = orig })
}

// crtShStub serves a scripted sequence of responses, then repeats the last one.
func crtShStub(t *testing.T, responses ...func(w http.ResponseWriter)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(calls.Add(1)) - 1
		if n >= len(responses) {
			n = len(responses) - 1
		}
		responses[n](w)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func respondStatus(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func respondBody(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = w.Write([]byte(body)) }
}

func TestFetchCrtSh_Success(t *testing.T) {
	fastCrtShRetries(t)
	srv, calls := crtShStub(t, respondBody(`[{"name_value":"a.example.com"}]`))

	body, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "IntelligenceAPI/1.0", 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(body), "a.example.com") {
		t.Errorf("body = %q, want the served payload", body)
	}
	if calls.Load() != 1 {
		t.Errorf("made %d requests, want 1", calls.Load())
	}
}

// TestFetchCrtSh_DoubleNotFoundMeansNoCertificates is the behavior the fix
// exists for: crt.sh answers 404 with an empty body for a name it holds no
// certificates for, and that must surface as the sentinel — which the lookups
// turn into a successful empty result — rather than as a failure. A freshly
// registered typosquat domain, the case a triaging customer cares most about,
// is exactly a name with no certificates yet.
func TestFetchCrtSh_DoubleNotFoundMeansNoCertificates(t *testing.T) {
	fastCrtShRetries(t)
	// Both 404s are the point of the test — the retry must also see one.
	//nolint:gocritic // dupOption: the duplicate response is deliberate.
	srv, calls := crtShStub(t, respondStatus(404), respondStatus(404))

	_, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "IntelligenceAPI/1.0", 1<<20)
	if !errors.Is(err, errCrtShNoResults) {
		t.Fatalf("err = %v, want errCrtShNoResults", err)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d requests, want 2 — one 404 is not evidence of absence", calls.Load())
	}
}

// TestFetchCrtSh_SingleNotFoundIsRetried guards the reason the retry exists:
// crt.sh 404s names it does hold certificates for when it is unhealthy, and
// concluding "no certificates" from one 404 would give a security tool a wrong
// answer that looks authoritative.
func TestFetchCrtSh_SingleNotFoundIsRetried(t *testing.T) {
	fastCrtShRetries(t)
	srv, calls := crtShStub(t, respondStatus(404), respondBody(`[]`))

	body, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "IntelligenceAPI/1.0", 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != `[]` {
		t.Errorf("body = %q, want the retried payload", body)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d requests, want 2", calls.Load())
	}
}

func TestFetchCrtSh_ServerErrorIsRetriedOnce(t *testing.T) {
	fastCrtShRetries(t)

	t.Run("recovers", func(t *testing.T) {
		srv, calls := crtShStub(t, respondStatus(502), respondBody(`[]`))
		if _, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 1<<20); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls.Load() != 2 {
			t.Errorf("made %d requests, want 2", calls.Load())
		}
	})

	t.Run("stays down", func(t *testing.T) {
		srv, calls := crtShStub(t, respondStatus(502), respondStatus(503))
		_, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 1<<20)
		if err == nil || errors.Is(err, errCrtShNoResults) {
			t.Fatalf("err = %v, want a status error", err)
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("err = %v, want the last status reported", err)
		}
		if calls.Load() != 2 {
			t.Errorf("made %d requests, want 2 — one retry, not a loop", calls.Load())
		}
	})
}

// TestFetchCrtSh_OtherStatusesAreNotRetried covers 429 in particular: repeating
// a request that was rejected for rate limiting makes the problem worse, and
// the answer will not change.
func TestFetchCrtSh_OtherStatusesAreNotRetried(t *testing.T) {
	fastCrtShRetries(t)
	srv, calls := crtShStub(t, respondStatus(429))

	_, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 1<<20)
	if err == nil || errors.Is(err, errCrtShNoResults) {
		t.Fatalf("err = %v, want a status error", err)
	}
	if calls.Load() != 1 {
		t.Errorf("made %d requests, want exactly 1", calls.Load())
	}
}

// TestFetchCrtSh_MixedNotFoundThenServerError must not report "no
// certificates": only two 404s are evidence of absence, and a 5xx on the retry
// means crt.sh could not answer.
func TestFetchCrtSh_MixedNotFoundThenServerError(t *testing.T) {
	fastCrtShRetries(t)
	srv, _ := crtShStub(t, respondStatus(404), respondStatus(502))

	_, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 1<<20)
	if errors.Is(err, errCrtShNoResults) {
		t.Fatal("a 404 followed by a 502 was reported as no-certificates")
	}
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("err = %v, want the 502 reported", err)
	}
}

// TestFetchCrtSh_ServerErrorThenNotFoundIsNotAbsence is the regression test for
// a bug the review caught: checking only the *final* status let a 502 followed
// by a 404 report "no certificates" on the strength of a single 404 — exactly
// the single-404 conclusion the two-attempt rule exists to rule out.
func TestFetchCrtSh_ServerErrorThenNotFoundIsNotAbsence(t *testing.T) {
	fastCrtShRetries(t)
	srv, calls := crtShStub(t, respondStatus(502), respondStatus(404))

	_, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 1<<20)
	if errors.Is(err, errCrtShNoResults) {
		t.Fatal("a 502 followed by a 404 was reported as no-certificates")
	}
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want the final 404 reported as a status error", err)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d requests, want 2", calls.Load())
	}
}

func TestFetchCrtSh_ContextCancelledDuringRetryPause(t *testing.T) {
	orig := crtShRetryDelay
	crtShRetryDelay = time.Hour // the pause must be interruptible, not waited out
	t.Cleanup(func() { crtShRetryDelay = orig })

	srv, _ := crtShStub(t, respondStatus(404))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := fetchCrtSh(ctx, srv.Client(), srv.URL, "x", 1<<20)
		done <- err
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetchCrtSh sat in the retry pause after cancellation")
	}
}

func TestFetchCrtSh_SetsUserAgent(t *testing.T) {
	fastCrtShRetries(t)
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	if _, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "IntelligenceAPI/1.0", 1<<20); err != nil {
		t.Fatal(err)
	}
	if got.Load() != "IntelligenceAPI/1.0" {
		t.Errorf("User-Agent = %q", got.Load())
	}
}

func TestFetchCrtSh_BodyIsCapped(t *testing.T) {
	fastCrtShRetries(t)
	srv, _ := crtShStub(t, respondBody(strings.Repeat("x", 4096)))

	body, err := fetchCrtSh(context.Background(), srv.Client(), srv.URL, "x", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 100 {
		t.Errorf("read %d bytes, want the 100-byte cap", len(body))
	}
}
