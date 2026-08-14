package domain

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRedactLicenseKeyParam(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "scrubs license_key in MaxMind URL",
			in:   "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=SECRET123&suffix=tar.gz",
			want: "license_key=REDACTED",
		},
		{
			name: "passthrough when no license_key present",
			in:   "https://example.com/path?foo=bar",
			want: "foo=bar",
		},
		{
			name: "passthrough on unparseable input",
			in:   "::not a url::",
			want: "::not a url::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactLicenseKeyParam(tt.in)
			if !strings.Contains(got, tt.want) {
				t.Errorf("redactLicenseKeyParam(%q) = %q, want it to contain %q", tt.in, got, tt.want)
			}
			if strings.Contains(got, "SECRET123") {
				t.Errorf("redactLicenseKeyParam(%q) leaked license key: %q", tt.in, got)
			}
		})
	}
}

func TestScrubLicenseKey_RewritesURLError(t *testing.T) {
	original := &url.Error{
		Op:  "Get",
		URL: "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=SECRET123&suffix=tar.gz",
		Err: errors.New("dial tcp: lookup failed"),
	}

	scrubbed := scrubLicenseKey(original)

	msg := scrubbed.Error()
	if strings.Contains(msg, "SECRET123") {
		t.Errorf("scrubbed error still contains license key: %q", msg)
	}
	if !strings.Contains(msg, "REDACTED") {
		t.Errorf("scrubbed error missing REDACTED marker: %q", msg)
	}

	// The same *url.Error pointer should be in the chain so callers can still
	// errors.As it; only its URL field is mutated.
	var urlErr *url.Error
	if !errors.As(scrubbed, &urlErr) {
		t.Fatal("scrubbed error no longer satisfies errors.As(*url.Error)")
	}
	if urlErr != original {
		t.Errorf("expected the same *url.Error pointer, got a different one")
	}
}

func TestScrubLicenseKey_NilAndUnrelatedErrors(t *testing.T) {
	if got := scrubLicenseKey(nil); got != nil {
		t.Errorf("scrubLicenseKey(nil) = %v, want nil", got)
	}

	plain := errors.New("plain error")
	if got := scrubLicenseKey(plain); got != plain {
		t.Errorf("scrubLicenseKey(plain) returned a different error: %v", got)
	}
}

func TestDownloadMMDB_CancelsOnContextCancel(t *testing.T) {
	// Server holds the response open until the connection drops, simulating a
	// slow MaxMind download. The test cancels ctx; downloadMMDB must abort
	// promptly via the request context, not wait for the http.Client timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	saved := maxmindDownloadURL
	maxmindDownloadURL = srv.URL + "/?edition_id=%s&license_key=%s&suffix=tar.gz"
	t.Cleanup(func() { maxmindDownloadURL = saved })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call so the request is born already-dead

	client := &http.Client{Timeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() {
		_, _, _, err := downloadMMDB(ctx, client, "GeoLite2-City", "test-key", t.TempDir())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from canceled context")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want errors.Is(context.Canceled)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("downloadMMDB did not honor canceled context within 2s")
	}
}
