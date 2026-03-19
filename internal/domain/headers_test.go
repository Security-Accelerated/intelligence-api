package domain

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// swapTransport replaces safeTransport for the duration of the test and
// restores it via t.Cleanup. Since tests in the same package run serially
// by default (and -race will flag genuine data races), this is safe.
func swapTransport(t *testing.T, tr http.RoundTripper) {
	t.Helper()
	orig := safeTransport
	safeTransport = tr.(*http.Transport)
	t.Cleanup(func() { safeTransport = orig })
}

// testTransportFor returns an *http.Transport that routes all requests to
// the given httptest.Server, skipping TLS verification.
func testTransportFor(srv *httptest.Server) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Override DialContext so that any host:port resolves to the test server.
		DialContext: srv.Client().Transport.(*http.Transport).DialContext,
	}
}

func TestLookupHeaders_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "hello")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Build a transport that directs everything to the test server.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	swapTransport(t, tr)

	// LookupHeaders constructs "https://<domain>" — we need the domain to
	// resolve to our test server. Parse the server URL to get host:port.
	u, _ := url.Parse(srv.URL)

	info, err := LookupHeaders(context.Background(), u.Host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", info.StatusCode, http.StatusOK)
	}
	if got := info.Headers["X-Custom"]; got != "hello" {
		t.Errorf("Headers[X-Custom] = %q, want %q", got, "hello")
	}
	if got := info.Headers["Content-Type"]; got != "text/html" {
		t.Errorf("Headers[Content-Type] = %q, want %q", got, "text/html")
	}
}

func TestLookupHeaders_SecurityHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Xss-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	swapTransport(t, tr)

	u, _ := url.Parse(srv.URL)
	info, err := LookupHeaders(context.Background(), u.Host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecurityHeaders == nil {
		t.Fatal("SecurityHeaders is nil")
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"StrictTransportSecurity", info.SecurityHeaders.StrictTransportSecurity, "max-age=31536000; includeSubDomains"},
		{"ContentSecurityPolicy", info.SecurityHeaders.ContentSecurityPolicy, "default-src 'self'"},
		{"XFrameOptions", info.SecurityHeaders.XFrameOptions, "DENY"},
		{"XContentTypeOptions", info.SecurityHeaders.XContentTypeOptions, "nosniff"},
		{"XXSSProtection", info.SecurityHeaders.XXSSProtection, "1; mode=block"},
		{"ReferrerPolicy", info.SecurityHeaders.ReferrerPolicy, "strict-origin"},
		{"PermissionsPolicy", info.SecurityHeaders.PermissionsPolicy, "camera=()"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestLookupHeaders_HTTPFallback(t *testing.T) {
	// Start a plain HTTP server (no TLS). LookupHeaders tries HTTPS first,
	// which will fail, then falls back to HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fallback", "yes")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use a transport that connects to the test server but does NOT support TLS
	// on the server side, so the HTTPS attempt will fail and trigger fallback.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	swapTransport(t, tr)

	u, _ := url.Parse(srv.URL)
	info, err := LookupHeaders(context.Background(), u.Host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", info.StatusCode, http.StatusOK)
	}
	if got := info.Headers["X-Fallback"]; got != "yes" {
		t.Errorf("Headers[X-Fallback] = %q, want %q", got, "yes")
	}
}

func TestLookupHeaders_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	info, err := LookupHeaders(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if info != nil {
		t.Errorf("expected nil info for cancelled context, got %+v", info)
	}
}

func TestLookupHeaders_NoRedirectFollow(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	swapTransport(t, tr)

	u, _ := url.Parse(srv.URL)
	info, err := LookupHeaders(context.Background(), u.Host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should capture the redirect status, not follow it.
	if info.StatusCode != http.StatusMovedPermanently {
		t.Errorf("StatusCode = %d, want %d (should not follow redirects)", info.StatusCode, http.StatusMovedPermanently)
	}
	if got := info.Headers["Location"]; got == "" {
		t.Error("expected Location header in redirect response")
	}
}

func TestLookupHeaders_UserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	swapTransport(t, tr)

	u, _ := url.Parse(srv.URL)
	_, err := LookupHeaders(context.Background(), u.Host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotUA != "IntelligenceAPI/1.0" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "IntelligenceAPI/1.0")
	}
}
