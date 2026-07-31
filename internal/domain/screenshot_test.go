package domain

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// chromeAvailable reports whether a Chrome/Chromium binary chromedp can drive
// is on PATH. The browser is present in the Docker image and on dev machines,
// but not necessarily in every CI runner.
func chromeAvailable(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "headless_shell"} {
		if _, err := exec.LookPath(bin); err == nil {
			return
		}
	}
	t.Skip("no Chrome/Chromium binary on PATH")
}

// TestCaptureScreenshot_CannotReachLoopback is the SSRF regression test for the
// screenshot lookup.
//
// Chrome is pointed at safenet's proxy, but Chromium *implicitly bypasses
// proxies for loopback and link-local addresses* unless the bypass list says
// otherwise. Without `--proxy-bypass-list=<-loopback>` a page that passes the
// pre-flight probe can redirect the browser to 127.0.0.1 or 169.254.169.254 and
// Chrome connects directly, straight around every check safenet makes.
//
// The assertion is deliberately "did the origin server receive a connection?"
// rather than anything about the returned image. A blocked navigation still
// produces a perfectly valid screenshot — of Chrome's own error page — so
// asserting on the PNG would pass whether or not the request escaped. Only the
// server's own view proves containment.
//
// Loopback stands in for link-local (169.254.169.254, the cloud metadata
// address) too: both are in Chromium's implicit bypass list and both are
// governed by the same flag, so this test fails the moment it is removed. A
// separate link-local test was tried and deleted — with nothing listening on
// that address and no way to observe the internal proxy, it passed whether
// Chrome was contained, blocked, or simply had no route, which is worse than
// no test at all.
func TestCaptureScreenshot_CannotReachLoopback(t *testing.T) {
	chromeAvailable(t)

	var hits atomic.Int32
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>INTERNAL SERVICE</h1></body></html>"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	target := "http://" + ln.Addr().String() + "/"

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// The capture itself may succeed (Chrome screenshots its error page) or
	// fail; either is acceptable. What must not happen is the loopback service
	// being contacted.
	_, _ = captureScreenshot(ctx, target)

	if n := hits.Load(); n != 0 {
		t.Errorf("loopback service received %d request(s) from Chrome — the SSRF proxy was bypassed; "+
			"a redirect to localhost or a cloud metadata endpoint would be screenshotted and returned", n)
	}
}
