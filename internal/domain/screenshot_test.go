package domain

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// chromeAvailable ensures a Chrome/Chromium binary chromedp can drive is on
// PATH. It skips locally when there is none, so contributors without a browser
// can still run the suite.
//
// REQUIRE_CHROME=1 turns the skip into a failure. CI sets it, because a skipped
// SSRF regression test is indistinguishable from a passing one in the summary:
// the gate would go green having never launched a browser. Provisioning Chrome
// on the runner and demanding it be there are two halves of the same guarantee.
func chromeAvailable(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "headless_shell"} {
		if _, err := exec.LookPath(bin); err == nil {
			return
		}
	}
	if os.Getenv("REQUIRE_CHROME") != "" {
		t.Fatal("REQUIRE_CHROME is set but no Chrome/Chromium binary is on PATH — " +
			"the screenshot SSRF regression test cannot run, and silently skipping it would leave the gate green")
	}
	t.Skip("no Chrome/Chromium binary on PATH (set REQUIRE_CHROME=1 to make this fatal)")
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

	// Generous on purpose. This budget is not measuring performance — it only
	// has to outlast a cold Chrome launch on a contended CI runner, which has
	// been observed taking over 20s while the rest of the suite saturates the
	// box. Failing here proves nothing about containment and only costs a red
	// build, so the deadline is set well clear of the slowest plausible start.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	png, err := captureScreenshot(ctx, target)

	// Positive control, asserted before containment. hits == 0 is only
	// meaningful if Chrome actually launched and navigated: had the browser
	// failed to start, or the proxy failed to bind, the origin would also see
	// nothing and the containment check would pass while proving nothing.
	//
	// A blocked navigation still completes — Chrome renders its own error page
	// and screenshots that — so a nil error and a non-empty PNG together show
	// the whole path ran. That keeps the control offline; a public origin would
	// need network access, and a loopback one is blocked by SafeDialer.
	if err != nil {
		t.Fatalf("capture did not run to completion, so containment is unproven: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("capture returned no image, so containment is unproven")
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("loopback service received %d request(s) from Chrome — the SSRF proxy was bypassed; "+
			"a redirect to localhost or a cloud metadata endpoint would be screenshotted and returned", n)
	}
}
