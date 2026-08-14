package domain

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
	"go.uber.org/zap"
)

// DefaultMaxPNGBytes is the default maximum size for a screenshot PNG (5 MB).
var DefaultMaxPNGBytes = 5 << 20

// ChromiumProvider captures screenshots with a headless Chromium in this
// process. It is the default provider and the only one that needs no external
// service, at the cost of a browser's worth of memory per concurrent capture.
type ChromiumProvider struct{}

// NewChromiumProvider returns the in-process Chromium provider.
func NewChromiumProvider() *ChromiumProvider { return &ChromiumProvider{} }

func (p *ChromiumProvider) Name() string { return "chromium" }

// Capture navigates to target in headless Chromium and captures a PNG. It tries
// HTTPS first, falling back to HTTP. Only a 200 triggers an actual capture;
// other status codes are reported without image data, which is how a parked or
// dead domain — the common case when triaging typosquats — is distinguished
// from a capture that failed.
func (p *ChromiumProvider) Capture(ctx context.Context, target string, opts ScreenshotOptions) (*ScreenshotInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout(DefaultScreenshotTimeout))
	defer cancel()

	url, code, err := probeURL(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("screenshot probe: %w", err)
	}

	// The probe is what keeps bulk triage affordable: a domain that does not
	// answer never costs a browser launch.
	if code != http.StatusOK {
		return &ScreenshotInfo{StatusCode: code}, nil
	}

	png, err := captureScreenshot(ctx, url, opts)
	if err != nil {
		return nil, fmt.Errorf("screenshot capture: %w", err)
	}

	if limit := opts.maxBytes(); len(png) > limit {
		return nil, fmt.Errorf("screenshot too large: %d bytes exceeds %d byte limit", len(png), limit)
	}

	return &ScreenshotInfo{
		StatusCode: code,
		PNG:        base64.StdEncoding.EncodeToString(png),
	}, nil
}

// LookupScreenshot captures with the default Chromium provider. Retained for
// callers that predate the provider interface.
func LookupScreenshot(ctx context.Context, domain string, timeout time.Duration, maxPNGBytes int) (*ScreenshotInfo, error) {
	return NewChromiumProvider().Capture(ctx, domain, ScreenshotOptions{
		Timeout:     timeout,
		MaxPNGBytes: maxPNGBytes,
	})
}

// probeURL checks HTTPS then HTTP and returns the working URL and status code.
func probeURL(ctx context.Context, domain string) (string, int, error) {
	// probeURL validates the resolved IP before Chrome navigates. Chrome traffic
	// is also routed through a safe proxy (see captureScreenshot), so this serves
	// as an early rejection to avoid launching Chrome for obviously-blocked targets.
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: safeTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + domain
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "IntelligenceAPI/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if err := resp.Body.Close(); err != nil {
			logging.Logger().Debug("screenshot probe response close failed", zap.Error(err))
		}
		return u, resp.StatusCode, nil
	}

	return "", 0, fmt.Errorf("domain unreachable via HTTPS and HTTP")
}

// wsURLReadTimeout decides how long to wait for Chrome to announce its DevTools
// URL on startup, returning false to leave chromedp's own default in place.
//
// chromedp caps that wait at a fixed 20s and watches only its own timer, never
// the context (see its allocate.go). The cap is therefore a wall the caller
// cannot move in either direction, and both directions are wrong for us. Our
// screenshot timeout defaults to 15s, so a slow launch overruns the configured
// budget by 20s while holding one of only screenshot.max_concurrent Chromium
// slots; conversely a generous budget cannot buy a cold or CPU-starved machine
// the extra seconds it needs. Handing chromedp whatever remains of the deadline
// makes the screenshot timeout the single authority over how long a capture may
// take. A deadline already passed yields a non-positive duration, which fires
// immediately — the correct answer for a budget that is already spent.
func wsURLReadTimeout(ctx context.Context) (time.Duration, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, false
	}
	return time.Until(deadline), true
}

// captureScreenshot launches headless Chrome behind a local SSRF-safe proxy
// and takes a full-page screenshot. All Chrome network traffic is routed through
// the proxy, which blocks connections to private/reserved IP ranges.
func captureScreenshot(ctx context.Context, url string, opts ScreenshotOptions) ([]byte, error) {
	proxy, ln, err := safenet.NewSafeProxy()
	if err != nil {
		return nil, fmt.Errorf("start safe proxy: %w", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			logging.Logger().Warn("safe proxy close failed", zap.Error(err))
		}
	}()

	width, height := opts.viewport()
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(width, height),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		// Containers get a 64MB /dev/shm by default. Chromium assumes far more
		// and crashes or hangs when it runs out, which surfaces as a startup
		// timeout rather than as anything mentioning shared memory. Writing to
		// /tmp instead is slower but survives a small container.
		chromedp.Flag("disable-dev-shm-usage", true),
		// Trim work that a one-shot capture never benefits from. Each is small;
		// together they matter on a machine sized for the API rather than for a
		// browser.
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-software-rasterizer", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-first-run", true),
		chromedp.ProxyServer("http://"+ln.Addr().String()),
		// Chromium bypasses the proxy for loopback and link-local addresses by
		// default, so ProxyServer alone does not contain it: a page that passed
		// the pre-flight probe can redirect to 127.0.0.1 or 169.254.169.254 and
		// Chrome dials it directly, around every check safenet makes.
		// "<-loopback>" removes that implicit bypass so everything is proxied.
		// See https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
	)

	if d, ok := wsURLReadTimeout(ctx); ok {
		allocOpts = append(allocOpts, chromedp.WSURLReadTimeout(d))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()

	chromeCtx, chromeCancel := chromedp.NewContext(allocCtx)
	defer chromeCancel()

	var buf []byte
	if err := chromedp.Run(chromeCtx,
		chromedp.Navigate(url),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return nil, err
	}

	return buf, nil
}
