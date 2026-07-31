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

// LookupScreenshot navigates to the domain in headless Chrome and captures a
// PNG screenshot. It tries HTTPS first, falling back to HTTP. Only a 200 OK
// triggers an actual screenshot capture; other status codes are recorded
// without image data. The timeout parameter controls the deadline for the
// entire operation (probe + capture). maxPNGBytes limits the captured image size.
func LookupScreenshot(ctx context.Context, domain string, timeout time.Duration, maxPNGBytes int) (*ScreenshotInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url, code, err := probeURL(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("screenshot probe: %w", err)
	}

	if code != http.StatusOK {
		return &ScreenshotInfo{StatusCode: code}, nil
	}

	png, err := captureScreenshot(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("screenshot capture: %w", err)
	}

	if len(png) > maxPNGBytes {
		return nil, fmt.Errorf("screenshot too large: %d bytes exceeds %d byte limit", len(png), maxPNGBytes)
	}

	return &ScreenshotInfo{
		StatusCode: code,
		PNG:        base64.StdEncoding.EncodeToString(png),
	}, nil
}

// probeURL checks HTTPS then HTTP and returns the working URL and status code.
func probeURL(ctx context.Context, domain string) (string, int, error) {
	// probeURL validates the resolved IP before Chrome navigates. Chrome traffic
	// is also routed through a safe proxy (see captureScreenshot), so this serves
	// as an early rejection to avoid launching Chrome for obviously-blocked targets.
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: safeTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + domain
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
func captureScreenshot(ctx context.Context, url string) ([]byte, error) {
	proxy, ln, err := safenet.NewSafeProxy()
	if err != nil {
		return nil, fmt.Errorf("start safe proxy: %w", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			logging.Logger().Warn("safe proxy close failed", zap.Error(err))
		}
	}()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1280, 720),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
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
		opts = append(opts, chromedp.WSURLReadTimeout(d))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
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
