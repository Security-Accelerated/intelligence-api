package domain

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
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
		resp.Body.Close()
		return u, resp.StatusCode, nil
	}

	return "", 0, fmt.Errorf("domain unreachable via HTTPS and HTTP")
}

// captureScreenshot launches headless Chrome behind a local SSRF-safe proxy
// and takes a full-page screenshot. All Chrome network traffic is routed through
// the proxy, which blocks connections to private/reserved IP ranges.
func captureScreenshot(ctx context.Context, url string) ([]byte, error) {
	proxy, ln, err := safenet.NewSafeProxy()
	if err != nil {
		return nil, fmt.Errorf("start safe proxy: %w", err)
	}
	defer proxy.Close()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1280, 720),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.ProxyServer("http://"+ln.Addr().String()),
	)

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
