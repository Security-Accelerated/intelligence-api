package domain

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

const maxPNGBytes = 5 << 20 // 5 MB

// LookupScreenshot navigates to the domain in headless Chrome and captures a
// PNG screenshot. It tries HTTPS first, falling back to HTTP. Only a 200 OK
// triggers an actual screenshot capture; other status codes are recorded
// without image data. The timeout parameter controls the deadline for the
// entire operation (probe + capture).
func LookupScreenshot(ctx context.Context, domain string, timeout time.Duration) (*ScreenshotInfo, error) {
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
	// probeURL validates the resolved IP before Chrome navigates. Chrome does its
	// own DNS resolution so there is a narrow theoretical DNS-rebinding window,
	// but this is best-effort defence-in-depth for the screenshot path.
	// InsecureSkipVerify is intentional: the screenshot probe must reach targets
	// with invalid certificates. The SSL lookup reports certificate validity separately.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     safenet.SafeDialer(10 * time.Second).DialContext,
		},
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

// captureScreenshot launches headless Chrome and takes a full-page screenshot.
func captureScreenshot(ctx context.Context, url string) ([]byte, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1280, 720),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
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
