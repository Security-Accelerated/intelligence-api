package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

func LookupHeaders(ctx context.Context, domain string) (*HeadersInfo, error) {
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

	var resp *http.Response
	var err error

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "IntelligenceAPI/1.0")

	resp, err = client.Do(req)
	if err != nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", "IntelligenceAPI/1.0")

		resp, err = client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("http request: %w", err)
		}
	}
	defer resp.Body.Close()

	headers := make(map[string]string, len(resp.Header))
	for key := range resp.Header {
		headers[key] = resp.Header.Get(key)
	}

	info := &HeadersInfo{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		SecurityHeaders: &SecurityHeaders{
			StrictTransportSecurity: resp.Header.Get("Strict-Transport-Security"),
			ContentSecurityPolicy:   resp.Header.Get("Content-Security-Policy"),
			XFrameOptions:           resp.Header.Get("X-Frame-Options"),
			XContentTypeOptions:     resp.Header.Get("X-Content-Type-Options"),
			XXSSProtection:          resp.Header.Get("X-Xss-Protection"),
			ReferrerPolicy:          resp.Header.Get("Referrer-Policy"),
			PermissionsPolicy:       resp.Header.Get("Permissions-Policy"),
		},
	}

	return info, nil
}
