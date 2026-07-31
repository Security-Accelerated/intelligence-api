package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultHost is the production API. Every HTTP command takes --host, so
// pointing the CLI at a local instance is one flag.
const defaultHost = "https://api.securityaccelerated.com"

// maxAPIResponse bounds what the CLI will read from a response body. Without it
// a misrouted request returning an endless stream would be buffered in full.
const maxAPIResponse = 8 << 20

// apiFlags are shared by every command that talks to the running API.
type apiFlags struct {
	host    string
	key     string
	timeout time.Duration
	jsonOut bool
}

func registerAPIFlags(fs *flag.FlagSet) *apiFlags {
	f := &apiFlags{}
	fs.StringVar(&f.host, "host", defaultHost, "API base URL")
	fs.StringVar(&f.key, "key", "", "admin API key; defaults to $SMOKE_ADMIN_KEY")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "per-request timeout")
	fs.BoolVar(&f.jsonOut, "json", false, "emit raw JSON instead of a rendered table")
	return f
}

// adminKey resolves the key to use, preferring the flag over the environment.
func (f *apiFlags) adminKey() (string, error) {
	if k := strings.TrimSpace(f.key); k != "" {
		return k, nil
	}
	if k := strings.TrimSpace(os.Getenv("SMOKE_ADMIN_KEY")); k != "" {
		return k, nil
	}
	return "", errors.New("no admin key: pass --key or set SMOKE_ADMIN_KEY (see --env-file)")
}

func (f *apiFlags) client() *http.Client {
	return &http.Client{
		Timeout: f.timeout,
		// Redirects are part of the contract, not something to follow past.
		// The default client follows a 301 and reports the destination's 200,
		// which made an assertion that GET / redirects pass whether or not the
		// redirect existed.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getJSON performs an authenticated GET and decodes the body into out.
func (f *apiFlags) getJSON(ctx context.Context, path string, out any) error {
	key, err := f.adminKey()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(f.host, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", key)

	resp, err := f.client().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		// Surface the API's own error message rather than only the status.
		// "401" alone does not distinguish a missing key from a revoked one.
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// probe issues an unauthenticated request and returns the status code, for the
// reachability checks in `sactl status`.
func (f *apiFlags) probe(ctx context.Context, method, path string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(f.host, "/")+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAPIResponse))
	return resp.StatusCode, nil
}

// postJSON performs an authenticated POST and returns the raw body.
func (f *apiFlags) postJSON(ctx context.Context, path string, body any) ([]byte, error) {
	key, err := f.adminKey()
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimHost(f.host)+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)

	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
			return nil, fmt.Errorf("POST %s: HTTP %d: %s", path, resp.StatusCode, apiErr.Error)
		}
		return nil, fmt.Errorf("POST %s: HTTP %d", path, resp.StatusCode)
	}
	return raw, nil
}

// postNoBody performs an authenticated POST with no request body, for admin
// actions that take none.
func (f *apiFlags) postNoBody(ctx context.Context, path string) error {
	key, err := f.adminKey()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimHost(f.host)+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", key)

	resp, err := f.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: HTTP %d: %s", path, resp.StatusCode,
			truncate(strings.TrimSpace(string(raw)), 120))
	}
	return nil
}
