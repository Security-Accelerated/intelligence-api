package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const crtShURL = "https://crt.sh/?q=%%.%s&output=json"

// MaxResponseBody is the maximum response body size for crt.sh API calls,
// shared by subdomain and CT log lookups. Set from config at startup.
var MaxResponseBody int64 = 10 << 20 // 10 MB default

// SubdomainHTTPTimeout bounds the whole crt.sh request including body read.
// Overridable via config (subdomain.http_timeout), set in app bootstrap.
var SubdomainHTTPTimeout = 15 * time.Second

// crtShEntry is the minimal structure returned by the crt.sh JSON API.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// LookupSubdomains queries Certificate Transparency logs via crt.sh for
// subdomains of the given domain. It deduplicates, filters wildcards, and
// caps results at opts.MaxResults.
func LookupSubdomains(ctx context.Context, domainName string, opts SubdomainOptions) (*SubdomainInfo, error) {
	url := fmt.Sprintf(crtShURL, domainName)

	client := &http.Client{
		Transport: trustedTransport,
		// End-to-end cap: the transport's dial timeout doesn't bound a
		// stalled response body, which would otherwise hold the request
		// until the whole lookup deadline.
		Timeout: SubdomainHTTPTimeout,
	}

	body, err := fetchCrtSh(ctx, client, url, "IntelligenceAPI/1.0", MaxResponseBody)
	if err != nil {
		// A name with no certificates is a successful empty answer, not a
		// failure. That is the common case when triaging a freshly registered
		// typosquat domain — exactly when the answer matters most.
		if errors.Is(err, crtShNoResults) {
			return &SubdomainInfo{Count: 0, Subdomains: []SubdomainEntry{}}, nil
		}
		return nil, err
	}

	subdomains, err := parseCrtShResponse(body, domainName)
	if err != nil {
		// Distinguish "crt.sh knows of no subdomains" from "we could not read
		// the answer". Both used to produce an empty list cached for 24 hours.
		if int64(len(body)) >= MaxResponseBody {
			return nil, fmt.Errorf("crt.sh response exceeded the %d byte limit and was truncated: %w", MaxResponseBody, err)
		}
		return nil, fmt.Errorf("parse crt.sh response: %w", err)
	}

	capped := false
	if opts.MaxResults > 0 && len(subdomains) > opts.MaxResults {
		subdomains = subdomains[:opts.MaxResults]
		capped = true
	}

	entries := make([]SubdomainEntry, len(subdomains))
	for i, sd := range subdomains {
		entries[i] = SubdomainEntry{
			Domain: sd,
			Source: "crt.sh",
		}
	}

	return &SubdomainInfo{
		Count:      len(entries),
		Capped:     capped,
		Subdomains: entries,
	}, nil
}

// parseCrtShResponse extracts unique subdomain names from crt.sh JSON output.
// It filters wildcards, the base domain itself, and sorts alphabetically.
func parseCrtShResponse(data []byte, baseDomain string) ([]string, error) {
	var entries []crtShEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	base := strings.ToLower(baseDomain)

	for _, e := range entries {
		// crt.sh can return multiple names separated by newlines
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			// Skip wildcards
			if strings.HasPrefix(name, "*.") {
				continue
			}
			// Skip the base domain itself
			if name == base {
				continue
			}
			// Must be a subdomain of the base domain
			if !strings.HasSuffix(name, "."+base) {
				continue
			}
			seen[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}
