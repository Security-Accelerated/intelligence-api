package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

const crtShURL = "https://crt.sh/?q=%%.%s&output=json"

// MaxResponseBody is the maximum response body size for crt.sh API calls,
// shared by subdomain and CT log lookups. Set from config at startup.
var MaxResponseBody int64 = 10 << 20 // 10 MB default

// crtShEntry is the minimal structure returned by the crt.sh JSON API.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// LookupSubdomains queries Certificate Transparency logs via crt.sh for
// subdomains of the given domain. It deduplicates, filters wildcards, and
// caps results at opts.MaxResults.
func LookupSubdomains(ctx context.Context, domainName string, opts SubdomainOptions) (*SubdomainInfo, error) {
	url := fmt.Sprintf(crtShURL, domainName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "IntelligenceAPI/1.0")

	client := &http.Client{
		Transport: safeTransport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read crt.sh response: %w", err)
	}

	subdomains := parseCrtShResponse(body, domainName)

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
func parseCrtShResponse(data []byte, baseDomain string) []string {
	var entries []crtShEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
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
	return result
}
