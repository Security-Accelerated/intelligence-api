package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

const (
	// crtShCTURL queries crt.sh for the exact domain (not wildcard).
	// Subdomains use "%.domain" — CT logs use the bare domain for full cert metadata.
	crtShCTURL = "https://crt.sh/?q=%s&output=json"
)

// CTLogsHTTPTimeout bounds the whole crt.sh request including body read.
// Overridable via config (ct_logs.http_timeout), set in app bootstrap.
var CTLogsHTTPTimeout = 15 * time.Second

// crtShCTEntry is the structure returned by crt.sh JSON API with full cert details.
type crtShCTEntry struct {
	ID             int    `json:"id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// LookupCTLogs queries Certificate Transparency logs via crt.sh for all
// certificates issued for the given domain. Results are deduplicated by serial
// number and sorted newest-first by entry timestamp. maxEntries caps the output.
func LookupCTLogs(ctx context.Context, domainName string, maxEntries int) (*CTLogsInfo, error) {
	url := fmt.Sprintf(crtShCTURL, domainName)

	client := &http.Client{
		Transport: trustedTransport,
		// End-to-end cap: the transport's dial timeout doesn't bound a
		// stalled response body, which would otherwise hold the request
		// until the whole lookup deadline.
		Timeout: CTLogsHTTPTimeout,
	}

	body, err := fetchCrtSh(ctx, client, url, "IntelligenceAPI/1.0", MaxResponseBody)
	if err != nil {
		// No certificates is an empty result, not a failure — see subdomain.go.
		if errors.Is(err, crtShNoResults) {
			return &CTLogsInfo{Count: 0, Entries: []CTLogEntry{}}, nil
		}
		return nil, fmt.Errorf("ct_logs: %w", err)
	}

	var raw []crtShCTEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ct_logs: parse response: %w", err)
	}

	entries := dedupCTEntries(raw)

	// Sort newest-first by entry timestamp.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LoggedAt > entries[j].LoggedAt
	})

	capped := false
	if maxEntries > 0 && len(entries) > maxEntries {
		entries = entries[:maxEntries]
		capped = true
	}

	return &CTLogsInfo{
		Count:   len(entries),
		Capped:  capped,
		Entries: entries,
	}, nil
}

// dedupCTEntries deduplicates crt.sh results by serial number, keeping the
// first occurrence of each serial.
func dedupCTEntries(raw []crtShCTEntry) []CTLogEntry {
	seen := make(map[string]struct{})
	var entries []CTLogEntry

	for _, r := range raw {
		if r.SerialNumber == "" {
			continue
		}
		if _, ok := seen[r.SerialNumber]; ok {
			continue
		}
		seen[r.SerialNumber] = struct{}{}

		entries = append(entries, CTLogEntry{
			LoggedAt:   r.EntryTimestamp,
			NotBefore:  r.NotBefore,
			NotAfter:   r.NotAfter,
			Issuer:     r.IssuerName,
			CommonName: r.CommonName,
			NameValue:  r.NameValue,
			Serial:     r.SerialNumber,
		})
	}

	return entries
}
