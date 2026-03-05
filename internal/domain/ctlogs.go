package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

const (
	// crtShCTURL queries crt.sh for the exact domain (not wildcard).
	// Subdomains use "%.domain" — CT logs use the bare domain for full cert metadata.
	crtShCTURL = "https://crt.sh/?q=%s&output=json"
)

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ct_logs: create request: %w", err)
	}
	req.Header.Set("User-Agent", "IntelligenceAPI/1.0")

	client := &http.Client{
		Transport: safeTransport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ct_logs: crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ct_logs: crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("ct_logs: read response: %w", err)
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
