package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RDAP bootstrap URL for IP lookups. IANA's bootstrap redirects to the
// appropriate RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
const rdapBootstrapURL = "https://rdap.org/ip/"

// rdapResponse is a minimal subset of the RDAP IP Network response.
type rdapResponse struct {
	Handle   string       `json:"handle"`
	Name     string       `json:"name"`
	Country  string       `json:"country"`
	StartAddr string      `json:"startAddress"`
	EndAddr   string      `json:"endAddress"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles  []string     `json:"roles"`
	VCards []any `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
}

// LookupAbuseContact queries RDAP for the IP network and extracts the abuse
// contact information. Uses safeTransport for SSRF protection.
func LookupAbuseContact(ctx context.Context, ip string) (*AbuseContactInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := &http.Client{Transport: safeTransport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBootstrapURL+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("build rdap request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap returned HTTP %d", resp.StatusCode)
	}

	var rdap rdapResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rdap); err != nil {
		return nil, fmt.Errorf("decode rdap response: %w", err)
	}

	info := &AbuseContactInfo{
		Organization: rdap.Name,
		Country:      rdap.Country,
	}

	if rdap.StartAddr != "" && rdap.EndAddr != "" {
		info.Network = rdap.StartAddr + " - " + rdap.EndAddr
	}

	// Find the abuse contact email by searching entities with "abuse" role
	info.Email = findAbuseEmail(rdap.Entities)

	return info, nil
}

// findAbuseEmail recursively searches RDAP entities for one with the "abuse"
// role and extracts the email from its vCard data.
func findAbuseEmail(entities []rdapEntity) string {
	for _, entity := range entities {
		for _, role := range entity.Roles {
			if role == "abuse" {
				if email := extractEmailFromVCard(entity.VCards); email != "" {
					return email
				}
			}
		}
		// Entities can be nested
		if email := findAbuseEmail(entity.Entities); email != "" {
			return email
		}
	}
	return ""
}

// extractEmailFromVCard extracts an email address from a jCard (RFC 7095)
// vcardArray. The format is [["vcard", [["version", {}, "text", "4.0"], ["email", {}, "text", "abuse@example.com"], ...]]]
func extractEmailFromVCard(vcards []any) string {
	if len(vcards) < 2 {
		return ""
	}
	props, ok := vcards[1].([]any)
	if !ok {
		return ""
	}
	for _, prop := range props {
		arr, ok := prop.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		name, ok := arr[0].(string)
		if !ok || name != "email" {
			continue
		}
		if email, ok := arr[3].(string); ok {
			return email
		}
	}
	return ""
}
