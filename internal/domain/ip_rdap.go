package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// RIR RDAP endpoints — queried directly to avoid rdap.org bootstrap rate limits.
var rirEndpoints = map[string]string{
	"arin":    "https://rdap.arin.net/registry/ip/",
	"ripe":    "https://rdap.db.ripe.net/ip/",
	"apnic":   "https://rdap.apnic.net/ip/",
	"lacnic":  "https://rdap.lacnic.net/rdap/ip/",
	"afrinic": "https://rdap.afrinic.net/rdap/ip/",
}

// rdapLimiter is a global safety net that limits total RDAP request volume
// across all RIR endpoints to avoid overwhelming upstream services under load.
var rdapLimiter = rate.NewLimiter(rate.Limit(10), 5) // 10 req/s, burst of 5

// rdapResponse is a minimal subset of the RDAP IP Network response.
type rdapResponse struct {
	Handle    string       `json:"handle"`
	Name      string       `json:"name"`
	Country   string       `json:"country"`
	StartAddr string       `json:"startAddress"`
	EndAddr   string       `json:"endAddress"`
	Entities  []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles    []string     `json:"roles"`
	VCards   []any        `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
}

// LookupAbuseContact queries the appropriate RIR's RDAP endpoint for the IP
// network and extracts the abuse contact information.
func LookupAbuseContact(ctx context.Context, ip string) (*AbuseContactInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := rdapLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rdap rate limit: %w", err)
	}

	endpoint := rirEndpointForIP(ip)
	client := &http.Client{Transport: trustedTransport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+ip, nil)
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

	info.Email = findAbuseEmail(rdap.Entities)

	return info, nil
}

// rirEndpointForIP returns the RDAP endpoint URL for the RIR responsible for
// the given IP address. Uses a simplified first-octet heuristic based on IANA
// allocations. Falls back to ARIN for unrecognized ranges.
func rirEndpointForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return rirEndpoints["arin"]
	}

	// IPv6 — simplified mapping
	if parsed.To4() == nil {
		return rirEndpoints["arin"]
	}

	first := parsed.To4()[0]

	// Approximate IANA allocation by first octet.
	// These cover the major ranges; edge cases fall back to ARIN.
	switch {
	// RIPE NCC (Europe, Middle East, Central Asia)
	case first == 2,
		first >= 5 && first <= 5,
		first >= 25 && first <= 31,
		first >= 37 && first <= 37,
		first >= 46 && first <= 46,
		first >= 51 && first <= 51,
		first >= 62 && first <= 62,
		first >= 77 && first <= 95,
		first >= 141 && first <= 141,
		first >= 145 && first <= 145,
		first >= 151 && first <= 151,
		first >= 176 && first <= 176,
		first >= 178 && first <= 178,
		first >= 185 && first <= 185,
		first >= 188 && first <= 188,
		first >= 193 && first <= 195,
		first >= 212 && first <= 213,
		first >= 217 && first <= 217:
		return rirEndpoints["ripe"]

	// APNIC (Asia Pacific)
	case first == 1,
		first >= 14 && first <= 14,
		first >= 27 && first <= 27,
		first >= 36 && first <= 36,
		first >= 39 && first <= 39,
		first >= 42 && first <= 42,
		first >= 43 && first <= 43,
		first >= 49 && first <= 49,
		first >= 58 && first <= 58,
		first >= 59 && first <= 61,
		first >= 101 && first <= 101,
		first >= 103 && first <= 103,
		first >= 106 && first <= 106,
		first >= 110 && first <= 112,
		first >= 113 && first <= 126,
		first >= 133 && first <= 133,
		first >= 150 && first <= 150,
		first >= 153 && first <= 153,
		first >= 163 && first <= 163,
		first >= 175 && first <= 175,
		first >= 180 && first <= 183,
		first >= 202 && first <= 203,
		first >= 210 && first <= 211,
		first >= 218 && first <= 223:
		return rirEndpoints["apnic"]

	// LACNIC (Latin America, Caribbean)
	case first >= 177 && first <= 177,
		first >= 179 && first <= 179,
		first >= 181 && first <= 181,
		first >= 186 && first <= 187,
		first >= 189 && first <= 191,
		first >= 200 && first <= 201:
		return rirEndpoints["lacnic"]

	// AFRINIC (Africa)
	case first >= 41 && first <= 41,
		first >= 102 && first <= 102,
		first >= 105 && first <= 105,
		first >= 154 && first <= 154,
		first >= 196 && first <= 197:
		return rirEndpoints["afrinic"]

	// Default to ARIN (North America, some others)
	default:
		return rirEndpoints["arin"]
	}
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
		if email := findAbuseEmail(entity.Entities); email != "" {
			return email
		}
	}
	return ""
}

// extractEmailFromVCard extracts an email address from a jCard (RFC 7095)
// vcardArray.
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
