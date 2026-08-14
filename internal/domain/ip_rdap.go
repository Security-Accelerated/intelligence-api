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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+ip, http.NoBody)
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

// rirOctetRanges approximates the IANA allocation table by first octet, as an
// ordered list of inclusive ranges. It is data rather than control flow
// because it is a table: written as a switch it was fifty-eight branches of
// `first >= n && first <= n`, which said nothing the numbers do not.
//
// Order is significant: the first match wins, exactly as the switch's case
// order did. Two entries are shadowed by an earlier broader range and are
// therefore unreachable, which is pre-existing and is preserved here rather
// than fixed, so that this change stays a provable no-op:
//
//	27  is claimed by RIPE's 25-31, though IANA allocated 27.0.0.0/8 to APNIC
//	181 is claimed by APNIC's 180-183, though 181.0.0.0/8 belongs to LACNIC
//
// Correcting them changes which RIR is queried for an abuse contact in those
// two /8s, so it belongs in its own change with its own reasoning. See the
// collision cases in TestRIREndpointForIP, which pin today's answers.
var rirOctetRanges = []struct {
	lo, hi byte
	rir    string
}{
	// RIPE NCC (Europe, Middle East, Central Asia)
	{2, 2, "ripe"}, {5, 5, "ripe"}, {25, 31, "ripe"}, {37, 37, "ripe"},
	{46, 46, "ripe"}, {51, 51, "ripe"}, {62, 62, "ripe"}, {77, 95, "ripe"},
	{141, 141, "ripe"}, {145, 145, "ripe"}, {151, 151, "ripe"},
	{176, 176, "ripe"}, {178, 178, "ripe"}, {185, 185, "ripe"},
	{188, 188, "ripe"}, {193, 195, "ripe"}, {212, 213, "ripe"},
	{217, 217, "ripe"},

	// APNIC (Asia Pacific)
	{1, 1, "apnic"}, {14, 14, "apnic"}, {27, 27, "apnic"}, {36, 36, "apnic"},
	{39, 39, "apnic"}, {42, 43, "apnic"}, {49, 49, "apnic"}, {58, 61, "apnic"},
	{101, 101, "apnic"}, {103, 103, "apnic"}, {106, 106, "apnic"},
	{110, 126, "apnic"}, {133, 133, "apnic"}, {150, 150, "apnic"},
	{153, 153, "apnic"}, {163, 163, "apnic"}, {175, 175, "apnic"},
	{180, 183, "apnic"}, {202, 203, "apnic"}, {210, 211, "apnic"},
	{218, 223, "apnic"},

	// LACNIC (Latin America, Caribbean)
	{177, 177, "lacnic"}, {179, 179, "lacnic"}, {181, 181, "lacnic"},
	{186, 187, "lacnic"}, {189, 191, "lacnic"}, {200, 201, "lacnic"},

	// AFRINIC (Africa)
	{41, 41, "afrinic"}, {102, 102, "afrinic"}, {105, 105, "afrinic"},
	{154, 154, "afrinic"}, {196, 197, "afrinic"},
}

// rirEndpointForIP returns the RDAP endpoint URL for the RIR responsible for
// the given IP address. Uses a simplified first-octet heuristic based on IANA
// allocations. Falls back to ARIN for unrecognized ranges, for IPv6, and for
// anything that does not parse.
func rirEndpointForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return rirEndpoints["arin"]
	}

	v4 := parsed.To4()
	if v4 == nil {
		return rirEndpoints["arin"]
	}

	first := v4[0]
	for _, r := range rirOctetRanges {
		if first >= r.lo && first <= r.hi {
			return rirEndpoints[r.rir]
		}
	}

	return rirEndpoints["arin"]
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
