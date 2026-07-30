package domain

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// LookupBGP resolves the domain to its A records, then queries Team Cymru's
// DNS-based IP-to-ASN mapping service for BGP/ASN information about each IP.
// Results are deduplicated by ASN (multiple IPs in the same ASN are merged,
// keeping the first IP seen).
func LookupBGP(ctx context.Context, domainName string) (*BGPInfo, error) {
	ips, err := net.DefaultResolver.LookupHost(ctx, domainName)
	if err != nil {
		return nil, fmt.Errorf("bgp: resolve domain: %w", err)
	}

	// Filter to IPv4 only — Cymru origin lookup uses reversed octets.
	var ipv4s []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}

	if len(ipv4s) == 0 {
		return &BGPInfo{Records: []ASNRecord{}}, nil
	}

	seenASN := make(map[int]struct{})
	var records []ASNRecord

	for _, ip := range ipv4s {
		record, err := lookupCymruOrigin(ctx, ip)
		if err != nil {
			continue // partial failure: skip this IP
		}

		// Deduplicate by ASN — multiple IPs often share an ASN.
		if _, ok := seenASN[record.ASN]; ok {
			continue
		}
		seenASN[record.ASN] = struct{}{}

		// Enrich with ASN description.
		desc, err := lookupCymruASName(ctx, record.ASN)
		if err == nil {
			record.Description = desc
		}

		records = append(records, *record)
	}

	if records == nil {
		records = []ASNRecord{}
	}

	return &BGPInfo{Records: records}, nil
}

// lookupCymruOrigin queries <reversed-ip>.origin.asn.cymru.com TXT to get
// ASN, prefix, country, and registry for the given IPv4 address.
//
// Response format: "ASN | Prefix | Country | Registry | Allocated"
// Example: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
func lookupCymruOrigin(ctx context.Context, ip string) (*ASNRecord, error) {
	reversed, ok := reverseIPv4(ip)
	if !ok {
		return nil, fmt.Errorf("bgp: invalid IPv4 address %q", ip)
	}

	name := reversed + ".origin.asn.cymru.com"
	txts, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("bgp: cymru origin lookup: %w", err)
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("bgp: no TXT record for %s", name)
	}

	return parseCymruOrigin(ip, txts[0])
}

// parseCymruOrigin parses "ASN | Prefix | CC | Registry | Date" into an ASNRecord.
func parseCymruOrigin(ip, txt string) (*ASNRecord, error) {
	parts := strings.SplitN(txt, "|", 5)
	if len(parts) < 4 {
		return nil, fmt.Errorf("bgp: unexpected cymru format: %q", txt)
	}

	asn, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("bgp: parse ASN: %w", err)
	}

	return &ASNRecord{
		IP:       ip,
		ASN:      asn,
		Prefix:   strings.TrimSpace(parts[1]),
		Country:  strings.TrimSpace(parts[2]),
		Registry: strings.TrimSpace(parts[3]),
	}, nil
}

// lookupCymruASName queries AS<number>.asn.cymru.com TXT to get the ASN
// description (organization name).
//
// Response format: "ASN | Country | Registry | Date | Description"
// Example: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
func lookupCymruASName(ctx context.Context, asn int) (string, error) {
	name := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		return "", fmt.Errorf("bgp: cymru AS name lookup: %w", err)
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("bgp: no TXT record for %s", name)
	}

	parts := strings.SplitN(txts[0], "|", 5)
	if len(parts) < 5 {
		return "", fmt.Errorf("bgp: unexpected cymru AS format: %q", txts[0])
	}

	return strings.TrimSpace(parts[4]), nil
}
