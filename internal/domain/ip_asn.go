package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// LookupIPASN returns the autonomous system announcing ip, via Team Cymru's
// DNS mapping service — the same source as the domain bgp lookup. Unlike a
// local database it needs no download, so it is available from the first
// request after a cold start; results are cached like any other network lookup.
func LookupIPASN(ctx context.Context, ip net.IP) (*IPASNInfo, error) {
	record, err := lookupCymruOrigin(ctx, ip.String())
	if err != nil {
		return nil, err
	}
	if record.ASN < 0 || record.ASN > 1<<32-1 {
		return nil, fmt.Errorf("cymru: AS number %d out of range", record.ASN)
	}

	info := &IPASNInfo{
		ASN:     uint32(record.ASN),
		Network: record.Prefix,
	}
	// A missing name is not a failed lookup: the number and prefix are the
	// substance, so an unnamed AS still returns them.
	if name, err := lookupCymruASName(ctx, record.ASN); err == nil {
		info.Organization = trimCountrySuffix(name)
	}
	return info, nil
}

// trimCountrySuffix drops the ", CC" country code Cymru appends to AS names
// ("GOOGLE - Google LLC, US" → "GOOGLE - Google LLC"). The country belongs to
// the registration, not the organization's name, and callers match on the name.
func trimCountrySuffix(name string) string {
	i := strings.LastIndex(name, ", ")
	if i < 0 || len(name)-i != 4 {
		return name
	}
	cc := name[i+2:]
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return name
	}
	return name[:i]
}
