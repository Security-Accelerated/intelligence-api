package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// LookupReverseDNS performs a PTR lookup for the given IP address and returns
// the associated hostnames.
func LookupReverseDNS(ctx context.Context, ip string) (*ReverseDNSInfo, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("ptr lookup: %w", err)
	}

	// LookupAddr returns FQDNs with trailing dots; strip them for consistency.
	hostnames := make([]string, 0, len(names))
	for _, name := range names {
		hostnames = append(hostnames, strings.TrimSuffix(name, "."))
	}

	return &ReverseDNSInfo{Hostnames: hostnames}, nil
}
