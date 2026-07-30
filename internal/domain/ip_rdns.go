package domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// LookupReverseDNS performs a PTR lookup for the given IP address and returns
// the associated hostnames. Returns an empty result (not an error) when no PTR
// record exists, since many IPs legitimately lack reverse DNS.
func LookupReverseDNS(ctx context.Context, ip string) (*ReverseDNSInfo, error) {
	names, err := Resolver().LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return &ReverseDNSInfo{Hostnames: []string{}}, nil
		}
		return nil, fmt.Errorf("ptr lookup: %w", err)
	}

	// LookupAddr returns FQDNs with trailing dots; strip them for consistency.
	hostnames := make([]string, 0, len(names))
	for _, name := range names {
		hostnames = append(hostnames, strings.TrimSuffix(name, "."))
	}

	return &ReverseDNSInfo{Hostnames: hostnames}, nil
}
