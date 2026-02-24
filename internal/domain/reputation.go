package domain

import (
	"context"
	"fmt"
	"net"
)

const spamhausDBLSuffix = ".dbl.spamhaus.org"

// LookupReputation queries the Spamhaus DBL via DNS to check whether a domain
// appears on a reputation blocklist. NXDOMAIN means the domain is clean; any resolved
// address indicates a listing whose category is determined by the return code.
func LookupReputation(ctx context.Context, domain string) (*ReputationInfo, error) {
	query := domain + spamhausDBLSuffix

	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		// NXDOMAIN means the domain is not listed — this is the clean/happy path.
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return &ReputationInfo{Listed: false, Provider: "spamhaus_dbl"}, nil
		}
		return nil, fmt.Errorf("reputation lookup: %w", err)
	}

	if len(addrs) == 0 {
		return &ReputationInfo{Listed: false, Provider: "spamhaus_dbl"}, nil
	}

	addr := addrs[0]
	return &ReputationInfo{
		Listed:     true,
		Category:   classifyDBLResponse(addr),
		Provider:   "spamhaus_dbl",
		ReturnCode: addr,
	}, nil
}

// classifyDBLResponse maps a Spamhaus DBL return code to a human-readable category.
func classifyDBLResponse(addr string) string {
	switch addr {
	case "127.0.1.2":
		return "spam"
	case "127.0.1.4":
		return "phishing"
	case "127.0.1.5":
		return "malware"
	case "127.0.1.6":
		return "botnet_cc"
	case "127.0.1.102":
		return "abused_spam"
	case "127.0.1.103":
		return "abused_spammed_redirector"
	case "127.0.1.104":
		return "abused_phishing"
	case "127.0.1.105":
		return "abused_malware"
	case "127.0.1.106":
		return "abused_botnet_cc"
	default:
		return "unknown"
	}
}
