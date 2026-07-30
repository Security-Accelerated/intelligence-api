package domain

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	spamhausDBLSuffix = ".dbl.spamhaus.org"
	surblSuffix       = ".multi.surbl.org"
	uriblSuffix       = ".multi.uribl.com"
	spamhausZENSuffix = ".zen.spamhaus.org"
)

// LookupReputation queries multiple DNS-based blocklists concurrently and returns
// a scored reputation result. The result is always non-nil (even if all providers
// report clean). Per-provider errors are returned separately so callers can see
// partial results.
func LookupReputation(ctx context.Context, domain string) (*ReputationInfo, []LookupError) {
	type providerResult struct {
		result *ProviderResult
		err    error
		name   string
	}

	ch := make(chan providerResult, 4)
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		r, err := lookupSpamhausDBL(ctx, domain)
		ch <- providerResult{result: r, err: err, name: "spamhaus_dbl"}
	}()
	go func() {
		defer wg.Done()
		r, err := lookupSURBL(ctx, domain)
		ch <- providerResult{result: r, err: err, name: "surbl"}
	}()
	go func() {
		defer wg.Done()
		r, err := lookupURIBL(ctx, domain)
		ch <- providerResult{result: r, err: err, name: "uribl"}
	}()
	go func() {
		defer wg.Done()
		r, err := lookupSpamhausZEN(ctx, domain)
		ch <- providerResult{result: r, err: err, name: "spamhaus_zen"}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	var providers []*ProviderResult
	var errs []LookupError
	for pr := range ch {
		if pr.err != nil {
			msg := pr.err.Error()
			if i := strings.LastIndex(msg, ": "); i != -1 {
				msg = msg[i+2:]
			}
			errs = append(errs, LookupError{
				Lookup:  "reputation:" + pr.name,
				Message: msg,
			})
			continue
		}
		providers = append(providers, pr.result)
	}

	score, risk := ScoreReputation(providers)
	return &ReputationInfo{
		Score:     score,
		Risk:      risk,
		Providers: providers,
	}, errs
}

func lookupSpamhausDBL(ctx context.Context, domain string) (*ProviderResult, error) {
	query := domain + spamhausDBLSuffix

	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return &ProviderResult{Listed: false, Provider: "spamhaus_dbl"}, nil
		}
		return nil, fmt.Errorf("spamhaus_dbl lookup: %w", err)
	}

	if len(addrs) == 0 {
		return &ProviderResult{Listed: false, Provider: "spamhaus_dbl"}, nil
	}

	addr := addrs[0]
	return &ProviderResult{
		Listed:     true,
		Category:   classifyDBLResponse(addr),
		Provider:   "spamhaus_dbl",
		ReturnCode: addr,
	}, nil
}

func lookupSURBL(ctx context.Context, domain string) (*ProviderResult, error) {
	query := domain + surblSuffix

	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return &ProviderResult{Listed: false, Provider: "surbl"}, nil
		}
		return nil, fmt.Errorf("surbl lookup: %w", err)
	}

	if len(addrs) == 0 {
		return &ProviderResult{Listed: false, Provider: "surbl"}, nil
	}

	addr := addrs[0]
	category := classifySURBLResponse(addr)
	if category == "" {
		return &ProviderResult{Listed: false, Provider: "surbl"}, nil
	}

	return &ProviderResult{
		Listed:     true,
		Category:   category,
		Provider:   "surbl",
		ReturnCode: addr,
	}, nil
}

func lookupURIBL(ctx context.Context, domain string) (*ProviderResult, error) {
	query := domain + uriblSuffix

	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return &ProviderResult{Listed: false, Provider: "uribl"}, nil
		}
		return nil, fmt.Errorf("uribl lookup: %w", err)
	}

	if len(addrs) == 0 {
		return &ProviderResult{Listed: false, Provider: "uribl"}, nil
	}

	addr := addrs[0]
	// 127.0.0.1 is a rate-limit/error response from URIBL, not an actual listing.
	if addr == "127.0.0.1" {
		return nil, fmt.Errorf("uribl lookup: rate limited (127.0.0.1)")
	}

	category := classifyURIBLResponse(addr)
	return &ProviderResult{
		Listed:     true,
		Category:   category,
		Provider:   "uribl",
		ReturnCode: addr,
	}, nil
}

func lookupSpamhausZEN(ctx context.Context, domain string) (*ProviderResult, error) {
	// ZEN is IP-based: resolve domain A records, then check each IP.
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return &ProviderResult{Listed: false, Provider: "spamhaus_zen"}, nil
		}
		return nil, fmt.Errorf("spamhaus_zen: resolve domain: %w", err)
	}

	for _, ip := range ips {
		reversed, ok := reverseIPv4(ip)
		if !ok {
			continue
		}

		query := reversed + spamhausZENSuffix
		addrs, err := net.DefaultResolver.LookupHost(ctx, query)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				continue
			}
			return nil, fmt.Errorf("spamhaus_zen lookup %s: %w", ip, err)
		}

		if len(addrs) == 0 {
			continue
		}

		addr := addrs[0]
		return &ProviderResult{
			Listed:     true,
			Category:   classifyZENResponse(addr),
			Provider:   "spamhaus_zen",
			ReturnCode: addr,
		}, nil
	}

	return &ProviderResult{Listed: false, Provider: "spamhaus_zen"}, nil
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

// classifySURBLResponse interprets the SURBL bitmask in the last octet.
// Multiple bits can be set simultaneously; categories are joined with "+".
// Returns "" if no known bits are set.
func classifySURBLResponse(addr string) string {
	octet := parseLastOctet(addr)
	if octet < 0 {
		return ""
	}

	var parts []string
	if octet&64 != 0 {
		parts = append(parts, "suspicious")
	}
	if octet&32 != 0 {
		parts = append(parts, "cracked")
	}
	if octet&16 != 0 {
		parts = append(parts, "abuse")
	}
	if octet&8 != 0 {
		parts = append(parts, "malware")
	}

	return strings.Join(parts, "+")
}

// classifyURIBLResponse maps a URIBL return code to a category.
func classifyURIBLResponse(addr string) string {
	switch addr {
	case "127.0.0.2":
		return "spam"
	case "127.0.0.4":
		return "grey"
	case "127.0.0.8":
		return "red"
	default:
		return "unknown"
	}
}

// classifyZENResponse maps a Spamhaus ZEN return code to a category based on
// the last octet range.
func classifyZENResponse(addr string) string {
	octet := parseLastOctet(addr)
	switch {
	case octet >= 2 && octet <= 3:
		return "sbl_spam"
	case octet >= 4 && octet <= 7:
		return "xbl_exploits"
	case octet >= 10 && octet <= 11:
		return "pbl_policy"
	default:
		return "unknown"
	}
}

// ScoreReputation computes a risk score (0–100) and risk level from provider results.
func ScoreReputation(providers []*ProviderResult) (int, string) {
	total := 0
	for _, p := range providers {
		if !p.Listed {
			continue
		}
		total += scoreProvider(p)
	}
	if total > 100 {
		total = 100
	}

	var risk string
	switch {
	case total == 0:
		risk = "clean"
	case total <= 29:
		risk = "low"
	case total <= 59:
		risk = "medium"
	default:
		risk = "high"
	}
	return total, risk
}

func scoreProvider(p *ProviderResult) int {
	switch p.Provider {
	case "spamhaus_dbl":
		return scoreDBL(p.Category)
	case "surbl":
		return scoreSURBL(p.Category)
	case "uribl":
		return scoreURIBL(p.Category)
	case "spamhaus_zen":
		return scoreZEN(p.Category)
	default:
		return 0
	}
}

func scoreDBL(category string) int {
	switch category {
	case "malware", "botnet_cc":
		return 40
	case "abused_malware", "abused_botnet_cc":
		return 40
	case "phishing", "abused_phishing":
		return 35
	case "spam", "abused_spam", "abused_spammed_redirector":
		return 25
	default:
		return 15
	}
}

func scoreSURBL(category string) int {
	total := 0
	for _, part := range strings.Split(category, "+") {
		switch part {
		case "malware":
			total += 30
		case "cracked":
			total += 20
		case "abuse":
			total += 15
		case "suspicious":
			total += 10
		}
	}
	return total
}

func scoreURIBL(category string) int {
	switch category {
	case "red":
		return 20
	case "spam":
		return 15
	case "grey":
		return 5
	default:
		return 5
	}
}

func scoreZEN(category string) int {
	switch category {
	case "xbl_exploits":
		return 20
	case "sbl_spam":
		return 15
	case "pbl_policy":
		return 5
	default:
		return 5
	}
}

// reverseIPv4 reverses the octets of an IPv4 address for rDNS-style queries.
// Returns ("", false) for non-IPv4 addresses.
func reverseIPv4(ip string) (string, bool) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", false
	}
	// Validate all parts are numeric
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return "", false
		}
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0], true
}

// parseLastOctet extracts the last octet from a dotted IPv4 address as an int.
// Returns -1 on malformed input.
func parseLastOctet(addr string) int {
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		return -1
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil {
		return -1
	}
	return n
}
