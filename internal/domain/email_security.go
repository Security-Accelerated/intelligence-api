package domain

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
)

// commonDKIMSelectors are well-known selector names used by major email providers.
var commonDKIMSelectors = []string{
	"google",    // Google Workspace
	"default",   // Generic
	"selector1", // Microsoft 365
	"selector2", // Microsoft 365
	"k1",        // Mailchimp
	"s1",        // Generic
	"mail",      // Generic
	"dkim",      // Generic
}

// LookupEmailSecurity queries SPF, DMARC, and DKIM records for a domain.
// It returns partial results when some sub-lookups fail and only returns
// an error if all three produce nothing.
func LookupEmailSecurity(ctx context.Context, domainName string) (*EmailSecurityInfo, error) {
	resolver := net.DefaultResolver

	info := &EmailSecurityInfo{}
	var hasData bool

	// SPF
	if spf, err := lookupSPF(ctx, resolver, domainName); err == nil && spf != nil {
		info.SPF = spf
		hasData = true
	}

	// DMARC
	if dmarc, err := lookupDMARC(ctx, resolver, domainName); err == nil && dmarc != nil {
		info.DMARC = dmarc
		hasData = true
	}

	// DKIM — probe common selectors concurrently
	records := lookupDKIM(ctx, resolver, domainName)
	info.DKIM = records
	for _, r := range records {
		if r.Found {
			hasData = true
			break
		}
	}

	if !hasData {
		return nil, nil
	}
	return info, nil
}

// lookupSPF retrieves and parses the SPF TXT record for a domain.
func lookupSPF(ctx context.Context, resolver *net.Resolver, domain string) (*SPFRecord, error) {
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			return parseSPF(txt), nil
		}
	}
	return nil, nil
}

// parseSPF extracts structured fields from a raw SPF record string.
func parseSPF(raw string) *SPFRecord {
	rec := &SPFRecord{Raw: raw}

	parts := strings.Fields(raw)
	for _, p := range parts {
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "v=") {
			rec.Version = strings.TrimPrefix(lower, "v=")
			continue
		}
		// Terminal "all" mechanism
		if lower == "all" || lower == "+all" || lower == "-all" || lower == "~all" || lower == "?all" {
			rec.All = lower
			continue
		}
		rec.Mechanisms = append(rec.Mechanisms, p)
	}
	return rec
}

// lookupDMARC retrieves and parses the DMARC TXT record at _dmarc.<domain>.
func lookupDMARC(ctx context.Context, resolver *net.Resolver, domain string) (*DMARCRecord, error) {
	txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			return parseDMARC(txt), nil
		}
	}
	return nil, nil
}

// parseDMARC extracts structured fields from a raw DMARC record string.
func parseDMARC(raw string) *DMARCRecord {
	rec := &DMARCRecord{Raw: raw}

	tags := strings.Split(raw, ";")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "v":
			rec.Version = val
		case "p":
			rec.Policy = strings.ToLower(val)
		case "pct":
			if n, err := strconv.Atoi(val); err == nil {
				rec.Pct = n
			}
		case "rua":
			rec.RUA = val
		case "ruf":
			rec.RUF = val
		case "sp":
			rec.SP = strings.ToLower(val)
		}
	}
	return rec
}

// lookupDKIM probes common DKIM selectors concurrently and returns results
// for every selector tried (Found=true when a record exists).
func lookupDKIM(ctx context.Context, resolver *net.Resolver, domain string) []DKIMRecord {
	results := make([]DKIMRecord, len(commonDKIMSelectors))

	var wg sync.WaitGroup
	for i, sel := range commonDKIMSelectors {
		wg.Add(1)
		go func(idx int, selector string) {
			defer wg.Done()
			rec := DKIMRecord{Selector: selector}
			txts, err := resolver.LookupTXT(ctx, selector+"._domainkey."+domain)
			if err == nil {
				joined := strings.Join(txts, "")
				if joined != "" {
					rec.Found = true
					rec.Raw = joined
				}
			}
			results[idx] = rec
		}(i, sel)
	}
	wg.Wait()

	return results
}
