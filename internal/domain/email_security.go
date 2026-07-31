package domain

import (
	"context"
	"errors"
	"fmt"
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

// LookupEmailSecurity queries SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI
// records for a domain. All sub-lookups run concurrently. It returns partial
// results when some sub-lookups fail and (nil, nil) when none produce data.
func LookupEmailSecurity(ctx context.Context, domainName string) (*EmailSecurityInfo, error) {
	resolver := Resolver()

	info := &EmailSecurityInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var hasData bool
	var failures int
	var lastErr error

	setData := func(apply func()) {
		mu.Lock()
		defer mu.Unlock()
		apply()
		hasData = true
	}

	// record separates "this domain publishes no such record" from "we could
	// not find out". NXDOMAIN and NODATA are authoritative answers — plenty of
	// domains have no DMARC or BIMI — but a timeout or SERVFAIL means the
	// question went unanswered, and reporting that as an absent record would
	// tell a caller the domain's email security is unconfigured when we simply
	// do not know.
	record := func(err error) {
		if err == nil || isDNSAbsence(err) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		failures++
		lastErr = err
	}

	wg.Go(func() {
		spf, err := lookupSPF(ctx, resolver, domainName)
		record(err)
		if err == nil && spf != nil {
			setData(func() { info.SPF = spf })
		}
	})

	wg.Go(func() {
		dmarc, err := lookupDMARC(ctx, resolver, domainName)
		record(err)
		if err == nil && dmarc != nil {
			setData(func() { info.DMARC = dmarc })
		}
	})

	wg.Go(func() {
		// DKIM probes common selectors concurrently internally.
		records := lookupDKIM(ctx, resolver, domainName)
		mu.Lock()
		defer mu.Unlock()
		info.DKIM = records
		for _, r := range records {
			if r.Found {
				hasData = true
				break
			}
		}
	})

	wg.Go(func() {
		mtasts, err := lookupMTASTS(ctx, resolver, domainName)
		record(err)
		if err == nil && mtasts != nil {
			setData(func() { info.MTASTS = mtasts })
		}
	})

	wg.Go(func() {
		tlsrpt, err := lookupTLSRPT(ctx, resolver, domainName)
		record(err)
		if err == nil && tlsrpt != nil {
			setData(func() { info.TLSRPT = tlsrpt })
		}
	})

	wg.Go(func() {
		bimi, err := lookupBIMI(ctx, resolver, domainName)
		record(err)
		if err == nil && bimi != nil {
			setData(func() { info.BIMI = bimi })
		}
	})

	wg.Wait()

	if !hasData {
		// Nothing resolved. If that is because the queries failed rather than
		// because the records are absent, say so: an empty result is cached
		// for four hours and reads as "this domain has no email security".
		if failures > 0 {
			return nil, fmt.Errorf("email security: %d of 6 lookups could not complete, last error: %w", failures, lastErr)
		}
		return nil, nil
	}
	return info, nil
}

// isDNSAbsence reports whether err means the record does not exist, as opposed
// to the lookup having failed to reach an answer.
func isDNSAbsence(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
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
