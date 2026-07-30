package domain

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnsSecurityQueryTimeout bounds each raw DNS exchange.
var dnsSecurityQueryTimeout = 10 * time.Second

// LookupDNSSecurity queries DNSSEC deployment (DS at the parent, DNSKEY at the
// zone) and CAA records for a domain. It uses raw DNS via miekg/dns against the
// configured resolvers because net.Resolver cannot query these record types.
// Partial results are returned when some queries fail; an error is returned
// only when nothing could be determined.
func LookupDNSSecurity(ctx context.Context, domainName string) (*DNSSecurityInfo, error) {
	info := &DNSSecurityInfo{}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errs    []error
		hasData bool
	)

	wg.Go(func() {
		dnssec, err := lookupDNSSEC(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("dnssec: %w", err))
			return
		}
		info.DNSSEC = dnssec
		hasData = true
	})

	wg.Go(func() {
		caa, err := lookupCAA(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("caa: %w", err))
			return
		}
		info.CAA = caa
		hasData = true
	})

	wg.Wait()

	if !hasData {
		if len(errs) > 0 {
			return nil, fmt.Errorf("dns security lookup: %w", errs[0])
		}
		return nil, nil
	}
	return info, nil
}

func lookupDNSSEC(ctx context.Context, domainName string) (*DNSSECInfo, error) {
	dsAnswers, err := queryDNS(ctx, domainName, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	dnskeyAnswers, err := queryDNS(ctx, domainName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	info := &DNSSECInfo{}
	algoSet := map[string]struct{}{}
	for _, rr := range dsAnswers {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		info.DSRecords++
		if name, ok := dns.AlgorithmToString[ds.Algorithm]; ok {
			algoSet[name] = struct{}{}
		} else {
			algoSet[fmt.Sprintf("ALG%d", ds.Algorithm)] = struct{}{}
		}
	}
	for _, rr := range dnskeyAnswers {
		if _, ok := rr.(*dns.DNSKEY); ok {
			info.DNSKEYRecords++
		}
	}
	for a := range algoSet {
		info.Algorithms = append(info.Algorithms, a)
	}
	sort.Strings(info.Algorithms)
	info.Enabled = info.DSRecords > 0 && info.DNSKEYRecords > 0
	return info, nil
}

func lookupCAA(ctx context.Context, domainName string) (*CAAInfo, error) {
	answers, err := queryDNS(ctx, domainName, dns.TypeCAA)
	if err != nil {
		return nil, err
	}

	info := &CAAInfo{}
	for _, rr := range answers {
		caa, ok := rr.(*dns.CAA)
		if !ok {
			continue
		}
		info.Records = append(info.Records, CAARecord{
			Flag:  caa.Flag,
			Tag:   caa.Tag,
			Value: caa.Value,
		})
	}
	info.Present = len(info.Records) > 0
	return info, nil
}

// queryDNS performs a raw DNS query against the configured resolvers, trying
// each server in order until one responds.
func queryDNS(ctx context.Context, domainName string, qtype uint16) ([]dns.RR, error) {
	client := &dns.Client{Timeout: dnsSecurityQueryTimeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domainName), qtype)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range ActiveDNSServers() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			// Retry this server over TCP for large DNSKEY responses.
			tcpClient := &dns.Client{Net: "tcp", Timeout: dnsSecurityQueryTimeout}
			if tcpResp, _, tcpErr := tcpClient.ExchangeContext(ctx, msg, server); tcpErr == nil {
				resp = tcpResp
			}
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("dns query %s/%s: %s", domainName, dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode])
			continue
		}
		return resp.Answer, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns query %s/%s: no resolvers configured", domainName, dns.TypeToString[qtype])
	}
	return nil, lastErr
}
