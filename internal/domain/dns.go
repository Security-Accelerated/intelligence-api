package domain

import (
	"context"
	"net"
)

func LookupDNS(ctx context.Context, domain string) (*DNSInfo, error) {
	resolver := Resolver()
	info := &DNSInfo{}
	var lastErr error

	if addrs, err := resolver.LookupHost(ctx, domain); err == nil {
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				if ip.To4() != nil {
					info.A = append(info.A, addr)
				} else {
					info.AAAA = append(info.AAAA, addr)
				}
			}
		}
	} else {
		lastErr = err
	}

	if mxRecords, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxRecords {
			info.MX = append(info.MX, MXRecord{
				Host:     mx.Host,
				Priority: mx.Pref,
			})
		}
	} else {
		lastErr = err
	}

	if nsRecords, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nsRecords {
			info.NS = append(info.NS, ns.Host)
		}
	} else {
		lastErr = err
	}

	if txtRecords, err := resolver.LookupTXT(ctx, domain); err == nil {
		info.TXT = txtRecords
	} else {
		lastErr = err
	}

	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil {
		if cname != domain+"." && cname != "" {
			info.CNAME = cname
		}
	} else {
		lastErr = err
	}

	if info.A == nil && info.AAAA == nil && info.MX == nil && info.NS == nil && info.TXT == nil && info.CNAME == "" {
		return nil, lastErr
	}

	return info, nil
}
