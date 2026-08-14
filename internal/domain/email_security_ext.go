package domain

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// mtaSTSPolicyMaxBytes caps the policy file read — real policies are tiny.
const mtaSTSPolicyMaxBytes = 64 * 1024

// mtaSTSPolicyClient fetches MTA-STS policy files. The well-known URL is
// derived from the target domain, so the SSRF-safe transport applies; TLS
// verification stays ON because MTA-STS policies are only valid over
// correctly-authenticated HTTPS.
var mtaSTSPolicyClient = &http.Client{
	Transport: trustedTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		// RFC 8461 §3.3: policy fetch MUST NOT follow redirects.
		return http.ErrUseLastResponse
	},
}

// lookupMTASTS retrieves the MTA-STS TXT record and, when present, fetches the
// policy file from https://mta-sts.<domain>/.well-known/mta-sts.txt.
func lookupMTASTS(ctx context.Context, resolver *net.Resolver, domain string) (*MTASTSRecord, error) {
	txts, err := resolver.LookupTXT(ctx, "_mta-sts."+domain)
	if err != nil {
		return nil, err
	}

	var rec *MTASTSRecord
	for _, txt := range txts {
		if r := parseMTASTSRecord(txt); r != nil {
			rec = r
			break
		}
	}
	if rec == nil {
		return nil, nil
	}

	// The TXT record only announces a policy — the actual mode lives in the
	// well-known policy file. Fetch failure leaves PolicyFetched=false but the
	// record itself is still returned.
	if body, err := fetchMTASTSPolicy(ctx, domain); err == nil {
		if mode, maxAge, mxPatterns, perr := parseMTASTSPolicy(body); perr == nil {
			rec.PolicyFetched = true
			rec.Mode = mode
			rec.MaxAge = maxAge
			rec.MXPatterns = mxPatterns
		}
	}
	return rec, nil
}

func parseMTASTSRecord(txt string) *MTASTSRecord {
	if !strings.HasPrefix(strings.ToLower(txt), "v=stsv1") {
		return nil
	}
	rec := &MTASTSRecord{Raw: txt}
	for tag := range strings.SplitSeq(txt, ";") {
		if k, v, ok := cutTag(tag); ok && k == "id" {
			rec.ID = v
		}
	}
	return rec
}

func fetchMTASTSPolicy(ctx context.Context, domain string) ([]byte, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := mtaSTSPolicyClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mta-sts policy fetch: status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, mtaSTSPolicyMaxBytes))
}

func parseMTASTSPolicy(body []byte) (mode string, maxAge int, mxPatterns []string, err error) {
	for line := range strings.Lines(string(body)) {
		k, v, ok := cutTag(line)
		if !ok {
			continue
		}
		switch k {
		case "mode":
			mode = strings.ToLower(v)
		case "max_age":
			if n, err := strconv.Atoi(v); err == nil {
				maxAge = n
			}
		case "mx":
			mxPatterns = append(mxPatterns, v)
		}
	}
	if mode == "" {
		return "", 0, nil, fmt.Errorf("mta-sts policy: missing mode")
	}
	return mode, maxAge, mxPatterns, nil
}

// lookupTLSRPT retrieves the SMTP TLS reporting record at _smtp._tls.<domain>.
func lookupTLSRPT(ctx context.Context, resolver *net.Resolver, domain string) (*TLSRPTRecord, error) {
	txts, err := resolver.LookupTXT(ctx, "_smtp._tls."+domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		if rec := parseTLSRPT(txt); rec != nil {
			return rec, nil
		}
	}
	return nil, nil
}

func parseTLSRPT(txt string) *TLSRPTRecord {
	if !strings.HasPrefix(strings.ToLower(txt), "v=tlsrptv1") {
		return nil
	}
	rec := &TLSRPTRecord{Raw: txt}
	for tag := range strings.SplitSeq(txt, ";") {
		if k, v, ok := cutTag(tag); ok && k == "rua" {
			rec.RUA = v
		}
	}
	return rec
}

// lookupBIMI retrieves the BIMI record at default._bimi.<domain>.
func lookupBIMI(ctx context.Context, resolver *net.Resolver, domain string) (*BIMIRecord, error) {
	txts, err := resolver.LookupTXT(ctx, "default._bimi."+domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		if rec := parseBIMI(txt); rec != nil {
			return rec, nil
		}
	}
	return nil, nil
}

func parseBIMI(txt string) *BIMIRecord {
	if !strings.HasPrefix(strings.ToLower(txt), "v=bimi1") {
		return nil
	}
	rec := &BIMIRecord{Raw: txt}
	for tag := range strings.SplitSeq(txt, ";") {
		k, v, ok := cutTag(tag)
		if !ok {
			continue
		}
		switch k {
		case "l":
			rec.Location = v
		case "a":
			rec.Authority = v
		}
	}
	return rec
}

// cutTag splits a "key=value" tag (or "key: value" policy line), returning the
// lowercased key and trimmed value.
func cutTag(tag string) (key, value string, ok bool) {
	tag = strings.TrimSpace(tag)
	sep := "="
	if strings.Contains(tag, ":") && !strings.Contains(tag, "=") {
		sep = ":"
	}
	k, v, found := strings.Cut(tag, sep)
	if !found {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v), true
}
