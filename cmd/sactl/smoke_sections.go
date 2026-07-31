package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/handler"
)

// --- public surface ---

func (r *smokeRunner) publicSurface(ctx context.Context) {
	r.group("Public surface")

	r.expect(ctx, "GET / redirects to /docs",
		request{method: http.MethodGet, path: "/"}, http.StatusMovedPermanently)

	for _, path := range []string{
		"/docs", "/docs/domain", "/docs/ip", "/docs/changelog",
		"/docs/openapi.yaml", "/docs/styles.css", "/docs/theme.js", "/docs/docs.js",
	} {
		r.expect(ctx, "GET "+path, request{method: http.MethodGet, path: path}, http.StatusOK)
	}

	if resp := r.expect(ctx, "GET /v1/hello",
		request{method: http.MethodGet, path: "/v1/hello"}, http.StatusOK); resp != nil {
		var hello struct {
			Message string `json:"message"`
		}
		r.assert(json.Unmarshal(resp.body, &hello) == nil && hello.Message == "hello world",
			"hello returns the expected body", string(resp.body))
	}

	if resp := r.expect(ctx, "GET /v1/health",
		request{method: http.MethodGet, path: "/v1/health"}, http.StatusOK); resp != nil {
		var h healthResponse
		if err := json.Unmarshal(resp.body, &h); err != nil {
			r.bad("health payload decodes", err.Error())
			return
		}
		r.assert(h.Status == "ok", "health reports ok", "status="+h.Status)
		for _, component := range []string{"postgres", "redis", "geoip"} {
			state, present := h.Components[component]
			if !present {
				r.bad("health reports "+component, "component missing from the response")
				continue
			}
			// A missing GeoIP database self-bootstraps and is absent for the
			// first seconds of a cold start, which is why it does not degrade
			// the endpoint's own status either.
			healthy := state == "ok" || (component == "geoip" && state != "down")
			r.assert(healthy, "health: "+component+" = "+state, state)
		}
	}
}

func (r *smokeRunner) billingSurface(ctx context.Context) {
	r.group("Billing surface")

	// The success page renders an error rather than failing, so a customer
	// arriving with a stale link sees an explanation instead of a 500.
	r.expect(ctx, "GET /billing/success without a session renders a page",
		request{method: http.MethodGet, path: "/billing/success"}, http.StatusOK)
	r.expect(ctx, "GET /billing/success with an invalid session renders a page",
		request{method: http.MethodGet, path: "/billing/success?session_id=cs_test_invalid"}, http.StatusOK)

	// The webhook must reject anything it cannot verify. A deployment that
	// accepted unsigned webhooks would let anyone provision themselves a key.
	payload := map[string]any{"type": "checkout.session.completed"}
	r.expect(ctx, "POST /billing/webhook without a signature -> 400",
		request{method: http.MethodPost, path: "/billing/webhook", body: payload},
		http.StatusBadRequest)
	// A present-but-wrong signature is a different code path from an absent
	// one: it reaches signature verification rather than being rejected for a
	// missing header. Sending no header for both, as this did, left the
	// verification path untested while appearing to cover it.
	r.expect(ctx, "POST /billing/webhook with a bad signature -> 400",
		request{method: http.MethodPost, path: "/billing/webhook", body: payload,
			headers: map[string]string{"Stripe-Signature": "t=1,v1=" + strings.Repeat("0", 64)}},
		http.StatusBadRequest)
}

// --- authentication ---

// protectedEndpoints is every route behind APIKeyAuth, with the plan each one
// needs. Used to assert that no key and a bad key are refused everywhere,
// rather than spot-checking one endpoint and assuming the rest.
var protectedEndpoints = []struct {
	method, path, minPlan string
	body                  any
}{
	{http.MethodPost, "/v1/domain/lookup", "free", map[string]any{"domains": []string{"example.com"}, "lookups": []string{"dns"}}},
	{http.MethodPost, "/v1/ip/lookup", "free", map[string]any{"ips": []string{"8.8.8.8"}, "lookups": []string{"geo"}}},
	{http.MethodGet, "/v1/usage?days=1", "free", nil},
	{http.MethodPost, "/v1/keys/rotate", "free", nil},
	{http.MethodGet, "/v1/info", "admin", nil},
	{http.MethodGet, "/v1/admin/usage?days=1", "admin", nil},
	{http.MethodGet, "/v1/admin/changelog", "admin", nil},
	{http.MethodGet, "/v1/admin/fingerprints", "admin", nil},
	{http.MethodPost, "/v1/admin/fingerprints", "admin", map[string]any{"rules": []any{}}},
	{http.MethodPost, "/v1/admin/auth/cache/invalidate", "admin", nil},
	{http.MethodPost, "/v1/admin/geoip/refresh", "admin", nil},
}

func (r *smokeRunner) authMatrix(ctx context.Context) {
	r.group("Authentication — every protected route rejects missing and invalid keys")

	for _, e := range protectedEndpoints {
		label := e.method + " " + e.path
		r.expect(ctx, label+" without a key -> 401",
			request{method: e.method, path: e.path, body: e.body}, http.StatusUnauthorized)
		// A syntactically valid but unknown key must be refused the same way,
		// not accepted or 500'd. This is distinct from sending no key at all.
		r.expect(ctx, label+" with an unknown key -> 401",
			request{method: e.method, path: e.path, body: e.body,
				rawKey: strings.Repeat("0", 64)}, http.StatusUnauthorized)
		r.expect(ctx, label+" with a malformed key -> 401",
			request{method: e.method, path: e.path, body: e.body,
				rawKey: "not-a-real-key"}, http.StatusUnauthorized)
	}
}

// --- plan permutations ---

// planMatrix exercises every lookup against every plan.
//
// Allowed lookups for a plan go in ONE request rather than one each. That is
// both faster and a stronger check: the combined request also exercises the
// concurrent fan-out, and asserting each lookup came back populated and absent
// from errors[] verifies the lookup actually ran, which a per-lookup status
// code alone does not — a broken lookup still returns 200 with an entry in
// errors[]. Refusals stay one request each, since a 403 names only the first
// lookup it rejects.
func (r *smokeRunner) planMatrix(
	ctx context.Context,
	title, path, target string,
	names []string,
	allowedFn func(plan, name string) (bool, bool),
	bodyFn func(lookups ...string) map[string]any,
) {
	r.group(title)

	for _, plan := range plans {
		if !r.f.keys.have(plan) {
			r.skip("all lookups × "+plan, "no "+plan+" key configured")
			continue
		}

		var allowed, refused []string
		var maxTimeout time.Duration
		for _, name := range names {
			ok, known := allowedFn(plan, name)
			if !known {
				r.bad("lookup catalog", fmt.Sprintf("%q is in the name list but not in the gating table", name))
				continue
			}
			if r.f.quick && slowLookups[name] {
				// Recorded, not silently dropped: a run that quietly covers
				// less reads identically to one that covers everything.
				r.skip(fmt.Sprintf("%s (%s)", name, plan), "quick mode")
				continue
			}
			if ok {
				allowed = append(allowed, name)
				if t := lookupTimeout(name); t > maxTimeout {
					maxTimeout = t
				}
				continue
			}
			refused = append(refused, name)
		}

		if len(allowed) > 0 {
			desc := fmt.Sprintf("%s: %d allowed lookups in one request -> 200", plan, len(allowed))
			resp := r.expect(ctx, desc, request{
				method: http.MethodPost, path: path, plan: plan,
				body: bodyFn(allowed...), timeout: maxTimeout,
			}, http.StatusOK)
			if resp != nil {
				r.assertLookupsRan(resp, plan, target, allowed)
			}
		}

		for _, name := range refused {
			r.expect(ctx, fmt.Sprintf("%s (%s) -> 403", name, plan), request{
				method: http.MethodPost, path: path, plan: plan,
				body: bodyFn(name), timeout: lookupTimeout(name),
			}, http.StatusForbidden)
		}
	}
}

// assertLookupsRan checks each requested lookup came back present and without
// an error entry, which is what distinguishes "the plan allows it" from "it
// actually works".
func (r *smokeRunner) assertLookupsRan(resp *response, plan, target string, names []string) {
	var envelope struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil {
		r.bad(plan+": response decodes", err.Error())
		return
	}
	if len(envelope.Results) != 1 {
		r.bad(plan+": one result per target", fmt.Sprintf("got %d results", len(envelope.Results)))
		return
	}
	result := envelope.Results[0]

	var errs []struct {
		Lookup  string `json:"lookup"`
		Message string `json:"message"`
	}
	if raw, ok := result["errors"]; ok {
		_ = json.Unmarshal(raw, &errs)
	}
	failed := map[string]string{}
	for _, e := range errs {
		failed[e.Lookup] = e.Message
	}

	for _, name := range names {
		if msg, bad := failed[name]; bad {
			// A lookup that errors is a real regression even though the request
			// succeeded: partial failure is by design, so nothing else reports it.
			r.bad(fmt.Sprintf("%s (%s) returned data", name, plan), msg)
			continue
		}
		if _, present := result[name]; !present {
			r.bad(fmt.Sprintf("%s (%s) returned data", name, plan), "absent from the response")
			continue
		}
		r.ok(fmt.Sprintf("%s (%s) returned data", name, plan))
	}

	// The envelope must also carry the canonical target and the verbatim inputs.
	r.assert(len(result[target]) > 0, plan+": result carries the normalized "+target, target+" is absent")
	r.assert(len(result["inputs"]) > 0, plan+": result carries inputs", "inputs is absent")
}

func (r *smokeRunner) domainPlanMatrix(ctx context.Context) {
	r.planMatrix(ctx, "Domain lookups — every lookup against every plan",
		"/v1/domain/lookup", "domain", domain.AllLookupNames,
		handler.DomainLookupAllowed,
		func(lookups ...string) map[string]any { return domainBody([]string{"example.com"}, lookups...) })
}

func (r *smokeRunner) ipPlanMatrix(ctx context.Context) {
	r.planMatrix(ctx, "IP lookups — every lookup against every plan",
		"/v1/ip/lookup", "ip", domain.AllIPLookupNames,
		handler.IPLookupAllowed,
		func(lookups ...string) map[string]any { return ipBody([]string{"8.8.8.8"}, lookups...) })
}

// --- validation ---

func (r *smokeRunner) validationMatrix(ctx context.Context) {
	r.group("Validation — domain endpoint")
	for _, tc := range []struct {
		desc string
		body any
	}{
		{"missing lookups", map[string]any{"domains": []string{"example.com"}}},
		{"empty lookups", domainBody([]string{"example.com"})},
		{"blank lookup name", domainBody([]string{"example.com"}, "   ")},
		{"unknown lookup", domainBody([]string{"example.com"}, "nonsense")},
		{"IP-only lookup name", domainBody([]string{"example.com"}, domain.LookupGeoName)},
		{"missing domains", map[string]any{"lookups": []string{"dns"}}},
		{"empty domains", domainBody([]string{}, "dns")},
		{"raw IP as a domain", domainBody([]string{"8.8.8.8"}, "dns")},
		{"invalid domain", domainBody([]string{"not a domain"}, "dns")},
		{"domain with no dot", domainBody([]string{"localhost"}, "dns")},
		{"consecutive dots", domainBody([]string{"example..com"}, "dns")},
	} {
		r.expect(ctx, tc.desc+" -> 400",
			request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin", body: tc.body},
			http.StatusBadRequest)
	}

	// Names are trimmed, lowercased and deduplicated before validation, so
	// these are accepted rather than rejected.
	r.expect(ctx, "lookup names are normalized (whitespace, case, duplicates) -> 200",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
			body: domainBody([]string{"example.com"}, "  DNS  ", "dns", "Ssl")}, http.StatusOK)
	r.expect(ctx, "domain is normalized (scheme, path, port, case) -> 200",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
			body: domainBody([]string{"HTTPS://Example.COM:443/some/path"}, "dns")}, http.StatusOK)

	r.group("Validation — IP endpoint")
	for _, tc := range []struct {
		desc string
		body any
	}{
		{"missing lookups", map[string]any{"ips": []string{"8.8.8.8"}}},
		{"empty lookups", ipBody([]string{"8.8.8.8"})},
		{"unknown lookup", ipBody([]string{"8.8.8.8"}, "nonsense")},
		{"domain-only lookup name", ipBody([]string{"8.8.8.8"}, domain.LookupWhoisName)},
		{"missing ips", map[string]any{"lookups": []string{"geo"}}},
		{"empty ips", ipBody([]string{}, "geo")},
		{"invalid IP", ipBody([]string{"999.1.1.1"}, "geo")},
		{"private IP", ipBody([]string{"10.0.0.1"}, "geo")},
		{"loopback IP", ipBody([]string{"127.0.0.1"}, "geo")},
		{"link-local metadata IP", ipBody([]string{"169.254.169.254"}, "geo")},
		{"CGNAT IP", ipBody([]string{"100.64.0.1"}, "geo")},
		{"unspecified IP", ipBody([]string{"0.0.0.0"}, "geo")},
		{"private IPv6", ipBody([]string{"fd00::1"}, "geo")},
	} {
		r.expect(ctx, tc.desc+" -> 400",
			request{method: http.MethodPost, path: "/v1/ip/lookup", plan: "admin", body: tc.body},
			http.StatusBadRequest)
	}

	r.expect(ctx, "IPv6 is canonicalized -> 200",
		request{method: http.MethodPost, path: "/v1/ip/lookup", plan: "admin",
			body: ipBody([]string{"2001:4860:4860:0:0:0:0:8888"}, "geo")}, http.StatusOK)
}

// --- admin ---

func (r *smokeRunner) adminMatrix(ctx context.Context) {
	r.group("Admin routes — admin allowed, every other plan refused")

	for _, e := range protectedEndpoints {
		if e.minPlan != "admin" {
			continue
		}
		label := e.method + " " + e.path
		// A destructive admin action is only exercised for its gating, not run.
		if strings.Contains(e.path, "geoip/refresh") || e.method == http.MethodPost && strings.Contains(e.path, "fingerprints") {
			for _, plan := range []string{"free", "basic", "pro"} {
				r.expect(ctx, fmt.Sprintf("%s (%s) -> 403", label, plan),
					request{method: e.method, path: e.path, plan: plan, body: e.body}, http.StatusForbidden)
			}
			continue
		}
		for _, plan := range plans {
			want := http.StatusForbidden
			if plan == "admin" {
				want = http.StatusOK
			}
			r.expect(ctx, fmt.Sprintf("%s (%s) -> %d", label, plan, want),
				request{method: e.method, path: e.path, plan: plan, body: e.body}, want)
		}
	}

	r.group("Customer routes — available to every authenticated plan")
	for _, plan := range plans {
		r.expect(ctx, fmt.Sprintf("GET /v1/usage (%s) -> 200", plan),
			request{method: http.MethodGet, path: "/v1/usage?days=7", plan: plan}, http.StatusOK)
	}
	r.expect(ctx, "GET /v1/usage rejects an out-of-range days -> 400",
		request{method: http.MethodGet, path: "/v1/usage?days=999", plan: "admin"}, http.StatusBadRequest)
	r.expect(ctx, "GET /v1/admin/usage rejects an out-of-range days -> 400",
		request{method: http.MethodGet, path: "/v1/admin/usage?days=999", plan: "admin"}, http.StatusBadRequest)
}

// --- response contracts ---

type domainResult struct {
	Domain      string          `json:"domain"`
	Inputs      []string        `json:"inputs"`
	Whois       json.RawMessage `json:"whois"`
	DNS         json.RawMessage `json:"dns"`
	SSL         json.RawMessage `json:"ssl"`
	Headers     json.RawMessage `json:"headers"`
	Fingerprint json.RawMessage `json:"fingerprint"`
	DNSSecurity struct {
		DNSSEC json.RawMessage `json:"dnssec"`
	} `json:"dns_security"`
	Risk struct {
		Score *int `json:"score"`
		// The field is risk_level, not level. Getting this wrong produced a
		// failing check that looked like the API had stopped scoring.
		RiskLevel *string `json:"risk_level"`
	} `json:"risk"`
	Errors []struct {
		Lookup  string `json:"lookup"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (r *smokeRunner) responseContract(ctx context.Context) {
	r.group("Domain response contract")

	lookups := []string{"whois", "dns", "ssl", "headers", "dns_security", "risk"}
	resp := r.expect(ctx, "multi-lookup request",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
			body:    domainBody([]string{"example.com", "EXAMPLE.com", "example.net"}, lookups...),
			timeout: 60 * time.Second}, http.StatusOK)
	if resp == nil {
		return
	}

	var envelope struct {
		Results   []domainResult  `json:"results"`
		CacheHit  *bool           `json:"cache_hit"`
		BareArray json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil {
		r.bad("response decodes as a results envelope", err.Error())
		return
	}

	r.assert(envelope.CacheHit == nil, "no top-level cache_hit",
		"a top-level cache_hit is present; caching is per lookup")
	r.assert(len(envelope.Results) == 2, "duplicate domains collapse into one result",
		fmt.Sprintf("got %d results, want 2", len(envelope.Results)))

	var target *domainResult
	for i := range envelope.Results {
		if envelope.Results[i].Domain == "example.com" {
			target = &envelope.Results[i]
		}
	}
	if target == nil {
		r.bad("results include the normalized domain", "example.com is missing from the response")
		return
	}

	r.assert(len(target.Inputs) == 2, "inputs report every original spelling verbatim",
		fmt.Sprintf("got %v", target.Inputs))

	for _, f := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"whois", target.Whois},
		{"dns", target.DNS},
		{"ssl", target.SSL},
		{"headers", target.Headers},
	} {
		r.assert(len(f.raw) > 0, f.name+" is populated", f.name+" is absent from the response")
	}
	r.assert(len(target.DNSSecurity.DNSSEC) > 0, "dns_security carries a dnssec object", "dnssec is absent")
	r.assert(target.Risk.Score != nil && target.Risk.RiskLevel != nil,
		"risk scores over the other requested lookups", "risk has no score or risk_level")

	// Every lookup object carries its own flag; there is no shared one.
	r.assert(bytes.Count(resp.body, []byte(`"cache_hit"`)) >= len(lookups),
		"every lookup carries its own cache_hit",
		fmt.Sprintf("found %d cache_hit fields for %d lookups",
			bytes.Count(resp.body, []byte(`"cache_hit"`)), len(lookups)))

	// Unrequested lookups must be absent, not null.
	r.assert(target.Fingerprint == nil, "unrequested lookups are omitted",
		"fingerprint was returned without being requested")

	// fingerprint is computed from headers data but has no cache entry of its
	// own; requesting it alone must not leak the headers object.
	if fp := r.expect(ctx, "fingerprint alone -> 200",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
			body: domainBody([]string{"example.com"}, "fingerprint")}, http.StatusOK); fp != nil {
		var one struct {
			Results []domainResult `json:"results"`
		}
		if json.Unmarshal(fp.body, &one) == nil && len(one.Results) == 1 {
			r.assert(one.Results[0].Fingerprint != nil, "fingerprint is populated", "fingerprint is absent")
			r.assert(one.Results[0].Headers == nil, "fingerprint alone omits headers",
				"headers was returned without being requested")
		}
	}

	// Multi-domain batches, per plan cap.
	for _, tc := range []struct {
		plan  string
		count int
		want  int
	}{
		{"free", 2, http.StatusBadRequest},
		{"basic", 3, http.StatusOK},
		{"basic", 6, http.StatusBadRequest},
		{"pro", 3, http.StatusOK},
	} {
		domains := make([]string, tc.count)
		for i := range domains {
			domains[i] = fmt.Sprintf("example%d.com", i)
		}
		r.expect(ctx, fmt.Sprintf("%s plan, %d domains -> %d", tc.plan, tc.count, tc.want),
			request{method: http.MethodPost, path: "/v1/domain/lookup", plan: tc.plan,
				body: domainBody(domains, "dns")}, tc.want)
	}
}

type ipResult struct {
	IP           string          `json:"ip"`
	Inputs       []string        `json:"inputs"`
	Geo          json.RawMessage `json:"geo"`
	ASN          json.RawMessage `json:"asn"`
	ReverseDNS   json.RawMessage `json:"reverse_dns"`
	AbuseContact json.RawMessage `json:"abuse_contact"`
	ThreatIntel  json.RawMessage `json:"threat_intel"`
}

func (r *smokeRunner) ipResponseContract(ctx context.Context) {
	r.group("IP response contract")

	resp := r.expect(ctx, "multi-lookup request",
		request{method: http.MethodPost, path: "/v1/ip/lookup", plan: "admin",
			body: ipBody([]string{"8.8.8.8", "8.8.8.8", "2001:4860:4860:0:0:0:0:8888"},
				"geo", "asn", "reverse_dns", "abuse_contact"), timeout: 60 * time.Second},
		http.StatusOK)
	if resp == nil {
		return
	}

	var envelope struct {
		Results  []ipResult `json:"results"`
		CacheHit *bool      `json:"cache_hit"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil {
		r.bad("response decodes as a results envelope", err.Error())
		return
	}

	r.assert(envelope.CacheHit == nil, "no top-level cache_hit", "a top-level cache_hit is present")
	r.assert(len(envelope.Results) == 2, "duplicate IPs collapse into one result",
		fmt.Sprintf("got %d results, want 2", len(envelope.Results)))

	// Tracked so a result set that never contains the expected IP records a
	// failure rather than skipping the assertions and reporting nothing.
	checkedIPv4 := false
	for _, res := range envelope.Results {
		if res.IP != "8.8.8.8" {
			// The IPv6 address must come back canonicalized, not as sent.
			r.assert(res.IP == "2001:4860:4860::8888", "IPv6 is returned canonicalized",
				"got "+res.IP)
			continue
		}
		checkedIPv4 = true
		r.assert(len(res.Inputs) == 2, "inputs report every original entry verbatim",
			fmt.Sprintf("got %v", res.Inputs))
		for _, f := range []struct {
			name string
			raw  json.RawMessage
		}{
			{"geo", res.Geo},
			{"asn", res.ASN},
			{"reverse_dns", res.ReverseDNS},
			{"abuse_contact", res.AbuseContact},
		} {
			r.assert(len(f.raw) > 0, "IP response has "+f.name, f.name+" is absent")
		}
		r.assert(res.ThreatIntel == nil, "unrequested IP lookups are omitted",
			"threat_intel was returned without being requested")
	}
	r.assert(checkedIPv4, "the requested IPv4 appears in the results",
		"8.8.8.8 was absent, so its field assertions never ran")

	// geo and asn read a local database and are never cached, so their flag is
	// always false. A true here means something started caching them.
	if strings.Contains(string(resp.body), `"geo"`) {
		var probe struct {
			Results []struct {
				Geo struct {
					CacheHit bool `json:"cache_hit"`
				} `json:"geo"`
			} `json:"results"`
		}
		if json.Unmarshal(resp.body, &probe) == nil && len(probe.Results) > 0 {
			r.assert(!probe.Results[0].Geo.CacheHit, "geo is never served from cache",
				"geo reported cache_hit true")
		}
	}
}

// --- headers and limits ---

func (r *smokeRunner) headerMatrix(ctx context.Context) {
	r.group("Response headers")

	// Values, not just presence. A header set to a permissive value is worse
	// than one that is missing, because it looks covered.
	securityHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Cache-Control":             "no-store",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
	}

	// Unauthenticated: security headers and a request ID must already be set,
	// since the middleware that adds them runs before auth.
	if resp := r.expect(ctx, "unauthenticated request",
		request{method: http.MethodGet, path: "/v1/hello"}, http.StatusOK); resp != nil {
		r.assert(resp.headers.Get("X-Request-ID") != "", "X-Request-ID on an unauthenticated request", "absent")
		for _, name := range sortedKeys(securityHeaders) {
			got := resp.headers.Get(name)
			want := securityHeaders[name]
			r.assert(got == want, "security header "+name,
				fmt.Sprintf("got %q, want %q", got, want))
		}
	}

	// Authenticated: rate limit headers appear for a limited plan.
	if resp := r.expect(ctx, "authenticated request (basic)",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "basic",
			body: domainBody([]string{"example.com"}, "dns")}, http.StatusOK); resp != nil {
		r.assert(resp.headers.Get("X-Request-ID") != "", "X-Request-ID on an authenticated request", "absent")
		r.assert(resp.headers.Get("X-RateLimit-Limit") == "30",
			"X-RateLimit-Limit reports the basic tier", "got "+resp.headers.Get("X-RateLimit-Limit"))
		r.assert(resp.headers.Get("X-RateLimit-Remaining") != "",
			"X-RateLimit-Remaining is present", "absent")
	}

	// Correlation IDs: echoed when valid, silently dropped when not.
	for _, tc := range []struct {
		id       string
		wantEcho bool
		why      string
	}{
		{"req-smoke-001", true, "a simple ID"},
		{"550e8400-e29b-41d4-a716-446655440000", true, "a UUID"},
		{"trace:abc.123_x", true, "colons, dots and underscores"},
		{strings.Repeat("a", 64), true, "exactly at the length limit"},
		{strings.Repeat("a", 65), false, "one over the length limit"},
		{"has space", false, "a space"},
		{"has/slash", false, "a slash"},
	} {
		r.correlationID(ctx, tc.id, tc.wantEcho, tc.why)
	}
}

func (r *smokeRunner) correlationID(ctx context.Context, id string, wantEcho bool, why string) {
	desc := "correlation ID with " + why
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimHost(r.f.api.host)+"/v1/hello", nil)
	if err != nil {
		r.bad(desc, err.Error())
		return
	}
	req.Header.Set("X-Client-Request-ID", id)

	resp, err := r.f.api.client().Do(req)
	if err != nil {
		r.bad(desc, err.Error())
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAPIResponse))

	echoed := resp.Header.Get("X-Client-Request-ID")
	switch {
	case wantEcho:
		r.assert(echoed == id, desc+" is echoed back", fmt.Sprintf("got %q", echoed))
	default:
		r.assert(echoed == "", desc+" is dropped silently", fmt.Sprintf("was echoed as %q", echoed))
	}
}

func (r *smokeRunner) limits(ctx context.Context) {
	r.group("Limits")

	// The body limit runs before JSON parsing, so an oversized body is rejected
	// regardless of whether it would have been valid.
	big := strings.Repeat("a", 1<<20+1024)
	r.expect(ctx, "oversized request body -> 413",
		request{method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
			body: map[string]any{"domains": []string{"example.com"}, "lookups": []string{"dns"}, "padding": big}},
		http.StatusRequestEntityTooLarge)

	if r.f.quick {
		r.skip("rate limiter returns 429 with Retry-After", "quick mode")
		return
	}
	if r.f.keys.rateLimit == "" {
		r.skip("rate limiter returns 429 with Retry-After",
			"no reserved key; set SMOKE_RATELIMIT_KEY to a free-plan key not used elsewhere")
		return
	}

	// Deliberately exceed the free tier's 5/minute, on a key reserved for this
	// and excluded from the pool. Every other check rotates across the pool to
	// spread load; here the load must land on one key, and nothing else may be
	// affected when its window is spent.
	r.group("Rate limiting")
	var limited *response
	for i := 0; i < 12; i++ {
		resp, err := r.do(ctx, request{
			method: http.MethodGet, path: "/v1/usage?days=1",
			rawKey: r.f.keys.rateLimit, noRetry: true,
		})
		if err != nil {
			r.bad("rate limiter engages on the free tier", err.Error())
			return
		}
		if resp.status == http.StatusTooManyRequests {
			limited = resp
			break
		}
	}

	if limited == nil {
		r.bad("rate limiter engages on the free tier",
			"12 rapid requests on one reserved key of a 5/minute plan were all accepted")
		return
	}
	r.ok("rate limiter engages on the free tier")
	r.assert(limited.headers.Get("Retry-After") != "",
		"429 carries Retry-After", "absent, so a client cannot know when to retry")
	r.assert(limited.headers.Get("X-RateLimit-Limit") == "5",
		"429 reports the free tier limit", "got "+limited.headers.Get("X-RateLimit-Limit"))
	r.assert(limited.headers.Get("X-Request-ID") != "",
		"429 still carries X-Request-ID", "absent")

	// The limiter is per key: another plan's key must be unaffected.
	r.expect(ctx, "a rate-limited free key does not affect the pro key",
		request{method: http.MethodGet, path: "/v1/usage?days=1", plan: "pro"}, http.StatusOK)
}

// reportKeyBudget prints the pool sizes and the resulting per-minute budget, so
// a slow run is self-explaining rather than looking like the service is slow.
func (r *smokeRunner) reportKeyBudget() {
	limits := map[string]int{"free": 5, "basic": 30, "pro": 120}
	var parts []string
	for _, plan := range plans {
		n := r.f.keys.count(plan)
		if n == 0 {
			parts = append(parts, plan+": none")
			continue
		}
		if limit, capped := limits[plan]; capped {
			parts = append(parts, fmt.Sprintf("%s: %d key(s), %d req/min", plan, n, n*limit))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %d key(s), unlimited", plan, n))
	}
	fmt.Fprintf(r.out, "keys — %s\n", strings.Join(parts, "  |  "))
}

// --- caching ---

// cacheProbe pulls the per-lookup cache_hit flags out of a single-result
// response.
func cacheFlags(body []byte) (map[string]bool, error) {
	var envelope struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Results) != 1 {
		return nil, fmt.Errorf("got %d results, want 1", len(envelope.Results))
	}

	out := map[string]bool{}
	for name, raw := range envelope.Results[0] {
		var probe struct {
			CacheHit *bool `json:"cache_hit"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.CacheHit != nil {
			out[name] = *probe.CacheHit
		}
	}
	return out, nil
}

// cacheBehaviour verifies both sides of the caching contract against the live
// service. Nothing else covers it end to end: the unit tests use a fake cache,
// so a misconfigured or unreachable Redis in production would show up only as
// quietly slower responses, since caching is deliberately fail-open.
func (r *smokeRunner) cacheBehaviour(ctx context.Context) {
	r.group("Caching")

	if !r.f.keys.have("admin") {
		r.skip("cache behaviour", "no admin key configured")
		return
	}

	const target = "example.com"

	// First request warms the entry. Whether it is a hit depends on what ran
	// before, so its state is reported rather than asserted.
	first := r.expect(ctx, "first lookup succeeds", request{
		method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
		body: domainBody([]string{target}, "dns"),
	}, http.StatusOK)
	if first == nil {
		return
	}
	firstFlags, err := cacheFlags(first.body)
	if err != nil {
		r.bad("first response decodes", err.Error())
		return
	}
	if firstFlags["dns"] {
		fmt.Fprintf(r.out, "    (dns was already cached; the miss path is covered by the uncached lookups below)\n")
	} else {
		r.ok("a cold lookup reports cache_hit false")
	}

	// Second identical request must be served from cache. This is the check
	// that fails if Redis is unreachable, misconfigured, or the TTL is zero.
	second := r.expect(ctx, "repeat lookup succeeds", request{
		method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
		body: domainBody([]string{target}, "dns"),
	}, http.StatusOK)
	if second == nil {
		return
	}
	secondFlags, err := cacheFlags(second.body)
	if err != nil {
		r.bad("repeat response decodes", err.Error())
		return
	}
	r.assert(secondFlags["dns"], "an immediate repeat is served from cache",
		"cache_hit was false on a repeat request, so nothing is being cached")

	// Cache keys are per lookup per domain, not per response: a request asking
	// for a different combination must still reuse the warmed entry. This is
	// the documented design, and a regression to whole-response caching would
	// pass every check above while silently halving the hit rate.
	mixed := r.expect(ctx, "overlapping lookup set succeeds", request{
		method: http.MethodPost, path: "/v1/domain/lookup", plan: "admin",
		body: domainBody([]string{target}, "dns", "ssl"),
	}, http.StatusOK)
	if mixed != nil {
		if flags, err := cacheFlags(mixed.body); err == nil {
			r.assert(flags["dns"], "a different lookup set still reuses the cached entry",
				"dns was refetched when asked for alongside ssl, so keying is per response rather than per lookup")
		}
	}

	// geo and asn read a local database, so they are deliberately never cached.
	// Requesting them alongside a cacheable lookup proves cache_hit is reported
	// per lookup rather than shared across the response.
	for i := 0; i < 2; i++ {
		resp := r.expect(ctx, fmt.Sprintf("IP lookup, pass %d", i+1), request{
			method: http.MethodPost, path: "/v1/ip/lookup", plan: "admin",
			body: ipBody([]string{"8.8.8.8"}, "geo", "reverse_dns"),
		}, http.StatusOK)
		if resp == nil || i == 0 {
			continue
		}
		flags, err := cacheFlags(resp.body)
		if err != nil {
			r.bad("IP response decodes", err.Error())
			continue
		}
		r.assert(!flags["geo"], "geo is never served from cache",
			"geo reported cache_hit true, but it reads a local database")
		r.assert(flags["reverse_dns"], "reverse_dns is served from cache on a repeat",
			"cache_hit was false on a repeat request")
		r.assert(flags["geo"] != flags["reverse_dns"],
			"cached and uncached lookups report different flags in one response",
			"every lookup in the response reported the same cache_hit, so the flag is not per lookup")
	}
}
