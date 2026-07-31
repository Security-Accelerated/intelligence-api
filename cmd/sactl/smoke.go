package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// smokeKeys holds one API key per plan. Every key is optional: a run with only
// some of them exercises the cases it can and reports the rest as skipped,
// rather than failing for a reason that has nothing to do with the deployment.
type smokeKeys struct {
	admin, pro, basic, free string
}

func (k smokeKeys) forPlan(plan string) string {
	switch plan {
	case "admin":
		return k.admin
	case "pro":
		return k.pro
	case "basic":
		return k.basic
	case "free":
		return k.free
	}
	return ""
}

type smokeFlags struct {
	api  *apiFlags
	keys smokeKeys
}

func smokeCommand() command {
	return command{
		name:    "smoke",
		summary: "exercise every endpoint against a running deployment",
		usage:   "[--host URL]",
		flags: func(fs *flag.FlagSet) any {
			f := &smokeFlags{api: registerAPIFlags(fs)}
			fs.StringVar(&f.keys.admin, "admin-key", "", "admin plan key; defaults to $SMOKE_ADMIN_KEY")
			fs.StringVar(&f.keys.pro, "pro-key", "", "pro plan key; defaults to $SMOKE_PRO_KEY")
			fs.StringVar(&f.keys.basic, "basic-key", "", "basic plan key; defaults to $SMOKE_BASIC_KEY")
			fs.StringVar(&f.keys.free, "free-key", "", "free plan key; defaults to $SMOKE_FREE_KEY")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			return runSmoke(ctx, cfg.(*smokeFlags))
		},
	}
}

// runSmoke executes the suite, shared by the command and the menu.
func runSmoke(ctx context.Context, f *smokeFlags) error {
	f.keys = resolveSmokeKeys(f.keys)

	r := &smokeRunner{f: f, out: os.Stdout}
	fmt.Printf("=== smoke: %s ===\n", f.api.host)
	r.runAll(ctx)
	return r.summary()
}

func resolveSmokeKeys(k smokeKeys) smokeKeys {
	pick := func(flagVal, env string) string {
		if strings.TrimSpace(flagVal) != "" {
			return flagVal
		}
		return strings.TrimSpace(os.Getenv(env))
	}
	return smokeKeys{
		admin: pick(k.admin, "SMOKE_ADMIN_KEY"),
		pro:   pick(k.pro, "SMOKE_PRO_KEY"),
		basic: pick(k.basic, "SMOKE_BASIC_KEY"),
		free:  pick(k.free, "SMOKE_FREE_KEY"),
	}
}

// planBudget caps how many requests a run may send with each plan's key.
//
// The rate limiter is per key per minute (free 5, basic 30, pro 120), and a
// smoke run is a burst. Without a budget the free-plan checks 429 partway
// through and the run reports failures that say nothing about the deployment —
// which is exactly what the first version of this command did. Admin bypasses
// the limiter entirely, so it is unbudgeted.
var planBudget = map[string]int{
	"free":  4,
	"basic": 25,
	"pro":   100,
}

type smokeRunner struct {
	f                   *smokeFlags
	out                 io.Writer
	pass, fail, skipped int
	section             string
	failures            []string
	// spent counts requests already made with each plan's key.
	spent map[string]int
}

// budgetFor reports whether another request may be made with plan's key.
func (r *smokeRunner) budgetFor(plan string) bool {
	limit, capped := planBudget[plan]
	if !capped {
		return true
	}
	if r.spent == nil {
		r.spent = map[string]int{}
	}
	if r.spent[plan] >= limit {
		return false
	}
	r.spent[plan]++
	return true
}

func (r *smokeRunner) group(name string) {
	r.section = name
	fmt.Fprintf(r.out, "\n%s\n", name)
}

func (r *smokeRunner) ok(desc string) {
	r.pass++
	fmt.Fprintf(r.out, "  \033[32m✓\033[0m %s\n", desc)
}

func (r *smokeRunner) bad(desc, detail string) {
	r.fail++
	r.failures = append(r.failures, r.section+": "+desc+" — "+detail)
	fmt.Fprintf(r.out, "  \033[31m✗\033[0m %s — %s\n", desc, detail)
}

func (r *smokeRunner) skip(desc, why string) {
	r.skipped++
	fmt.Fprintf(r.out, "  \033[33m-\033[0m %s (skipped: %s)\n", desc, why)
}

func (r *smokeRunner) summary() error {
	fmt.Fprintf(r.out, "\n%d passed, %d failed, %d skipped\n", r.pass, r.fail, r.skipped)
	if r.fail == 0 {
		return nil
	}
	fmt.Fprintln(r.out, "\nFailures:")
	for _, f := range r.failures {
		fmt.Fprintf(r.out, "  - %s\n", f)
	}
	return fmt.Errorf("%d check(s) failed", r.fail)
}

// call performs one request and returns the status, headers and body.
func (r *smokeRunner) call(ctx context.Context, method, path, key string, body any, timeout time.Duration) (int, http.Header, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, trimHost(r.f.api.host)+path, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}

	// The client's own Timeout would still cut a long case short even with a
	// generous context, so it is widened to match rather than left at the
	// default.
	client := r.f.api.client()
	if timeout > client.Timeout {
		client.Timeout = timeout
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// expect runs one status-code assertion using the default request timeout.
func (r *smokeRunner) expect(ctx context.Context, desc, method, path, plan string, body any, want int) ([]byte, http.Header, bool) {
	return r.expectWithTimeout(ctx, desc, method, path, plan, body, want, 0)
}

// expectWithTimeout is expect with a per-case deadline. A zero timeout uses the
// client default.
func (r *smokeRunner) expectWithTimeout(ctx context.Context, desc, method, path, plan string, body any, want int, timeout time.Duration) ([]byte, http.Header, bool) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return r.expectIn(ctx, desc, method, path, plan, body, want, timeout)
}

func (r *smokeRunner) expectIn(ctx context.Context, desc, method, path, plan string, body any, want int, timeout time.Duration) ([]byte, http.Header, bool) {
	key := ""
	if plan != "" {
		key = r.f.keys.forPlan(plan)
		if key == "" {
			r.skip(desc, "no "+plan+" key")
			return nil, nil, false
		}
		if !r.budgetFor(plan) {
			r.skip(desc, fmt.Sprintf("%s plan request budget spent; a 429 here would say nothing about the deployment", plan))
			return nil, nil, false
		}
	}

	code, headers, raw, err := r.call(ctx, method, path, key, body, timeout)
	if err != nil {
		r.bad(desc, err.Error())
		return nil, nil, false
	}
	if code != want {
		r.bad(desc, fmt.Sprintf("got %d, want %d: %s", code, want, truncate(strings.TrimSpace(string(raw)), 120)))
		return raw, headers, false
	}
	r.ok(desc)
	return raw, headers, true
}

func domainBody(domains []string, lookups ...string) map[string]any {
	return map[string]any{"domains": domains, "lookups": lookups}
}

func ipBody(ips []string, lookups ...string) map[string]any {
	return map[string]any{"ips": ips, "lookups": lookups}
}

func (r *smokeRunner) runAll(ctx context.Context) {
	r.publicSurface(ctx)
	r.domainAuth(ctx)
	r.domainValidation(ctx)
	r.ipEndpoint(ctx)
	r.adminSurface(ctx)
	r.responseContract(ctx)
	r.headers(ctx)
}

func (r *smokeRunner) publicSurface(ctx context.Context) {
	r.group("Public pages and health")
	for _, path := range []string{"/docs", "/docs/domain", "/docs/ip", "/docs/changelog", "/docs/openapi.yaml", "/docs/styles.css"} {
		r.expect(ctx, "GET "+path, http.MethodGet, path, "", nil, http.StatusOK)
	}
	r.expect(ctx, "GET /v1/hello", http.MethodGet, "/v1/hello", "", nil, http.StatusOK)

	if raw, _, ok := r.expect(ctx, "GET /v1/health", http.MethodGet, "/v1/health", "", nil, http.StatusOK); ok {
		var h healthResponse
		if err := json.Unmarshal(raw, &h); err != nil {
			r.bad("health payload decodes", err.Error())
			return
		}
		for _, component := range []string{"postgres", "redis", "geoip"} {
			state, present := h.Components[component]
			if !present {
				r.bad("health reports "+component, "component missing from the response")
				continue
			}
			// geoip absent is tolerated: it self-bootstraps and is missing for
			// the first few seconds of a cold start, which is why it does not
			// degrade the endpoint's own status either.
			if state == "ok" || (component == "geoip" && state != "down") {
				r.ok("health: " + component + " = " + state)
				continue
			}
			r.bad("health: "+component, state)
		}
	}
}

func (r *smokeRunner) domainAuth(ctx context.Context) {
	r.group("Domain lookup — authentication and plan gating")
	body := domainBody([]string{"example.com"}, "dns")

	r.expect(ctx, "no key -> 401", http.MethodPost, "/v1/domain/lookup", "", body, http.StatusUnauthorized)

	for _, plan := range []string{"admin", "pro", "basic", "free"} {
		r.expect(ctx, plan+" key -> 200", http.MethodPost, "/v1/domain/lookup", plan, body, http.StatusOK)
	}

	// Premium lookups: allowed for pro and admin, refused below that.
	//
	// The refusal is asserted with the basic key rather than free. Both are
	// below the gate so either proves it, and free is limited to 5 requests a
	// minute — spending its budget on three near-identical 403s would starve
	// the checks only a free key can make. One free-plan 403 is kept, since a
	// gate that behaved differently for the lowest plan would be worth knowing.
	for _, lookup := range []string{"screenshot", "reputation", "threat_intel"} {
		premium := domainBody([]string{"example.com"}, lookup)
		for _, plan := range []string{"admin", "pro"} {
			// Screenshots drive a real browser and queue behind a global
			// semaphore, so they can legitimately take far longer than a DNS
			// lookup. The default client timeout is shorter than the server's
			// own budget for one, which failed the check before the service
			// had a chance to answer.
			timeout := 0 * time.Second
			if lookup == "screenshot" {
				timeout = 90 * time.Second
			}
			r.expectWithTimeout(ctx, lookup+" ("+plan+") -> 200", http.MethodPost, "/v1/domain/lookup", plan, premium, http.StatusOK, timeout)
		}
		r.expect(ctx, lookup+" (basic) -> 403", http.MethodPost, "/v1/domain/lookup", "basic", premium, http.StatusForbidden)
	}

	r.expect(ctx, "screenshot (free) -> 403", http.MethodPost, "/v1/domain/lookup", "free",
		domainBody([]string{"example.com"}, "screenshot"), http.StatusForbidden)
}

func (r *smokeRunner) domainValidation(ctx context.Context) {
	r.group("Domain lookup — validation")
	for _, tc := range []struct {
		desc string
		body any
		want int
	}{
		{"missing lookups -> 400", map[string]any{"domains": []string{"example.com"}}, http.StatusBadRequest},
		{"empty lookups -> 400", domainBody([]string{"example.com"}), http.StatusBadRequest},
		{"unknown lookup -> 400", domainBody([]string{"example.com"}, "nonsense"), http.StatusBadRequest},
		{"IP-only lookup on domains -> 400", domainBody([]string{"example.com"}, "geo"), http.StatusBadRequest},
		{"missing domains -> 400", map[string]any{"lookups": []string{"dns"}}, http.StatusBadRequest},
		{"empty domains -> 400", domainBody([]string{}, "dns"), http.StatusBadRequest},
		{"raw IP as domain -> 400", domainBody([]string{"8.8.8.8"}, "dns"), http.StatusBadRequest},
		{"invalid domain -> 400", domainBody([]string{"not a domain"}, "dns"), http.StatusBadRequest},
	} {
		r.expect(ctx, tc.desc, http.MethodPost, "/v1/domain/lookup", "admin", tc.body, tc.want)
	}

	// Free is capped at one domain per request.
	r.expect(ctx, "free plan, 2 domains -> 400", http.MethodPost, "/v1/domain/lookup", "free",
		domainBody([]string{"example.com", "example.net"}, "dns"), http.StatusBadRequest)
}

func (r *smokeRunner) ipEndpoint(ctx context.Context) {
	r.group("IP lookup")
	body := ipBody([]string{"8.8.8.8"}, "geo", "asn")

	r.expect(ctx, "no key -> 401", http.MethodPost, "/v1/ip/lookup", "", body, http.StatusUnauthorized)
	for _, plan := range []string{"admin", "pro", "basic", "free"} {
		r.expect(ctx, plan+" key -> 200", http.MethodPost, "/v1/ip/lookup", plan, body, http.StatusOK)
	}

	ti := ipBody([]string{"8.8.8.8"}, "threat_intel")
	r.expect(ctx, "threat_intel (pro) -> 200", http.MethodPost, "/v1/ip/lookup", "pro", ti, http.StatusOK)
	r.expect(ctx, "threat_intel (free) -> 403", http.MethodPost, "/v1/ip/lookup", "free", ti, http.StatusForbidden)

	for _, tc := range []struct {
		desc string
		body any
	}{
		{"invalid IP -> 400", ipBody([]string{"999.1.1.1"}, "geo")},
		{"private IP -> 400", ipBody([]string{"10.0.0.1"}, "geo")},
		{"metadata IP -> 400", ipBody([]string{"169.254.169.254"}, "geo")},
		{"domain-only lookup on IPs -> 400", ipBody([]string{"8.8.8.8"}, "whois")},
		{"empty ips -> 400", ipBody([]string{}, "geo")},
	} {
		r.expect(ctx, tc.desc, http.MethodPost, "/v1/ip/lookup", "admin", tc.body, http.StatusBadRequest)
	}
}

func (r *smokeRunner) adminSurface(ctx context.Context) {
	r.group("Admin and customer endpoints")
	for _, path := range []string{"/v1/info", "/v1/admin/usage?days=1", "/v1/admin/changelog", "/v1/admin/fingerprints"} {
		r.expect(ctx, "admin GET "+path, http.MethodGet, path, "admin", nil, http.StatusOK)
		r.expect(ctx, "non-admin GET "+path+" -> 403", http.MethodGet, path, "pro", nil, http.StatusForbidden)
		r.expect(ctx, "no key GET "+path+" -> 401", http.MethodGet, path, "", nil, http.StatusUnauthorized)
	}

	// Customer-facing, available to any authenticated plan.
	r.expect(ctx, "GET /v1/usage (pro)", http.MethodGet, "/v1/usage?days=1", "pro", nil, http.StatusOK)
	r.expect(ctx, "GET /v1/usage without a key -> 401", http.MethodGet, "/v1/usage", "", nil, http.StatusUnauthorized)

	// Key rotation is deliberately not exercised: it would invalidate the very
	// keys this run depends on. Its auth gate is still checked.
	r.expect(ctx, "POST /v1/keys/rotate without a key -> 401", http.MethodPost, "/v1/keys/rotate", "", nil, http.StatusUnauthorized)
}

func (r *smokeRunner) responseContract(ctx context.Context) {
	r.group("Response contract")

	raw, _, ok := r.expect(ctx, "multi-lookup response", http.MethodPost, "/v1/domain/lookup", "admin",
		domainBody([]string{"example.com", "EXAMPLE.com", "example.net"}, "dns", "ssl"), http.StatusOK)
	if !ok {
		return
	}

	var envelope struct {
		Results []struct {
			Domain string          `json:"domain"`
			Inputs []string        `json:"inputs"`
			DNS    json.RawMessage `json:"dns"`
			SSL    json.RawMessage `json:"ssl"`
			Whois  json.RawMessage `json:"whois"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		r.bad("response decodes as a results envelope", err.Error())
		return
	}

	// Two of the three inputs normalize to the same domain, so a correct
	// implementation returns two results, not three.
	if len(envelope.Results) == 2 {
		r.ok("duplicate domains collapse into one result")
	} else {
		r.bad("duplicate domains collapse into one result", fmt.Sprintf("got %d results, want 2", len(envelope.Results)))
	}

	for _, res := range envelope.Results {
		if res.Domain == "example.com" && len(res.Inputs) == 2 {
			r.ok("inputs report both original spellings verbatim")
		}
		if res.Whois != nil {
			r.bad("only requested lookups are returned", "whois was present but not requested")
			return
		}
	}
	r.ok("only requested lookups are returned")

	// cache_hit is per lookup, and there is no top-level flag.
	if bytes.Contains(raw, []byte(`"cache_hit"`)) {
		r.ok("lookups carry their own cache_hit")
	} else {
		r.bad("lookups carry their own cache_hit", "no cache_hit found in the response")
	}
}

func (r *smokeRunner) headers(ctx context.Context) {
	r.group("Response headers")

	_, headers, ok := r.expect(ctx, "authenticated lookup", http.MethodPost, "/v1/domain/lookup", "pro",
		domainBody([]string{"example.com"}, "dns"), http.StatusOK)
	if ok {
		for _, h := range []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"} {
			if headers.Get(h) != "" {
				r.ok("returns " + h)
			} else {
				r.bad("returns "+h, "header absent")
			}
		}
		for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"} {
			if headers.Get(h) != "" {
				r.ok("security header " + h)
			} else {
				r.bad("security header "+h, "header absent")
			}
		}
	}

	// Correlation ID: echoed when valid, silently dropped when not.
	r.correlationID(ctx, "req-smoke-001", true)
	r.correlationID(ctx, strings.Repeat("a", 65), false)
	r.correlationID(ctx, "has space", false)
}

func (r *smokeRunner) correlationID(ctx context.Context, id string, wantEcho bool) {
	key := r.f.keys.forPlan("admin")
	if key == "" {
		r.skip("correlation ID "+truncate(id, 20), "no admin key")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimHost(r.f.api.host)+"/v1/domain/lookup",
		bytes.NewReader(mustJSON(domainBody([]string{"example.com"}, "dns"))))
	if err != nil {
		r.bad("correlation ID", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Client-Request-ID", id)

	resp, err := r.f.api.client().Do(req)
	if err != nil {
		r.bad("correlation ID", err.Error())
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAPIResponse))

	echoed := resp.Header.Get("X-Client-Request-ID")
	desc := fmt.Sprintf("correlation ID %q", truncate(id, 20))
	switch {
	case wantEcho && echoed == id:
		r.ok(desc + " echoed back")
	case wantEcho:
		r.bad(desc+" echoed back", fmt.Sprintf("got %q", echoed))
	case echoed == "":
		r.ok(desc + " rejected silently")
	default:
		r.bad(desc+" rejected silently", fmt.Sprintf("was echoed as %q", echoed))
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
