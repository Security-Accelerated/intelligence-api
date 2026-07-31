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
	"strconv"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// The smoke suite is the regression gate: the only thing exercising the
// deployed service end to end across every endpoint, lookup and plan.
//
// Coverage is derived from the code wherever it can be — domain.AllLookupNames
// for the catalog, handler.DomainLookupAllowed for the gating — so adding a
// lookup extends the matrix automatically. A restated copy of those tables
// would drift the moment a lookup was added or re-tiered, and the drift would
// be invisible: the suite would keep passing while testing the old contract.

// plans are the API key tiers, least privileged first.
var plans = []string{"free", "basic", "pro", "admin"}

// keyPool holds every key available for one plan and hands them out
// round-robin.
//
// The rate limiter is per key per minute, and the free tier allows 5. A full
// permutation run needs far more free-plan requests than that, so a single key
// forces the suite to either skip checks or sit waiting out windows. Several
// keys multiply the budget: the run stays complete and finishes in a fraction
// of the time. Mint more with `sactl customer create --plan free`.
type keyPool struct {
	keys []string
	next int
}

func (p *keyPool) size() int { return len(p.keys) }

// take returns the next key, cycling so load spreads evenly rather than
// exhausting the first key before touching the second.
func (p *keyPool) take() string {
	if len(p.keys) == 0 {
		return ""
	}
	k := p.keys[p.next%len(p.keys)]
	p.next++
	return k
}

type smokeKeys struct {
	pools map[string]*keyPool
	// rateLimit is a free-plan key held out of every pool.
	//
	// The rate limit check has to exhaust one key's window, which is the exact
	// opposite of what the pool is for. Borrowing a pooled key created a choice
	// between two bad outcomes: rotate, and the limit is never reached because
	// the load is spread; or pin, and every later check risks stalling on a
	// window the suite itself burned. A key nobody else touches removes the
	// conflict, and the check no longer depends on running last.
	rateLimit string
}

func (k smokeKeys) forPlan(plan string) string {
	if p, ok := k.pools[plan]; ok {
		return p.take()
	}
	return ""
}

// pinned returns one specific key from the plan's pool, so a caller can send
// repeated requests on the same key rather than spreading them.
func (k smokeKeys) have(plan string) bool {
	p, ok := k.pools[plan]
	return ok && p.size() > 0
}

func (k smokeKeys) count(plan string) int {
	if p, ok := k.pools[plan]; ok {
		return p.size()
	}
	return 0
}

type smokeFlags struct {
	api          *apiFlags
	keys         smokeKeys
	rateLimitKey string
	keyFlags     map[string]*stringList
	// keysResolved marks keys as already supplied by the caller, so runSmoke
	// does not overwrite an environment's credentials with the ambient ones.
	keysResolved bool
	quick        bool
	maxWait      time.Duration
}

// stringList collects a repeatable flag, also splitting comma-separated values.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func smokeCommand() command {
	return command{
		name:    "smoke",
		summary: "exercise every endpoint, lookup and plan against a running deployment",
		usage:   "[--host URL] [--quick]",
		flags: func(fs *flag.FlagSet) any {
			f := &smokeFlags{api: registerAPIFlags(fs), keyFlags: map[string]*stringList{}}
			for _, plan := range plans {
				f.keyFlags[plan] = &stringList{}
				fs.Var(f.keyFlags[plan], plan+"-key", fmt.Sprintf(
					"%s plan key; repeatable or comma-separated. Defaults to $SMOKE_%s_KEY, plus _2, _3, ...",
					plan, strings.ToUpper(plan)))
			}
			fs.StringVar(&f.rateLimitKey, "ratelimit-key", "", "free plan key reserved for the rate limit check "+
				"and excluded from the pool; defaults to $SMOKE_RATELIMIT_KEY")
			fs.BoolVar(&f.quick, "quick", false,
				"skip the slow lookups (screenshot, subdomains, ct_logs) and the rate limit test")
			fs.DurationVar(&f.maxWait, "max-wait", 8*time.Minute,
				"total time the run may spend waiting out rate limits before giving up")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			return runSmoke(ctx, cfg.(*smokeFlags))
		},
	}
}

// runSmoke executes the suite, shared by the command and the menu.
func runSmoke(ctx context.Context, f *smokeFlags) error {
	if !f.keysResolved {
		f.keys = resolveSmokeKeys(f)
	}
	if f.maxWait == 0 {
		f.maxWait = 8 * time.Minute
	}

	r := &smokeRunner{f: f, out: os.Stdout}
	fmt.Printf("=== smoke: %s ===\n", f.api.host)
	if f.quick {
		fmt.Println("(quick: slow lookups and the rate limit test are skipped)")
	}
	r.reportKeyBudget()
	r.runAll(ctx)
	return r.summary()
}

// resolveSmokeKeys builds each plan's pool from the flags and the environment.
//
// Env lookup accepts SMOKE_<PLAN>_KEY plus numbered siblings (SMOKE_FREE_KEY_2,
// _3, ...) and a plural SMOKE_<PLAN>_KEYS holding a comma-separated list, so
// extra keys can be added to .env without changing any command.
func resolveSmokeKeys(f *smokeFlags) smokeKeys {
	out := smokeKeys{pools: map[string]*keyPool{}}

	for _, plan := range plans {
		var keys []string
		if lst, ok := f.keyFlags[plan]; ok && lst != nil {
			keys = append(keys, *lst...)
		}

		prefix := "SMOKE_" + strings.ToUpper(plan) + "_KEY"
		if v := strings.TrimSpace(os.Getenv(prefix)); v != "" {
			keys = append(keys, v)
		}
		for _, v := range strings.Split(os.Getenv(prefix+"S"), ",") {
			if v = strings.TrimSpace(v); v != "" {
				keys = append(keys, v)
			}
		}
		for i := 2; ; i++ {
			v := strings.TrimSpace(os.Getenv(fmt.Sprintf("%s_%d", prefix, i)))
			if v == "" {
				break
			}
			keys = append(keys, v)
		}

		out.pools[plan] = &keyPool{keys: dedupeStrings(keys)}
	}

	out.rateLimit = strings.TrimSpace(f.rateLimitKey)
	if out.rateLimit == "" {
		out.rateLimit = strings.TrimSpace(os.Getenv("SMOKE_RATELIMIT_KEY"))
	}
	// Held out of the pool even if it was also listed as a free key, so the
	// reservation holds however the environment is configured.
	if out.rateLimit != "" {
		if p, ok := out.pools["free"]; ok {
			kept := p.keys[:0]
			for _, k := range p.keys {
				if k != out.rateLimit {
					kept = append(kept, k)
				}
			}
			p.keys = kept
		}
	}
	return out
}

// dedupeStrings drops repeats, so the same key listed twice does not read as
// twice the rate limit budget.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// slowLookups drive a browser or a third party and dominate the runtime.
// --quick omits them; a full run includes them.
var slowLookups = map[string]bool{
	domain.LookupScreenshotName: true,
	domain.LookupSubdomainsName: true,
	domain.LookupCTLogsName:     true,
}

// lookupTimeout is the per-request deadline for lookups that legitimately take
// longer than a DNS query. The default client timeout is shorter than the
// server's own budget for a screenshot, which fails the check before the
// service has a chance to answer.
func lookupTimeout(name string) time.Duration {
	switch name {
	case domain.LookupScreenshotName:
		return 120 * time.Second
	case domain.LookupSubdomainsName, domain.LookupCTLogsName, domain.LookupThreatIntelName:
		return 60 * time.Second
	default:
		return 0
	}
}

type smokeRunner struct {
	f                   *smokeFlags
	out                 io.Writer
	pass, fail, skipped int
	section             string
	failures            []string
	waited              time.Duration
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
	fmt.Fprintf(r.out, "\n%d passed, %d failed, %d skipped", r.pass, r.fail, r.skipped)
	if r.waited > 0 {
		fmt.Fprintf(r.out, " (%s waiting out rate limits)", r.waited.Round(time.Second))
	}
	fmt.Fprintln(r.out)

	if r.fail == 0 {
		return nil
	}
	fmt.Fprintln(r.out, "\nFailures:")
	for _, f := range r.failures {
		fmt.Fprintf(r.out, "  - %s\n", f)
	}
	return fmt.Errorf("%d check(s) failed", r.fail)
}

// request describes one call.
type request struct {
	method  string
	path    string
	plan    string // "" means send no key
	rawKey  string // overrides plan, for the deliberately-invalid-key cases
	body    any
	timeout time.Duration
	// headers are set verbatim on the request, for cases that need to exercise
	// a specific header value rather than a body or a key.
	headers map[string]string
	// noRetry suppresses rate limit retrying, for the check that deliberately
	// provokes a 429.
	noRetry bool
}

type response struct {
	status  int
	headers http.Header
	body    []byte
}

// do performs a request, waiting out rate limits rather than reporting them.
//
// A full permutation run makes far more requests than the free tier's 5/minute
// allows, so a 429 is an expected event during the run, not a result. The
// service says exactly how long to wait via Retry-After; honouring it keeps
// coverage complete instead of trading checks for speed. The cumulative wait is
// bounded so a broken limiter cannot hang the run forever.
func (r *smokeRunner) do(ctx context.Context, req request) (*response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := r.call(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.status != http.StatusTooManyRequests || req.noRetry || attempt >= 3 {
			return resp, nil
		}

		wait := retryAfter(resp.headers)
		if r.waited+wait > r.f.maxWait {
			return resp, nil
		}
		r.waited += wait
		fmt.Fprintf(r.out, "  \033[33m…\033[0m rate limited, waiting %s\n", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// retryAfter reads the header, falling back to a full window when it is absent
// or unparseable.
func retryAfter(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			// The advertised wait lands exactly on the window boundary, so a
			// margin is added or the retry is itself rejected.
			return time.Duration(secs)*time.Second + 2*time.Second
		}
	}
	return 62 * time.Second
}

func (r *smokeRunner) call(ctx context.Context, req request) (*response, error) {
	var reader io.Reader
	if req.body != nil {
		encoded, err := json.Marshal(req.body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	if req.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.timeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, trimHost(r.f.api.host)+req.path, reader)
	if err != nil {
		return nil, err
	}
	if req.body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if key := r.keyFor(req); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	for name, value := range req.headers {
		httpReq.Header.Set(name, value)
	}

	client := r.f.api.client()
	if req.timeout > client.Timeout {
		client.Timeout = req.timeout
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return nil, err
	}
	return &response{status: resp.StatusCode, headers: resp.Header, body: raw}, nil
}

func (r *smokeRunner) keyFor(req request) string {
	if req.rawKey != "" {
		return req.rawKey
	}
	if req.plan == "" {
		return ""
	}
	return r.f.keys.forPlan(req.plan)
}

// expect asserts a status code, returning the response for further checks.
func (r *smokeRunner) expect(ctx context.Context, desc string, req request, want int) *response {
	if req.plan != "" && req.rawKey == "" && !r.f.keys.have(req.plan) {
		r.skip(desc, "no "+req.plan+" key configured")
		return nil
	}

	resp, err := r.do(ctx, req)
	if err != nil {
		r.bad(desc, err.Error())
		return nil
	}
	if resp.status != want {
		r.bad(desc, fmt.Sprintf("got %d, want %d: %s", resp.status, want,
			truncate(strings.TrimSpace(string(resp.body)), 140)))
		return resp
	}
	r.ok(desc)
	return resp
}

// assert records a boolean check.
func (r *smokeRunner) assert(cond bool, desc, detail string) {
	if cond {
		r.ok(desc)
		return
	}
	r.bad(desc, detail)
}

func domainBody(domains []string, lookups ...string) map[string]any {
	return map[string]any{"domains": domains, "lookups": lookups}
}

func ipBody(ips []string, lookups ...string) map[string]any {
	return map[string]any{"ips": ips, "lookups": lookups}
}

func (r *smokeRunner) runAll(ctx context.Context) {
	r.publicSurface(ctx)
	r.billingSurface(ctx)
	r.authMatrix(ctx)
	r.domainPlanMatrix(ctx)
	r.ipPlanMatrix(ctx)
	r.validationMatrix(ctx)
	r.adminMatrix(ctx)
	r.responseContract(ctx)
	r.cacheBehaviour(ctx)
	r.ipResponseContract(ctx)
	r.headerMatrix(ctx)
	r.limits(ctx)
}
