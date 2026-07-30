package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/spf13/viper"
)

type mockService struct {
	mu        sync.Mutex
	resp      *domain.DomainResponse
	stats     domain.CacheStats
	lastOpts  domain.LookupOptions
	seen      []string
	callCount int
}

func (m *mockService) Lookup(_ context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, domain.CacheStats) {
	m.mu.Lock()
	m.lastOpts = opts
	m.seen = append(m.seen, domainName)
	m.callCount++
	m.mu.Unlock()
	if m.resp != nil {
		return m.resp, m.stats
	}
	return &domain.DomainResponse{Domain: domainName}, m.stats
}

func (m *mockService) domains() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Clone(m.seen)
	slices.Sort(out)
	return out
}

func (m *mockService) opts() domain.LookupOptions {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastOpts
}

// assertErrorBody checks that the response body contains a JSON "error" key and
// returns its value.
func assertErrorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error field in response body")
	}
	return body["error"]
}

func newTestRouter(svc DomainLookupService) *gin.Engine {
	return newTestRouterWithPlan(svc, planPro)
}

func newTestRouterWithPlan(svc DomainLookupService, plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

// post issues a domain lookup request and returns the recorder.
func post(r *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// decodeResults unwraps the {"results": [...]} envelope.
func decodeResults(t *testing.T, w *httptest.ResponseRecorder) []*domain.DomainResponse {
	t.Helper()
	var env domain.DomainResponseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to unmarshal response envelope: %v\nbody: %s", err, w.Body.String())
	}
	return env.Results
}

// findResult locates the element for a normalized domain. Array position is not
// part of the API contract, so tests match on the domain field.
func findResult(t *testing.T, results []*domain.DomainResponse, name string) *domain.DomainResponse {
	t.Helper()
	for _, r := range results {
		if r.Domain == name {
			return r
		}
	}
	t.Fatalf("no result for domain %q; got %+v", name, results)
	return nil
}

// --- Envelope and result identification ---

func TestDomainLookup_ReturnsResultsEnvelope(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":["example.com"],"lookups":["dns"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	// The top level must be an object, not a bare array.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &top); err != nil {
		t.Fatalf("response is not a JSON object: %v; body: %s", err, w.Body.String())
	}
	if _, ok := top["results"]; !ok {
		t.Fatalf("response missing the results key: %s", w.Body.String())
	}
	if len(top) != 1 {
		t.Errorf("envelope should carry only results for now, got keys %v", top)
	}

	results := decodeResults(t, w)
	if len(results) != 1 || results[0].Domain != "example.com" {
		t.Errorf("results = %+v", results)
	}
}

func TestDomainLookup_NoTopLevelCacheHit(t *testing.T) {
	w := post(newTestRouter(&mockService{stats: domain.CacheStats{Hits: 1}}),
		`{"domains":["example.com"],"lookups":["dns"]}`)

	var env struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := env.Results[0]["cache_hit"]; ok {
		t.Errorf("result carries a top-level cache_hit: %s", w.Body.String())
	}
}

func TestDomainLookup_PerFieldCacheHitSerialized(t *testing.T) {
	svc := &mockService{resp: &domain.DomainResponse{
		Domain: "example.com",
		DNS:    &domain.DNSResult{CacheHit: true, DNSInfo: &domain.DNSInfo{A: []string{"1.2.3.4"}}},
	}}
	w := post(newTestRouter(svc), `{"domains":["example.com"],"lookups":["dns"]}`)

	var env struct {
		Results []struct {
			DNS map[string]any `json:"dns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dns := env.Results[0].DNS
	if dns["cache_hit"] != true {
		t.Errorf("dns.cache_hit = %v, want true; body: %s", dns["cache_hit"], w.Body.String())
	}
	if _, ok := dns["a"]; !ok {
		t.Errorf("dns payload fields not flattened alongside cache_hit: %v", dns)
	}
}

func TestDomainLookup_InputsRecordOriginalEntriesVerbatim(t *testing.T) {
	svc := &mockService{}
	w := post(newTestRouter(svc),
		`{"domains":["HTTPS://Example.COM/","example.net","example.com"],"lookups":["dns"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	results := decodeResults(t, w)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 unique normalized domains: %+v", len(results), results)
	}

	com := findResult(t, results, "example.com")
	wantInputs := []string{"HTTPS://Example.COM/", "example.com"}
	if !slices.Equal(com.Inputs, wantInputs) {
		t.Errorf("inputs = %v, want %v (verbatim, untrimmed)", com.Inputs, wantInputs)
	}
	net := findResult(t, results, "example.net")
	if !slices.Equal(net.Inputs, []string{"example.net"}) {
		t.Errorf("inputs = %v, want [example.net]", net.Inputs)
	}

	// The service sees each unique normalized domain exactly once.
	if got := svc.domains(); !slices.Equal(got, []string{"example.com", "example.net"}) {
		t.Errorf("service saw %v, want the two normalized domains once each", got)
	}
}

func TestDomainLookup_DomainNormalizationProducesIdenticalResults(t *testing.T) {
	for _, entry := range []string{"Example.COM", " example.com ", "https://Example.com/"} {
		t.Run(entry, func(t *testing.T) {
			svc := &mockService{}
			body := fmt.Sprintf(`{"domains":[%q],"lookups":["dns"]}`, entry)
			w := post(newTestRouter(svc), body)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			results := decodeResults(t, w)
			if results[0].Domain != "example.com" {
				t.Errorf("domain = %q, want example.com", results[0].Domain)
			}
			if got := svc.domains(); !slices.Equal(got, []string{"example.com"}) {
				t.Errorf("service saw %v, want [example.com]", got)
			}
			if !slices.Equal(results[0].Inputs, []string{entry}) {
				t.Errorf("inputs = %v, want the verbatim entry %q", results[0].Inputs, entry)
			}
		})
	}
}

func TestDomainLookup_MultipleDomains(t *testing.T) {
	svc := &mockService{}
	w := post(newTestRouter(svc), `{"domains":["example.com","example.org"],"lookups":["dns"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	if len(decodeResults(t, w)) != 2 {
		t.Errorf("want 2 results")
	}
}

func TestDomainLookup_MixedValidInvalid(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":["example.com","not-a-domain"],"lookups":["dns"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	results := decodeResults(t, w)
	invalid := findResult(t, results, "not-a-domain")
	if len(invalid.Errors) != 1 || invalid.Errors[0].Lookup != "validation" {
		t.Errorf("expected a validation error, got %+v", invalid.Errors)
	}
	if !slices.Equal(invalid.Inputs, []string{"not-a-domain"}) {
		t.Errorf("invalid entries should still carry inputs, got %v", invalid.Inputs)
	}
}

// --- lookups validation ---

func TestDomainLookup_MissingLookups(t *testing.T) {
	for _, body := range []string{
		`{"domains":["example.com"]}`,
		`{"domains":["example.com"],"lookups":[]}`,
		`{"domains":["example.com"],"lookups":[" "]}`,
		`{"domains":["example.com"],"lookups":[""]}`,
		`{"domains":["example.com"],"lookups":["","  ",""]}`,
	} {
		t.Run(body, func(t *testing.T) {
			w := post(newTestRouter(&mockService{}), body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			msg := assertErrorBody(t, w)
			if !strings.Contains(msg, "lookups is required") {
				t.Errorf("error = %q, want it to mention that lookups is required", msg)
			}
		})
	}
}

func TestDomainLookup_UnknownLookupNamesTheOffender(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":["example.com"],"lookups":["dns","banana"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	msg := assertErrorBody(t, w)
	if !strings.Contains(msg, "banana") {
		t.Errorf("error = %q, want it to name the invalid entry", msg)
	}
}

func TestDomainLookup_MalformedJSON(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	assertErrorBody(t, w)
}

func TestDomainLookup_MissingBody(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	assertErrorBody(t, w)
}

func TestDomainLookup_EmptyDomainsArray(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":[],"lookups":["dns"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	assertErrorBody(t, w)
}

func TestDomainLookup_NoService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) { c.Set("api_key_plan", planPro); c.Next() })

	w := post(r, `{"domains":["example.com"],"lookups":["dns"]}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// --- lookup-name normalization ---

func TestNormalizeLookups(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"trims and lowercases", []string{" SSL "}, []string{"ssl"}},
		{"dedupes case and whitespace variants", []string{"ssl", "SSL", " ssl"}, []string{"ssl"}},
		{"drops blanks", []string{"", "  ", "dns"}, []string{"dns"}},
		{"all blank collapses to empty", []string{" ", ""}, []string{}},
		{"preserves distinct names", []string{"dns", "ssl"}, []string{"dns", "ssl"}},
		{"nil input", nil, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeLookups(tt.in)
			// Order is not part of the contract — compare as sets.
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeLookups(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("normalizeLookups(%v) = %v, missing %q", tt.in, got, w)
				}
			}
		})
	}
}

func TestDomainLookup_LookupNamesNormalizedBeforeValidation(t *testing.T) {
	svc := &mockService{}
	w := post(newTestRouter(svc), `{"domains":["example.com"],"lookups":[" SSL ","ssl","SSL","DNS"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	got := svc.opts().Lookups
	if len(got) != 2 {
		t.Fatalf("service received %v, want 2 deduped lookups", got)
	}
	for _, want := range []string{"ssl", "dns"} {
		if !slices.Contains(got, want) {
			t.Errorf("service received %v, missing %q", got, want)
		}
	}
}

func TestDomainLookup_OptsPassedToService(t *testing.T) {
	svc := &mockService{}
	all := strings.Join(quoteAll(domain.AllLookupNames), ",")
	w := post(newTestRouterWithPlan(svc, planAdmin),
		fmt.Sprintf(`{"domains":["example.com"],"lookups":[%s]}`, all))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	got := svc.opts()
	for _, name := range domain.AllLookupNames {
		if !got.Has(name) {
			t.Errorf("service opts missing %q; got %v", name, got.Lookups)
		}
	}
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

// --- Plan gating ---

func TestDomainLookup_PlanGating(t *testing.T) {
	gated := []string{
		domain.LookupScreenshotName,
		domain.LookupReputationName,
		domain.LookupThreatIntelName,
	}
	ungated := []string{
		domain.LookupWhoisName, domain.LookupDNSName, domain.LookupSSLName,
		domain.LookupHeadersName, domain.LookupEmailSecurityName, domain.LookupSubdomainsName,
		domain.LookupCTLogsName, domain.LookupBGPName, domain.LookupFingerprintName,
	}

	for _, plan := range []string{planFree, planBasic, planPro, planAdmin} {
		allowed := plan == planPro || plan == planAdmin
		for _, name := range gated {
			t.Run(plan+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf(`{"domains":["example.com"],"lookups":[%q]}`, name)
				w := post(newTestRouterWithPlan(&mockService{}, plan), body)
				want := http.StatusForbidden
				if allowed {
					want = http.StatusOK
				}
				if w.Code != want {
					t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
				}
				if !allowed {
					msg := assertErrorBody(t, w)
					if !strings.Contains(msg, name) {
						t.Errorf("error = %q, want it to name the gated lookup", msg)
					}
				}
			})
		}
		for _, name := range ungated {
			t.Run(plan+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf(`{"domains":["example.com"],"lookups":[%q]}`, name)
				w := post(newTestRouterWithPlan(&mockService{}, plan), body)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestDomainLookup_UnknownPlanTreatedAsLeastPrivileged(t *testing.T) {
	w := post(newTestRouterWithPlan(&mockService{}, "mystery"),
		`{"domains":["example.com"],"lookups":["screenshot"]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestLookupMinPlan_CoversEveryLookupName(t *testing.T) {
	for _, name := range domain.AllLookupNames {
		if _, ok := lookupMinPlan[name]; !ok {
			t.Errorf("lookupMinPlan is missing %q", name)
		}
	}
	if len(lookupMinPlan) != len(domain.AllLookupNames) {
		t.Errorf("lookupMinPlan has %d entries, want %d", len(lookupMinPlan), len(domain.AllLookupNames))
	}
}

// --- Domain normalization ---

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in    string
		want  string
		valid bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"  example.com  ", "example.com", true},
		{"https://Example.com/", "example.com", true},
		{"http://example.com/path", "example.com", true},
		{"https://user:pass@example.com:8443/x", "example.com", true},
		{"example.com.", "example.com", true},
		{"https://https://example.com", "example.com", true},
		{"", "", false},
		{"nodots", "nodots", false},
		{"example..com", "example..com", false},
		{"1.2.3.4", "1.2.3.4", false},
		{strings.Repeat("a", 250) + ".com", strings.Repeat("a", 250) + ".com", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := normalizeDomain(tt.in)
			if got != tt.want || ok != tt.valid {
				t.Errorf("normalizeDomain(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.valid)
			}
		})
	}
}

func TestDomainLookup_SingleInvalidDomain(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":["not-a-domain"],"lookups":["dns"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	assertErrorBody(t, w)
}

func TestDomainLookup_RawIPRejectedWithMessage(t *testing.T) {
	w := post(newTestRouter(&mockService{}), `{"domains":["8.8.8.8"],"lookups":["dns"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if msg := assertErrorBody(t, w); !strings.Contains(msg, "raw IP addresses") {
		t.Errorf("error = %q, want the raw-IP message", msg)
	}
}

// --- Domain caps ---

// testCfg builds a viper instance seeded with the given overrides.
func testCfg(overrides map[string]any) *viper.Viper {
	v := viper.New()
	for k, val := range overrides {
		v.Set(k, val)
	}
	return v
}

func newTestRouterWithConfig(svc DomainLookupService, plan string, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func TestDomainLookup_MaxDomains_CountsSubmittedEntriesNotUniqueDomains(t *testing.T) {
	cfg := viper.New()
	cfg.Set("domain.max_domains.free", 1)

	// Two entries that normalize to one domain still count as two submissions.
	w := post(newTestRouterWithConfig(&mockService{}, planFree, cfg),
		`{"domains":["example.com","EXAMPLE.com"],"lookups":["dns"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if msg := assertErrorBody(t, w); !strings.Contains(msg, "too many domains") {
		t.Errorf("error = %q", msg)
	}
}

func TestDomainLookup_MaxDomains_WithinLimit(t *testing.T) {
	cfg := viper.New()
	cfg.Set("domain.max_domains.basic", 2)

	w := post(newTestRouterWithConfig(&mockService{}, planBasic, cfg),
		`{"domains":["example.com","example.org"],"lookups":["dns"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestDomainLookup_MaxDomains_SubdomainCapTighter(t *testing.T) {
	cfg := viper.New()
	cfg.Set("domain.max_domains.basic", 5)
	cfg.Set("subdomain.max_domains.basic", 2)

	body := `{"domains":["a.com","b.com","c.com"],"lookups":["%s"]}`

	// Without subdomains the looser cap applies.
	if w := post(newTestRouterWithConfig(&mockService{}, planBasic, cfg), fmt.Sprintf(body, "dns")); w.Code != http.StatusOK {
		t.Fatalf("dns-only status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// With subdomains the tighter cap applies.
	w := post(newTestRouterWithConfig(&mockService{}, planBasic, cfg), fmt.Sprintf(body, "subdomains"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("subdomains status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if msg := assertErrorBody(t, w); !strings.Contains(msg, "subdomains is requested") {
		t.Errorf("error = %q", msg)
	}
}

// --- Context keys for logging and usage tracking ---

func TestDomainLookup_SetsContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(&mockService{stats: domain.CacheStats{Hits: 3, Misses: 1}}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	var (
		lookups            []string
		hits, misses       int
		domainCount, errCt int
		found              = map[string]bool{}
	)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", planPro)
		c.Next()
		for _, k := range []string{"lookups_requested", "cache_hits", "cache_misses", "domain_count", "error_count"} {
			_, found[k] = c.Get(k)
		}
		if v, ok := c.Get("lookups_requested"); ok {
			lookups, _ = v.([]string)
		}
		if v, ok := c.Get("cache_hits"); ok {
			hits, _ = v.(int)
		}
		if v, ok := c.Get("cache_misses"); ok {
			misses, _ = v.(int)
		}
		if v, ok := c.Get("domain_count"); ok {
			domainCount, _ = v.(int)
		}
		if v, ok := c.Get("error_count"); ok {
			errCt, _ = v.(int)
		}
	})

	w := post(r, `{"domains":["example.com","EXAMPLE.com"],"lookups":["dns","ssl"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	for k, ok := range found {
		if !ok {
			t.Errorf("context key %q not set", k)
		}
	}
	if len(lookups) != 2 || !slices.Contains(lookups, "dns") || !slices.Contains(lookups, "ssl") {
		t.Errorf("lookups_requested = %v, want {dns, ssl}", lookups)
	}
	// One unique normalized domain, so one Lookup call contributing its stats.
	if hits != 3 || misses != 1 {
		t.Errorf("cache_hits/cache_misses = %d/%d, want 3/1", hits, misses)
	}
	// domain_count counts submitted entries.
	if domainCount != 2 {
		t.Errorf("domain_count = %d, want 2", domainCount)
	}
	if errCt != 0 {
		t.Errorf("error_count = %d, want 0", errCt)
	}
}

func TestDomainLookup_CacheStatsSummedAcrossDomains(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(&mockService{stats: domain.CacheStats{Hits: 1, Misses: 2}}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	var hits, misses int
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", planPro)
		c.Next()
		if v, ok := c.Get("cache_hits"); ok {
			hits, _ = v.(int)
		}
		if v, ok := c.Get("cache_misses"); ok {
			misses, _ = v.(int)
		}
	})

	post(r, `{"domains":["example.com","example.org"],"lookups":["dns","ssl","whois"]}`)
	if hits != 2 || misses != 4 {
		t.Errorf("cache_hits/cache_misses = %d/%d, want 2/4 (summed across two domains)", hits, misses)
	}
}

func TestDomainLookup_ErrorCountIncludesValidationErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(&mockService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	var errCt int
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", planPro)
		c.Next()
		if v, ok := c.Get("error_count"); ok {
			errCt, _ = v.(int)
		}
	})

	post(r, `{"domains":["example.com","not-a-domain"],"lookups":["dns"]}`)
	if errCt != 1 {
		t.Errorf("error_count = %d, want 1", errCt)
	}
}

// --- Body limits ---

func TestDomainLookup_OversizedBody_Returns413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16)
		c.Next()
	})
	h := New(&mockService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) { c.Set("api_key_plan", planPro); c.Next() })

	w := post(r, `{"domains":["example.com"],"lookups":["dns","ssl","whois","headers"]}`)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body: %s", w.Code, w.Body.String())
	}
}

func TestDomainLookup_RecordsDemandOnRejectedRequests(t *testing.T) {
	// Validation failures still publish what the caller asked for, so usage
	// analytics reflect attempted demand rather than only successful requests.
	cases := []struct {
		name       string
		plan       string
		body       string
		wantStatus int
		wantLookup string
	}{
		{"plan-gated 403", planFree, `{"domains":["example.com"],"lookups":["screenshot"]}`, http.StatusForbidden, "screenshot"},
		{"unknown name 400", planPro, `{"domains":["example.com"],"lookups":["banana"]}`, http.StatusBadRequest, "banana"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			h := New(&mockService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

			var lookups []string
			var domainCount int
			h.RegisterProtectedRoutes(r, func(c *gin.Context) {
				c.Set("api_key_plan", tc.plan)
				c.Next()
				if v, ok := c.Get("lookups_requested"); ok {
					lookups, _ = v.([]string)
				}
				if v, ok := c.Get("domain_count"); ok {
					domainCount, _ = v.(int)
				}
			})

			w := post(r, tc.body)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if !slices.Contains(lookups, tc.wantLookup) {
				t.Errorf("lookups_requested = %v, want it to contain %q", lookups, tc.wantLookup)
			}
			if domainCount != 1 {
				t.Errorf("domain_count = %d, want 1", domainCount)
			}
		})
	}
}
