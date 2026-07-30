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
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/spf13/viper"
)

type mockIPService struct {
	mu       sync.Mutex
	resp     *domain.IPResponse
	stats    domain.CacheStats
	lastOpts domain.IPLookupOptions
	seen     []string
}

func (m *mockIPService) Lookup(_ context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, domain.CacheStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastOpts = opts
	m.seen = append(m.seen, ip)
	if m.resp != nil {
		return m.resp, m.stats
	}
	return &domain.IPResponse{IP: ip}, m.stats
}

func (m *mockIPService) ips() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Clone(m.seen)
	slices.Sort(out)
	return out
}

func (m *mockIPService) opts() domain.IPLookupOptions {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastOpts
}

// postIP issues an IP lookup request and returns the recorder.
func postIP(r *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// decodeIPResults unwraps the {"results": [...]} envelope.
func decodeIPResults(t *testing.T, w *httptest.ResponseRecorder) []*domain.IPResponse {
	t.Helper()
	var env domain.IPResponseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to unmarshal response envelope: %v\nbody: %s", err, w.Body.String())
	}
	return env.Results
}

func newIPTestRouter(svc IPLookupService) *gin.Engine {
	return newIPTestRouterWithPlan(svc, "pro")
}

func newIPTestRouterWithPlan(svc IPLookupService, plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, svc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func newIPTestRouterWithCfg(svc IPLookupService, plan string, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, svc, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

// --- Basic functionality ---

func TestIPLookup_ValidIP(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIPLookup_MultipleIPs(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	results := decodeIPResults(t, w)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
}

func TestIPLookup_IPv6(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["2001:4860:4860::8888"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// --- Validation ---

func TestIPLookup_InvalidIP(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["not-an-ip"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIPLookup_PrivateIP_Rejected(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	tests := []struct {
		name string
		ip   string
	}{
		{"loopback", "127.0.0.1"},
		{"private", "10.0.0.1"},
		{"link-local", "169.254.169.254"},
		{"private v6", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			body := `{"ips":["` + tt.ip + `"],"lookups":["geo","asn"]}`
			req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d for %s", w.Code, http.StatusBadRequest, tt.ip)
			}
		})
	}
}

func TestIPLookup_MixedValidInvalid(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","127.0.0.1"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	results := decodeIPResults(t, w)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	// First should be valid, second should have validation error
	if len(results[0].Errors) > 0 {
		t.Error("first IP should not have errors")
	}
	if len(results[1].Errors) == 0 {
		t.Error("second IP (private) should have validation error")
	}
}

func TestIPLookup_EmptyArray(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":[],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- Plan gating ---

func TestIPLookup_ThreatIntel_ProAllowed(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPLookup_ThreatIntel_AdminAllowed(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPLookup_ThreatIntel_FreeForbidden(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "free")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIPLookup_ThreatIntel_BasicForbidden(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- Max IPs per plan ---

func TestIPLookup_MaxIPs_ExceedsLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"ip.max_ips.basic": 2,
	})

	r := newIPTestRouterWithCfg(&mockIPService{}, "basic", cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1","9.9.9.9"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestIPLookup_MaxIPs_AtLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"ip.max_ips.basic": 2,
	})

	r := newIPTestRouterWithCfg(&mockIPService{}, "basic", cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"],"lookups":["geo","asn"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Options passthrough ---

func TestIPLookup_OptsPassedToService(t *testing.T) {
	svc := &mockIPService{}
	r := newIPTestRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if !svc.opts().Has(domain.LookupThreatIntelName) {
		t.Errorf("service opts = %v, want threat_intel", svc.opts().Lookups)
	}
}

// --- Body limit ---

func TestIPLookup_OversizedBody_Returns413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.BodyLimit(128))
	h := New(nil, &mockIPService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", "pro")
		c.Next()
	})

	w := httptest.NewRecorder()
	oversized := `{"ips":["` + strings.Repeat("8.8.8.8,", 50) + `8.8.8.8"],"lookups":["geo","asn"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}

// --- Selectable lookups: validation, normalization, envelope ---

func TestIPLookup_ReturnsResultsEnvelope(t *testing.T) {
	w := postIP(newIPTestRouter(&mockIPService{}), `{"ips":["8.8.8.8"],"lookups":["geo"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &top); err != nil {
		t.Fatalf("response is not a JSON object: %v; body: %s", err, w.Body.String())
	}
	if _, ok := top["results"]; !ok {
		t.Fatalf("response missing the results key: %s", w.Body.String())
	}
	if len(top) != 1 {
		t.Errorf("envelope should carry only results, got keys %v", top)
	}
}

func TestIPLookup_NoTopLevelCacheHit(t *testing.T) {
	w := postIP(newIPTestRouter(&mockIPService{stats: domain.CacheStats{Hits: 1}}),
		`{"ips":["8.8.8.8"],"lookups":["geo"]}`)

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

func TestIPLookup_MissingLookups(t *testing.T) {
	for _, body := range []string{
		`{"ips":["8.8.8.8"]}`,
		`{"ips":["8.8.8.8"],"lookups":[]}`,
		`{"ips":["8.8.8.8"],"lookups":["  "]}`,
	} {
		t.Run(body, func(t *testing.T) {
			w := postIP(newIPTestRouter(&mockIPService{}), body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if msg := assertErrorBody(t, w); !strings.Contains(msg, "lookups is required") {
				t.Errorf("error = %q", msg)
			}
		})
	}
}

func TestIPLookup_UnknownLookupNamesTheOffender(t *testing.T) {
	w := postIP(newIPTestRouter(&mockIPService{}), `{"ips":["8.8.8.8"],"lookups":["geo","banana"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if msg := assertErrorBody(t, w); !strings.Contains(msg, "banana") {
		t.Errorf("error = %q, want it to name the invalid entry", msg)
	}
}

func TestIPLookup_DomainOnlyLookupRejected(t *testing.T) {
	// whois is a valid domain lookup but meaningless for an IP — the two
	// catalogs are separate.
	w := postIP(newIPTestRouter(&mockIPService{}), `{"ips":["8.8.8.8"],"lookups":["whois"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if msg := assertErrorBody(t, w); !strings.Contains(msg, "whois") {
		t.Errorf("error = %q", msg)
	}
}

func TestIPLookup_PlanGating(t *testing.T) {
	ungated := []string{
		domain.LookupGeoName, domain.LookupASNName,
		domain.LookupReverseDNSName, domain.LookupAbuseContactName,
	}
	for _, plan := range []string{planFree, planBasic, planPro, planAdmin} {
		allowed := plan == planPro || plan == planAdmin

		t.Run(plan+"/threat_intel", func(t *testing.T) {
			w := postIP(newIPTestRouterWithPlan(&mockIPService{}, plan),
				`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`)
			want := http.StatusForbidden
			if allowed {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
			}
		})

		for _, name := range ungated {
			t.Run(plan+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf(`{"ips":["8.8.8.8"],"lookups":[%q]}`, name)
				w := postIP(newIPTestRouterWithPlan(&mockIPService{}, plan), body)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestIPLookupMinPlan_CoversEveryLookupName(t *testing.T) {
	for _, name := range domain.AllIPLookupNames {
		if _, ok := ipLookupMinPlan[name]; !ok {
			t.Errorf("ipLookupMinPlan is missing %q", name)
		}
	}
	if len(ipLookupMinPlan) != len(domain.AllIPLookupNames) {
		t.Errorf("ipLookupMinPlan has %d entries, want %d", len(ipLookupMinPlan), len(domain.AllIPLookupNames))
	}
}

func TestIPLookup_CanonicalizationDedupesAndRecordsInputs(t *testing.T) {
	svc := &mockIPService{}
	// Three spellings of the same IPv6 address plus one distinct IPv4.
	w := postIP(newIPTestRouter(svc),
		`{"ips":["2001:DB8::1","2001:db8:0:0:0:0:0:1"," 8.8.8.8 "],"lookups":["geo"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	results := decodeIPResults(t, w)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 unique canonical addresses: %+v", len(results), results)
	}

	var v6 *domain.IPResponse
	for _, r := range results {
		if strings.Contains(r.IP, ":") {
			v6 = r
		}
	}
	if v6 == nil {
		t.Fatalf("no IPv6 result: %+v", results)
	}
	// 2001:db8::1 is documentation space, so it is rejected as non-routable —
	// but the two spellings must still collapse into one result carrying both
	// verbatim inputs.
	want := []string{"2001:DB8::1", "2001:db8:0:0:0:0:0:1"}
	if !slices.Equal(v6.Inputs, want) {
		t.Errorf("inputs = %v, want %v (verbatim)", v6.Inputs, want)
	}
}

func TestIPLookup_LookupNamesNormalized(t *testing.T) {
	svc := &mockIPService{}
	w := postIP(newIPTestRouter(svc), `{"ips":["8.8.8.8"],"lookups":[" GEO ","geo","ASN"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	got := svc.opts().Lookups
	if len(got) != 2 {
		t.Fatalf("service received %v, want 2 deduped lookups", got)
	}
	for _, want := range []string{"geo", "asn"} {
		if !slices.Contains(got, want) {
			t.Errorf("service received %v, missing %q", got, want)
		}
	}
}

func TestIPLookup_SetsContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, &mockIPService{stats: domain.CacheStats{Hits: 2, Misses: 1}}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	var lookups []string
	var hits, misses, ipCount int
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", planPro)
		c.Next()
		if v, ok := c.Get("lookups_requested"); ok {
			lookups, _ = v.([]string)
		}
		if v, ok := c.Get("cache_hits"); ok {
			hits, _ = v.(int)
		}
		if v, ok := c.Get("cache_misses"); ok {
			misses, _ = v.(int)
		}
		if v, ok := c.Get("ip_count"); ok {
			ipCount, _ = v.(int)
		}
	})

	postIP(r, `{"ips":["8.8.8.8","8.8.8.8"],"lookups":["geo","asn"]}`)

	if len(lookups) != 2 {
		t.Errorf("lookups_requested = %v, want 2", lookups)
	}
	// Two entries collapse to one canonical address, so one Lookup call.
	if hits != 2 || misses != 1 {
		t.Errorf("cache_hits/cache_misses = %d/%d, want 2/1", hits, misses)
	}
	// ip_count counts submitted entries.
	if ipCount != 2 {
		t.Errorf("ip_count = %d, want 2", ipCount)
	}
}
