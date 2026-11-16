package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/spf13/viper"
)

// mockEncryptionService records the hosts and lookups it was asked for and
// answers with a key exchange payload.
type mockEncryptionService struct {
	mu    sync.Mutex
	hosts []string
	opts  []domain.EncryptionLookupOptions
	stats domain.CacheStats
}

func (m *mockEncryptionService) Lookup(_ context.Context, host string, opts domain.EncryptionLookupOptions) (*domain.EncryptionResponse, domain.CacheStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts = append(m.hosts, host)
	m.opts = append(m.opts, opts)
	return &domain.EncryptionResponse{
		Host:        host,
		KeyExchange: &domain.KeyExchangeResult{KeyExchangeInfo: &domain.KeyExchangeInfo{Verdict: domain.KeyExchangeClassical}},
	}, m.stats
}

// newEncryptionTestRouter serves the endpoint as a caller on the given plan,
// with small per-plan host limits.
func newEncryptionTestRouter(svc EncryptionLookupService, plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	cfg := viper.New()
	cfg.Set("encryption.max_hosts.free", 1)
	cfg.Set("encryption.max_hosts.pro", 3)

	r := gin.New()
	h := New(Deps{EncryptionService: svc, Config: cfg})
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func postEncryption(r *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/encryption/lookup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestEncryptionLookup_Rejections(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCode  int
		wantError string
	}{
		{"malformed json", `{`, http.StatusBadRequest, "hosts field is required"},
		{"missing hosts", `{"lookups":["certificate"]}`, http.StatusBadRequest, "hosts field is required"},
		{"missing lookups", `{"hosts":["example.com"]}`, http.StatusBadRequest, "lookups is required"},
		{"blank lookups", `{"hosts":["example.com"],"lookups":[" "]}`, http.StatusBadRequest, "lookups is required"},
		// A domain lookup name is not an encryption one: each endpoint has its
		// own table.
		{"unknown lookup", `{"hosts":["example.com"],"lookups":["ssl"]}`, http.StatusBadRequest, `invalid lookup "ssl"; valid lookups: protocols, key_exchange, certificate`},
		{"too many hosts for free", `{"hosts":["a.com","b.com"],"lookups":["certificate"]}`, http.StatusBadRequest, "too many hosts: maximum 1 allowed for free plan"},
		{"duplicates still count toward the limit", `{"hosts":["a.com","A.com"],"lookups":["certificate"]}`, http.StatusBadRequest, "too many hosts"},
		{"single invalid host", `{"hosts":["localhost"],"lookups":["certificate"]}`, http.StatusBadRequest, "invalid hostname"},
		{"single ip literal", `{"hosts":["93.184.216.34"],"lookups":["certificate"]}`, http.StatusBadRequest, "raw IP addresses are not accepted; provide a hostname"},
		// The port a caller writes is dropped, so an address with one is still
		// an address.
		{"ip literal with a port", `{"hosts":["93.184.216.34:8443"],"lookups":["certificate"]}`, http.StatusBadRequest, "raw IP addresses are not accepted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockEncryptionService{}
			w := postEncryption(newEncryptionTestRouter(svc, planFree), tt.body)

			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tt.wantCode, w.Body)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not a JSON object: %v", err)
			}
			if !strings.Contains(body.Error, tt.wantError) {
				t.Errorf("error = %q, want it to contain %q", body.Error, tt.wantError)
			}
			if len(svc.hosts) != 0 {
				t.Errorf("a rejected request still reached the service for %v", svc.hosts)
			}
		})
	}
}

// Every lookup is on the free plan today. This pins that on purpose: gating
// one is a pricing decision, and it should arrive as a deliberate edit to the
// table and this test, not as a side effect.
func TestEncryptionLookup_EveryLookupIsFree(t *testing.T) {
	w := postEncryption(newEncryptionTestRouter(&mockEncryptionService{}, planFree),
		`{"hosts":["example.com"],"lookups":["protocols","key_exchange","certificate"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a free key (body %s)", w.Code, w.Body)
	}

	for _, name := range domain.AllEncryptionLookupNames {
		if _, ok := encryptionLookupMinPlan[name]; !ok {
			t.Errorf("%q is in the catalog but has no plan row, so the handler rejects it", name)
		}
	}
	if len(encryptionLookupMinPlan) != len(domain.AllEncryptionLookupNames) {
		t.Errorf("plan table has %d rows, catalog has %d names", len(encryptionLookupMinPlan), len(domain.AllEncryptionLookupNames))
	}
}

// A plan value this code does not know has no config key of its own. It must
// get the free cap, as it does for lookup gating and rate limiting, and not
// read as "no limit". admin is the one plan that is meant to be unlimited.
func TestEncryptionLookup_UnrecognizedPlanGetsTheFreeHostCap(t *testing.T) {
	body := `{"hosts":["a.com","b.com"],"lookups":["certificate"]}`

	for _, plan := range []string{"enterprise", "basic", ""} {
		w := postEncryption(newEncryptionTestRouter(&mockEncryptionService{}, plan), body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too many hosts: maximum 1 allowed") {
			t.Errorf("plan %q: status = %d, body %s; want the free cap of 1 host", plan, w.Code, w.Body)
		}
	}

	if w := postEncryption(newEncryptionTestRouter(&mockEncryptionService{}, planAdmin), body); w.Code != http.StatusOK {
		t.Errorf("admin: status = %d, want 200 with no host cap; body %s", w.Code, w.Body)
	}
}

func TestCapPlan(t *testing.T) {
	for plan, want := range map[string]string{
		planFree: planFree, planPro: planPro, planAdmin: planAdmin,
		"basic": planFree, "": planFree,
	} {
		if got := capPlan(plan); got != want {
			t.Errorf("capPlan(%q) = %q, want %q", plan, got, want)
		}
	}
}

func TestEncryptionLookup_NormalizesDeduplicatesAndKeepsInvalidEntries(t *testing.T) {
	svc := &mockEncryptionService{}
	w := postEncryption(newEncryptionTestRouter(svc, planPro),
		`{"hosts":["https://Example.com:8443/path","example.com","localhost"],"lookups":[" Key_Exchange ","key_exchange"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body)
	}
	var env domain.EncryptionResponseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(env.Results) != 2 {
		t.Fatalf("got %d results, want 2 (one per unique host)", len(env.Results))
	}

	good := env.Results[0]
	if good.Host != "example.com" || len(good.Inputs) != 2 || good.KeyExchange == nil {
		t.Errorf("first result = %+v, want example.com with both inputs and a key_exchange payload", good)
	}
	bad := env.Results[1]
	if bad.Host != "localhost" || len(bad.Errors) != 1 || bad.Errors[0].Lookup != "validation" || bad.Errors[0].Message != "invalid hostname" {
		t.Errorf("second result = %+v, want a validation error for localhost", bad)
	}

	if len(svc.hosts) != 1 || svc.hosts[0] != "example.com" {
		t.Errorf("service was called for %v, want exactly one call for example.com", svc.hosts)
	}
	if got := svc.opts[0].Lookups; len(got) != 1 || got[0] != domain.LookupKeyExchangeName {
		t.Errorf("service received lookups %v, want [key_exchange]", got)
	}
}

func TestEncryptionLookup_NilServiceIsUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(Deps{}).RegisterProtectedRoutes(r)

	if w := postEncryption(r, `{"hosts":["example.com"],"lookups":["certificate"]}`); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestEncryptionLookup_SetsContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{
		EncryptionService: &mockEncryptionService{stats: domain.CacheStats{Hits: 2, Misses: 1}},
	})

	var lookups []string
	var hits, misses, hostCount int
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
		if v, ok := c.Get("host_count"); ok {
			hostCount, _ = v.(int)
		}
	})

	postEncryption(r, `{"hosts":["example.com","EXAMPLE.com"],"lookups":["protocols","certificate"]}`)

	if len(lookups) != 2 {
		t.Errorf("lookups_requested = %v, want 2", lookups)
	}
	// Two entries collapse to one host, so one Lookup call.
	if hits != 2 || misses != 1 {
		t.Errorf("cache_hits/cache_misses = %d/%d, want 2/1", hits, misses)
	}
	// host_count counts submitted entries.
	if hostCount != 2 {
		t.Errorf("host_count = %d, want 2", hostCount)
	}
}
