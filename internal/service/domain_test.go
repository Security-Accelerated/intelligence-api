package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// mockCache is a hand-written mock for cache.Cache.
type mockCache struct {
	mu       sync.Mutex
	store    map[string][]byte
	getErr   error
	setCalls int
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string][]byte)}
}

func (m *mockCache) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.store[key], nil
}

func (m *mockCache) Set(_ context.Context, key string, data []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = data
	m.setCalls++
	return nil
}

// helpers to build a testable DomainService with stub lookups.

func okWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return &domain.WhoisInfo{DomainName: "example.com"}, nil
}
func okDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return &domain.DNSInfo{A: []string{"1.2.3.4"}}, nil
}
func okSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return &domain.SSLInfo{Subject: "example.com"}, nil
}
func okHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return &domain.HeadersInfo{StatusCode: 200}, nil
}
func okScreenshot(_ context.Context, _ string, _ time.Duration) (*domain.ScreenshotInfo, error) {
	return &domain.ScreenshotInfo{StatusCode: 200, PNG: "iVBOR"}, nil
}

func failWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return nil, errors.New("whois failed")
}
func failDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return nil, errors.New("dns failed")
}
func failSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return nil, errors.New("ssl failed")
}
func failHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return nil, errors.New("headers failed")
}
func failScreenshot(_ context.Context, _ string, _ time.Duration) (*domain.ScreenshotInfo, error) {
	return nil, errors.New("screenshot failed")
}

func okReputation(_ context.Context, _ string) (*domain.ReputationResult, []domain.LookupError) {
	return &domain.ReputationResult{
		Score: 35,
		Risk:  "medium",
		Providers: []*domain.ProviderResult{
			{Listed: true, Category: "phishing", Provider: "spamhaus_dbl", ReturnCode: "127.0.1.4"},
			{Listed: false, Provider: "surbl"},
			{Listed: false, Provider: "uribl"},
			{Listed: false, Provider: "spamhaus_zen"},
		},
	}, nil
}
func failReputation(_ context.Context, _ string) (*domain.ReputationResult, []domain.LookupError) {
	return &domain.ReputationResult{
		Score:     0,
		Risk:      "clean",
		Providers: nil,
	}, []domain.LookupError{
		{Lookup: "reputation:spamhaus_dbl", Message: "spamhaus_dbl lookup: connection refused"},
		{Lookup: "reputation:surbl", Message: "surbl lookup: connection refused"},
		{Lookup: "reputation:uribl", Message: "uribl lookup: connection refused"},
		{Lookup: "reputation:spamhaus_zen", Message: "spamhaus_zen lookup: connection refused"},
	}
}

func okEmailSecurity(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
	return &domain.EmailSecurityInfo{
		SPF: &domain.SPFRecord{Raw: "v=spf1 -all", Version: "spf1", All: "-all"},
	}, nil
}
func failEmailSecurity(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
	return nil, errors.New("email_security failed")
}

func okSubdomains(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
	return &domain.SubdomainInfo{
		Count: 2,
		Subdomains: []domain.SubdomainEntry{
			{Domain: "www.example.com", Source: "crt.sh"},
			{Domain: "mail.example.com", Source: "crt.sh"},
		},
	}, nil
}
func failSubdomains(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
	return nil, errors.New("subdomains failed")
}

func okCTLogs(_ context.Context, _ string, _ int) (*domain.CTLogsInfo, error) {
	return &domain.CTLogsInfo{
		Count: 2,
		Entries: []domain.CTLogEntry{
			{LoggedAt: "2024-01-15T00:00:00", Issuer: "Let's Encrypt", CommonName: "example.com", Serial: "abc123"},
			{LoggedAt: "2023-06-01T00:00:00", Issuer: "DigiCert", CommonName: "*.example.com", Serial: "def456"},
		},
	}, nil
}
func failCTLogs(_ context.Context, _ string, _ int) (*domain.CTLogsInfo, error) {
	return nil, errors.New("ct_logs failed")
}

func okBGP(_ context.Context, _ string) (*domain.BGPInfo, error) {
	return &domain.BGPInfo{
		Records: []domain.ASNRecord{
			{IP: "93.184.216.34", ASN: 15133, Prefix: "93.184.216.0/24", Country: "US", Registry: "arin", Description: "EDGECAST, US"},
		},
	}, nil
}
func failBGP(_ context.Context, _ string) (*domain.BGPInfo, error) {
	return nil, errors.New("bgp failed")
}

func newTestService(mc *mockCache) *DomainService {
	return &DomainService{
		cache:               mc,
		cacheTTL:            5 * time.Minute,
		screenshotTimeout:   15 * time.Second,
		subdomainMaxResults: 500,
		ctLogsMaxEntries:    100,
		lookupWhois:         okWhois,
		lookupDNS:           okDNS,
		lookupSSL:           okSSL,
		lookupHeaders:       okHeaders,
		lookupScreenshot:    okScreenshot,
		lookupReputation:    okReputation,
		lookupEmailSecurity: okEmailSecurity,
		lookupSubdomains:    okSubdomains,
		lookupCTLogs:        okCTLogs,
		lookupBGP:           okBGP,
	}
}

func noOpts() domain.LookupOptions { return domain.LookupOptions{} }

func screenshotOpts() domain.LookupOptions { return domain.LookupOptions{Screenshot: true} }

func reputationOpts() domain.LookupOptions { return domain.LookupOptions{Reputation: true} }

func reputationAndScreenshotOpts() domain.LookupOptions {
	return domain.LookupOptions{Screenshot: true, Reputation: true}
}

func TestLookup_CacheHit(t *testing.T) {
	mc := newMockCache()
	cached := &domain.DomainResponse{Domain: "cached.com"}
	data, _ := json.Marshal(cached)
	mc.store["cached.com"] = data

	svc := newTestService(mc)
	// replace lookups with ones that panic to prove they aren't called
	svc.lookupWhois = func(context.Context, string) (*domain.WhoisInfo, error) {
		t.Fatal("whois lookup should not be called on cache hit")
		return nil, nil
	}

	resp, hit := svc.Lookup(context.Background(), "cached.com", noOpts())
	if !hit {
		t.Error("expected cache hit")
	}
	if resp.Domain != "cached.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "cached.com")
	}
}

func TestLookup_CacheMiss_AllSucceed(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", noOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Whois == nil {
		t.Error("expected Whois to be populated")
	}
	if resp.DNS == nil {
		t.Error("expected DNS to be populated")
	}
	if resp.SSL == nil {
		t.Error("expected SSL to be populated")
	}
	if resp.Headers == nil {
		t.Error("expected Headers to be populated")
	}
	if len(resp.Errors) != 0 {
		t.Errorf("expected no errors, got %v", resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheMiss_AllFail(t *testing.T) {
	mc := newMockCache()
	svc := &DomainService{
		cache:               mc,
		cacheTTL:            5 * time.Minute,
		screenshotTimeout:   15 * time.Second,
		ctLogsMaxEntries:    100,
		lookupWhois:         failWhois,
		lookupDNS:           failDNS,
		lookupSSL:           failSSL,
		lookupHeaders:       failHeaders,
		lookupScreenshot:    failScreenshot,
		lookupReputation:    failReputation,
		lookupEmailSecurity: failEmailSecurity,
		lookupSubdomains:    failSubdomains,
		lookupCTLogs:        failCTLogs,
		lookupBGP:           failBGP,
	}

	resp, hit := svc.Lookup(context.Background(), "fail.com", noOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if len(resp.Errors) != 4 {
		t.Errorf("expected 4 errors, got %d: %v", len(resp.Errors), resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 0 {
		t.Errorf("expected 0 cache Set calls when all lookups fail, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheMiss_PartialSuccess(t *testing.T) {
	mc := newMockCache()
	svc := &DomainService{
		cache:               mc,
		cacheTTL:            5 * time.Minute,
		screenshotTimeout:   15 * time.Second,
		ctLogsMaxEntries:    100,
		lookupWhois:         okWhois,
		lookupDNS:           failDNS,
		lookupSSL:           okSSL,
		lookupHeaders:       failHeaders,
		lookupScreenshot:    okScreenshot,
		lookupReputation:    okReputation,
		lookupEmailSecurity: okEmailSecurity,
		lookupSubdomains:    okSubdomains,
		lookupCTLogs:        okCTLogs,
		lookupBGP:           okBGP,
	}

	resp, hit := svc.Lookup(context.Background(), "partial.com", noOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Whois == nil {
		t.Error("expected Whois to be populated")
	}
	if resp.SSL == nil {
		t.Error("expected SSL to be populated")
	}
	if len(resp.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d: %v", len(resp.Errors), resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call (has data), got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheGetError(t *testing.T) {
	mc := newMockCache()
	mc.getErr = errors.New("redis down")
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", noOpts())
	if hit {
		t.Error("expected cache miss when Get errors")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	// lookups should still proceed and succeed
	if resp.Whois == nil {
		t.Error("expected Whois to be populated after cache error")
	}
}

func TestLookup_ConcurrentSafety(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := svc.Lookup(context.Background(), "concurrent.com", noOpts())
			if resp == nil {
				t.Error("expected non-nil response")
			}
		}()
	}
	wg.Wait()
}

func TestLookup_Screenshot_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", screenshotOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Screenshot == nil {
		t.Fatal("expected Screenshot to be populated")
	}
	if resp.Screenshot.StatusCode != 200 {
		t.Errorf("Screenshot.StatusCode = %d, want 200", resp.Screenshot.StatusCode)
	}
	if resp.Screenshot.PNG != "iVBOR" {
		t.Errorf("Screenshot.PNG = %q, want %q", resp.Screenshot.PNG, "iVBOR")
	}
}

func TestLookup_Screenshot_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	// First: non-screenshot lookup caches under "example.com"
	svc.Lookup(context.Background(), "example.com", noOpts())
	// Second: screenshot lookup caches under "example.com:screenshot"
	svc.Lookup(context.Background(), "example.com", screenshotOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:screenshot"]; !ok {
		t.Error("expected cache entry for screenshot key 'example.com:screenshot'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_Screenshot_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.Screenshot != nil {
		t.Error("expected Screenshot to be nil when not requested")
	}
}

func TestLookup_Screenshot_StatusCodeOnly(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupScreenshot = func(_ context.Context, _ string, _ time.Duration) (*domain.ScreenshotInfo, error) {
		return &domain.ScreenshotInfo{StatusCode: 301}, nil
	}

	resp, _ := svc.Lookup(context.Background(), "example.com", screenshotOpts())
	if resp.Screenshot == nil {
		t.Fatal("expected Screenshot to be populated")
	}
	if resp.Screenshot.StatusCode != 301 {
		t.Errorf("Screenshot.StatusCode = %d, want 301", resp.Screenshot.StatusCode)
	}
	if resp.Screenshot.PNG != "" {
		t.Errorf("Screenshot.PNG = %q, want empty for non-200", resp.Screenshot.PNG)
	}
}

func TestLookup_Screenshot_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupScreenshot = failScreenshot

	resp, _ := svc.Lookup(context.Background(), "example.com", screenshotOpts())
	if resp.Screenshot != nil {
		t.Error("expected Screenshot to be nil on failure")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "screenshot" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a screenshot error in resp.Errors")
	}
}

func TestLookup_Reputation_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", reputationOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Reputation == nil {
		t.Fatal("expected Reputation to be populated")
	}
	if resp.Reputation.Score != 35 {
		t.Errorf("Reputation.Score = %d, want 35", resp.Reputation.Score)
	}
	if resp.Reputation.Risk != "medium" {
		t.Errorf("Reputation.Risk = %q, want %q", resp.Reputation.Risk, "medium")
	}
	if len(resp.Reputation.Providers) != 4 {
		t.Fatalf("len(Reputation.Providers) = %d, want 4", len(resp.Reputation.Providers))
	}
}

func TestLookup_Reputation_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.Reputation != nil {
		t.Error("expected Reputation to be nil when not requested")
	}
}

func TestLookup_Reputation_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupReputation = failReputation

	resp, _ := svc.Lookup(context.Background(), "example.com", reputationOpts())
	if resp.Reputation == nil {
		t.Fatal("expected Reputation to be non-nil (always returned)")
	}
	if resp.Reputation.Score != 0 {
		t.Errorf("expected Score = 0 when all providers fail, got %d", resp.Reputation.Score)
	}
	found := false
	for _, e := range resp.Errors {
		if strings.HasPrefix(e.Lookup, "reputation:") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected reputation provider errors in resp.Errors")
	}
}

func TestLookup_Reputation_PartialProviderFailure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupReputation = func(_ context.Context, _ string) (*domain.ReputationResult, []domain.LookupError) {
		return &domain.ReputationResult{
			Score: 35,
			Risk:  "medium",
			Providers: []*domain.ProviderResult{
				{Listed: true, Category: "phishing", Provider: "spamhaus_dbl", ReturnCode: "127.0.1.4"},
				{Listed: false, Provider: "spamhaus_zen"},
			},
		}, []domain.LookupError{
			{Lookup: "reputation:surbl", Message: "surbl lookup: timeout"},
			{Lookup: "reputation:uribl", Message: "uribl lookup: rate limited"},
		}
	}

	resp, _ := svc.Lookup(context.Background(), "example.com", reputationOpts())
	if resp.Reputation == nil {
		t.Fatal("expected Reputation to be populated")
	}
	if resp.Reputation.Score != 35 {
		t.Errorf("Reputation.Score = %d, want 35", resp.Reputation.Score)
	}
	if len(resp.Reputation.Providers) != 2 {
		t.Errorf("len(Providers) = %d, want 2", len(resp.Reputation.Providers))
	}
	reputationErrs := 0
	for _, e := range resp.Errors {
		if strings.HasPrefix(e.Lookup, "reputation:") {
			reputationErrs++
		}
	}
	if reputationErrs != 2 {
		t.Errorf("expected 2 reputation errors, got %d", reputationErrs)
	}
}

func TestLookup_Reputation_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", noOpts())
	svc.Lookup(context.Background(), "example.com", reputationOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:reputation"]; !ok {
		t.Error("expected cache entry for reputation key 'example.com:reputation'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_ReputationAndScreenshot_CombinedCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", reputationAndScreenshotOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com:reputation+screenshot"]; !ok {
		t.Error("expected cache entry for combined key 'example.com:reputation+screenshot'")
	}
}

func TestLookup_DomainNameReachesLookups(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	var captured string
	svc.lookupWhois = func(_ context.Context, d string) (*domain.WhoisInfo, error) {
		captured = d
		return &domain.WhoisInfo{DomainName: d}, nil
	}

	svc.Lookup(context.Background(), "forwarded.com", noOpts())
	if captured != "forwarded.com" {
		t.Errorf("whois received domain = %q, want %q", captured, "forwarded.com")
	}
}

func TestLookup_CacheUnmarshalError_FallsBackToLookup(t *testing.T) {
	mc := newMockCache()
	mc.store["example.com"] = []byte("{invalid json")
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", noOpts())
	if hit {
		t.Error("expected cache miss when unmarshal fails")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Whois == nil {
		t.Error("expected Whois to be populated from live lookup after cache unmarshal failure")
	}
}

// --- Email Security tests ---

func emailSecurityOpts() domain.LookupOptions { return domain.LookupOptions{EmailSecurity: true} }

func TestLookup_EmailSecurity_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", emailSecurityOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.EmailSecurity == nil {
		t.Fatal("expected EmailSecurity to be populated")
	}
	if resp.EmailSecurity.SPF == nil {
		t.Fatal("expected SPF to be populated")
	}
	if resp.EmailSecurity.SPF.All != "-all" {
		t.Errorf("SPF.All = %q, want %q", resp.EmailSecurity.SPF.All, "-all")
	}
}

func TestLookup_EmailSecurity_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.EmailSecurity != nil {
		t.Error("expected EmailSecurity to be nil when not requested")
	}
}

func TestLookup_EmailSecurity_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupEmailSecurity = failEmailSecurity

	resp, _ := svc.Lookup(context.Background(), "example.com", emailSecurityOpts())
	if resp.EmailSecurity != nil {
		t.Error("expected EmailSecurity to be nil on failure")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "email_security" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected an email_security error in resp.Errors")
	}
}

func TestLookup_EmailSecurity_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", noOpts())
	svc.Lookup(context.Background(), "example.com", emailSecurityOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:email_security"]; !ok {
		t.Error("expected cache entry for email_security key 'example.com:email_security'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_SetEmailSecurityLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	called := false
	svc.SetEmailSecurityLookup(func(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
		called = true
		return &domain.EmailSecurityInfo{}, nil
	})

	svc.Lookup(context.Background(), "example.com", emailSecurityOpts())
	if !called {
		t.Error("expected custom email security lookup to be called")
	}
}

// --- Subdomain tests ---

func subdomainsOpts() domain.LookupOptions { return domain.LookupOptions{Subdomains: true} }

func TestLookup_Subdomains_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", subdomainsOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Subdomains == nil {
		t.Fatal("expected Subdomains to be populated")
	}
	if resp.Subdomains.Count != 2 {
		t.Errorf("Subdomains.Count = %d, want 2", resp.Subdomains.Count)
	}
	if len(resp.Subdomains.Subdomains) != 2 {
		t.Errorf("len(Subdomains.Subdomains) = %d, want 2", len(resp.Subdomains.Subdomains))
	}
}

func TestLookup_Subdomains_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.Subdomains != nil {
		t.Error("expected Subdomains to be nil when not requested")
	}
}

func TestLookup_Subdomains_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupSubdomains = failSubdomains

	resp, _ := svc.Lookup(context.Background(), "example.com", subdomainsOpts())
	if resp.Subdomains != nil {
		t.Error("expected Subdomains to be nil on failure")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "subdomains" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a subdomains error in resp.Errors")
	}
}

func TestLookup_Subdomains_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", noOpts())
	svc.Lookup(context.Background(), "example.com", subdomainsOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:subdomains"]; !ok {
		t.Error("expected cache entry for subdomains key 'example.com:subdomains'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_SetSubdomainLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	called := false
	svc.SetSubdomainLookup(func(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
		called = true
		return &domain.SubdomainInfo{}, nil
	})

	svc.Lookup(context.Background(), "example.com", subdomainsOpts())
	if !called {
		t.Error("expected custom subdomain lookup to be called")
	}
}

// --- CT Logs tests ---

func ctLogsOpts() domain.LookupOptions { return domain.LookupOptions{CTLogs: true} }

func TestLookup_CTLogs_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", ctLogsOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.CTLogs == nil {
		t.Fatal("expected CTLogs to be populated")
	}
	if resp.CTLogs.Count != 2 {
		t.Errorf("CTLogs.Count = %d, want 2", resp.CTLogs.Count)
	}
	if len(resp.CTLogs.Entries) != 2 {
		t.Errorf("len(CTLogs.Entries) = %d, want 2", len(resp.CTLogs.Entries))
	}
}

func TestLookup_CTLogs_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.CTLogs != nil {
		t.Error("expected CTLogs to be nil when not requested")
	}
}

func TestLookup_CTLogs_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupCTLogs = failCTLogs

	resp, _ := svc.Lookup(context.Background(), "example.com", ctLogsOpts())
	if resp.CTLogs != nil {
		t.Error("expected CTLogs to be nil on failure")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "ct_logs" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a ct_logs error in resp.Errors")
	}
}

func TestLookup_CTLogs_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", noOpts())
	svc.Lookup(context.Background(), "example.com", ctLogsOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:ct_logs"]; !ok {
		t.Error("expected cache entry for ct_logs key 'example.com:ct_logs'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_SetCTLogsLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	called := false
	svc.SetCTLogsLookup(func(_ context.Context, _ string, _ int) (*domain.CTLogsInfo, error) {
		called = true
		return &domain.CTLogsInfo{}, nil
	})

	svc.Lookup(context.Background(), "example.com", ctLogsOpts())
	if !called {
		t.Error("expected custom CT logs lookup to be called")
	}
}

// --- BGP/ASN tests ---

func bgpOpts() domain.LookupOptions { return domain.LookupOptions{BGP: true} }

func TestLookup_BGP_Populated(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", bgpOpts())
	if hit {
		t.Error("expected cache miss")
	}
	if resp.BGP == nil {
		t.Fatal("expected BGP to be populated")
	}
	if len(resp.BGP.Records) != 1 {
		t.Errorf("len(BGP.Records) = %d, want 1", len(resp.BGP.Records))
	}
	if resp.BGP.Records[0].ASN != 15133 {
		t.Errorf("BGP.Records[0].ASN = %d, want 15133", resp.BGP.Records[0].ASN)
	}
}

func TestLookup_BGP_NotIncludedWithoutOpt(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", noOpts())
	if resp.BGP != nil {
		t.Error("expected BGP to be nil when not requested")
	}
}

func TestLookup_BGP_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupBGP = failBGP

	resp, _ := svc.Lookup(context.Background(), "example.com", bgpOpts())
	if resp.BGP != nil {
		t.Error("expected BGP to be nil on failure")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "bgp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a bgp error in resp.Errors")
	}
}

func TestLookup_BGP_SeparateCacheKey(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", noOpts())
	svc.Lookup(context.Background(), "example.com", bgpOpts())

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, ok := mc.store["example.com"]; !ok {
		t.Error("expected cache entry for base key 'example.com'")
	}
	if _, ok := mc.store["example.com:bgp"]; !ok {
		t.Error("expected cache entry for bgp key 'example.com:bgp'")
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestLookup_SetBGPLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	called := false
	svc.SetBGPLookup(func(_ context.Context, _ string) (*domain.BGPInfo, error) {
		called = true
		return &domain.BGPInfo{}, nil
	})

	svc.Lookup(context.Background(), "example.com", bgpOpts())
	if !called {
		t.Error("expected custom BGP lookup to be called")
	}
}
