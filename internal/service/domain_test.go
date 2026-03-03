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

func newTestService(mc *mockCache) *DomainService {
	return &DomainService{
		cache:             mc,
		cacheTTL:          5 * time.Minute,
		screenshotTimeout: 15 * time.Second,
		lookupWhois:       okWhois,
		lookupDNS:         okDNS,
		lookupSSL:         okSSL,
		lookupHeaders:     okHeaders,
		lookupScreenshot:  okScreenshot,
		lookupReputation:   okReputation,
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
		cache:             mc,
		cacheTTL:          5 * time.Minute,
		screenshotTimeout: 15 * time.Second,
		lookupWhois:       failWhois,
		lookupDNS:         failDNS,
		lookupSSL:         failSSL,
		lookupHeaders:     failHeaders,
		lookupScreenshot:  failScreenshot,
		lookupReputation:   failReputation,
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
		cache:             mc,
		cacheTTL:          5 * time.Minute,
		screenshotTimeout: 15 * time.Second,
		lookupWhois:       okWhois,
		lookupDNS:         failDNS,
		lookupSSL:         okSSL,
		lookupHeaders:     failHeaders,
		lookupScreenshot:  okScreenshot,
		lookupReputation:   okReputation,
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
