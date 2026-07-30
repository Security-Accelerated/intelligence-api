package handler

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// Plan names, ordered by capability. Anything unrecognized is treated as the
// least privileged plan.
const (
	planFree  = "free"
	planBasic = "basic"
	planPro   = "pro"
	planAdmin = "admin"
)

var planRank = map[string]int{
	planFree:  0,
	planBasic: 1,
	planPro:   2,
	planAdmin: 3,
}

// lookupMinPlan is the single source of truth for which lookup names are valid
// and which plan each one requires. Adding a lookup means adding a row here —
// name validation and plan gating both read from this table.
var lookupMinPlan = map[string]string{
	domain.LookupWhoisName:         planFree,
	domain.LookupDNSName:           planFree,
	domain.LookupSSLName:           planFree,
	domain.LookupHeadersName:       planFree,
	domain.LookupEmailSecurityName: planFree,
	domain.LookupSubdomainsName:    planFree,
	domain.LookupCTLogsName:        planFree,
	domain.LookupBGPName:           planFree,
	domain.LookupFingerprintName:   planFree,
	domain.LookupScreenshotName:    planPro,
	domain.LookupReputationName:    planPro,
	domain.LookupThreatIntelName:   planPro,
}

func normalizeDomain(raw string) (string, bool) {
	d := strings.TrimSpace(raw)

	// Strip any scheme (http, https, ftp, etc.). Loop handles malformed
	// double-scheme inputs like "https://https://example.com".
	for {
		if i := strings.Index(d, "://"); i != -1 {
			d = d[i+3:]
		} else {
			break
		}
	}

	// Strip path, query, fragment first so '@' in the path can't poison
	// the host (e.g. "example.com/path@evil.com").
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(d, sep); i != -1 {
			d = d[:i]
		}
	}
	// Strip userinfo (user:pass@) from authority before removing port,
	// since userinfo may contain a colon.
	if at := strings.Index(d, "@"); at != -1 {
		d = d[at+1:]
	}
	// Now strip port.
	if i := strings.Index(d, ":"); i != -1 {
		d = d[:i]
	}

	d = strings.TrimRight(d, ".")
	// DNS names are case-insensitive, so lowercasing is always safe and makes
	// "Example.COM" and "example.com" share one cache key.
	d = strings.ToLower(d)

	if d == "" || !strings.Contains(d, ".") {
		return d, false
	}
	if net.ParseIP(d) != nil {
		return d, false
	}
	// FQDN max length per RFC 1035.
	if len(d) > 253 {
		return d, false
	}
	// Reject consecutive dots (e.g. "example..com").
	if strings.Contains(d, "..") {
		return d, false
	}
	return d, true
}

// normalizeLookups trims, lowercases and deduplicates requested lookup names.
// It runs before every validation step, so `[" SSL "]` is accepted as `ssl` and
// `[" "]` correctly collapses to empty.
func normalizeLookups(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, name := range raw {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// domainGroup collects every original request entry that normalizes to the same
// domain. Clients match results by `domain`; `inputs` lets them reconcile
// against what they sent without reimplementing normalization.
type domainGroup struct {
	normalized string
	inputs     []string
	valid      bool
	errMsg     string
}

// groupDomains normalizes and deduplicates the submitted domains, preserving
// first-appearance order. Inputs are recorded verbatim, exactly as received.
func groupDomains(raw []string) []*domainGroup {
	index := make(map[string]*domainGroup, len(raw))
	groups := make([]*domainGroup, 0, len(raw))

	for _, entry := range raw {
		normalized, ok := normalizeDomain(entry)
		g, exists := index[normalized]
		if !exists {
			g = &domainGroup{normalized: normalized, valid: ok}
			if !ok {
				g.errMsg = "invalid domain name"
				if net.ParseIP(normalized) != nil {
					g.errMsg = "raw IP addresses are not accepted; provide a domain name"
				}
			}
			index[normalized] = g
			groups = append(groups, g)
		}
		g.inputs = append(g.inputs, entry)
	}

	return groups
}

func (h *Handler) DomainLookup(c *gin.Context) {
	if h.domainService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "domain intelligence not configured"})
		return
	}

	var req domain.DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: domains field is required and must be a non-empty array"})
		return
	}

	// Normalization runs before every validation step.
	lookups := normalizeLookups(req.Lookups)
	groups := groupDomains(req.Domains)

	// Published before validation so usage tracking and request logs capture
	// attempted demand, including on requests that go on to be rejected.
	c.Set("domain_count", len(req.Domains))
	c.Set("lookups_requested", lookups)

	if len(lookups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": `lookups is required, e.g. ["dns", "ssl"]`})
		return
	}

	plan, _ := c.Get("api_key_plan")
	planStr, _ := plan.(string)

	for _, name := range lookups {
		minPlan, ok := lookupMinPlan[name]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid lookup %q; valid lookups: %s", name, strings.Join(domain.AllLookupNames, ", ")),
			})
			return
		}
		if planRank[planStr] < planRank[minPlan] {
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("%s requires a %s plan", name, minPlan),
			})
			return
		}
	}

	opts := domain.LookupOptions{Lookups: lookups}

	// Plan domain limits count submitted entries, not unique normalized domains.
	if max := h.maxDomains("domain", planStr); max > 0 && len(req.Domains) > max {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many domains: maximum %d allowed for %s plan", max, planStr)})
		return
	}
	// Subdomain enumeration fans out to crt.sh per domain, so enforce a tighter
	// per-plan cap when subdomains is requested.
	if opts.Has(domain.LookupSubdomainsName) {
		if max := h.maxDomains("subdomain", planStr); max > 0 && len(req.Domains) > max {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many domains: maximum %d allowed for %s plan when subdomains is requested", max, planStr)})
			return
		}
	}

	results := make([]*domain.DomainResponse, len(groups))
	var valid []int
	for i, g := range groups {
		if !g.valid {
			results[i] = &domain.DomainResponse{
				Domain: g.normalized,
				Inputs: g.inputs,
				Errors: []domain.LookupError{{Lookup: "validation", Message: g.errMsg}},
			}
			continue
		}
		valid = append(valid, i)
	}

	if len(valid) == 0 && len(req.Domains) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": results[0].Errors[0].Message})
		return
	}

	type indexedResult struct {
		index int
		resp  *domain.DomainResponse
		stats domain.CacheStats
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, idx := range valid {
		g := groups[idx]
		wg.Go(func() {
			result, stats := h.domainService.Lookup(c.Request.Context(), g.normalized, opts)
			result.Inputs = g.inputs
			ch <- indexedResult{index: idx, resp: result, stats: stats}
		})
	}

	wg.Wait()
	close(ch)

	cacheHits, cacheMisses := 0, 0
	for ir := range ch {
		results[ir.index] = ir.resp
		cacheHits += ir.stats.Hits
		cacheMisses += ir.stats.Misses
	}

	errorCount := 0
	for _, r := range results {
		errorCount += len(r.Errors)
	}
	c.Set("cache_hits", cacheHits)
	c.Set("cache_misses", cacheMisses)
	c.Set("error_count", errorCount)

	c.JSON(http.StatusOK, domain.DomainResponseEnvelope{Results: results})
}
