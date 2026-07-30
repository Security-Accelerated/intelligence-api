package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// ipLookupMinPlan is the single source of truth for which IP lookup names are
// valid and which plan each one requires. Adding a lookup means adding a row
// here — name validation and plan gating both read from this table.
var ipLookupMinPlan = map[string]string{
	domain.LookupGeoName:          planFree,
	domain.LookupASNName:          planFree,
	domain.LookupReverseDNSName:   planFree,
	domain.LookupAbuseContactName: planFree,
	domain.LookupThreatIntelName:  planPro,
}

// validateIP parses and canonicalizes an IP address. Returns the canonical
// string form and validity. Rejects private, loopback, multicast, link-local,
// unspecified, and CGNAT addresses.
func validateIP(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return trimmed, false
	}

	// Canonical form handles IPv6 normalization, so 2001:DB8::1 and
	// 2001:db8:0:0:0:0:0:1 collapse to one result and one cache key.
	canonical := addr.String()

	// Reject non-globally-routable IPs
	if safenet.IsPrivateAddr(addr) {
		return canonical, false
	}

	return canonical, true
}

// ipGroup collects every original request entry that canonicalizes to the same
// address. Clients match results by `ip`; `inputs` lets them reconcile against
// what they sent without reimplementing canonicalization.
type ipGroup struct {
	canonical string
	inputs    []string
	valid     bool
}

// groupIPs canonicalizes and deduplicates the submitted addresses, preserving
// first-appearance order. Inputs are recorded verbatim, exactly as received.
func groupIPs(raw []string) []*ipGroup {
	index := make(map[string]*ipGroup, len(raw))
	groups := make([]*ipGroup, 0, len(raw))

	for _, entry := range raw {
		canonical, ok := validateIP(entry)
		g, exists := index[canonical]
		if !exists {
			g = &ipGroup{canonical: canonical, valid: ok}
			index[canonical] = g
			groups = append(groups, g)
		}
		g.inputs = append(g.inputs, entry)
	}

	return groups
}

// IPLookup handles POST /v1/ip/lookup. It canonicalizes and validates the
// request, resolves the requested lookups against the caller's plan, fans out
// across the unique addresses, and returns a results envelope.
func (h *Handler) IPLookup(c *gin.Context) {
	if h.ipService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ip intelligence not configured"})
		return
	}

	var req domain.IPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: ips field is required and must be a non-empty array"})
		return
	}

	// Normalization runs before every validation step.
	lookups := normalizeLookups(req.Lookups)
	groups := groupIPs(req.IPs)

	// Published before validation so usage tracking and request logs capture
	// attempted demand, including on requests that go on to be rejected.
	c.Set("ip_count", len(req.IPs))
	c.Set("lookups_requested", lookups)

	if len(lookups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": `lookups is required, e.g. ["geo", "asn"]`})
		return
	}

	plan, _ := c.Get("api_key_plan")
	planStr, _ := plan.(string)

	for _, name := range lookups {
		minPlan, ok := ipLookupMinPlan[name]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid lookup %q; valid lookups: %s", name, strings.Join(domain.AllIPLookupNames, ", ")),
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

	opts := domain.IPLookupOptions{Lookups: lookups}

	// Plan IP limits count submitted entries, not unique canonical addresses.
	if max := h.maxIPs(planStr); max > 0 && len(req.IPs) > max {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many IPs: maximum %d allowed for %s plan", max, planStr)})
		return
	}

	results := make([]*domain.IPResponse, len(groups))
	var valid []int
	for i, g := range groups {
		if !g.valid {
			results[i] = &domain.IPResponse{
				IP:     g.canonical,
				Inputs: g.inputs,
				Errors: []domain.LookupError{{Lookup: "validation", Message: "invalid or non-routable IP address"}},
			}
			continue
		}
		valid = append(valid, i)
	}

	if len(valid) == 0 && len(req.IPs) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": results[0].Errors[0].Message})
		return
	}

	type indexedResult struct {
		index int
		resp  *domain.IPResponse
		stats domain.CacheStats
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, idx := range valid {
		g := groups[idx]
		wg.Go(func() {
			result, stats := h.ipService.Lookup(c.Request.Context(), g.canonical, opts)
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

	c.JSON(http.StatusOK, domain.IPResponseEnvelope{Results: results})
}
