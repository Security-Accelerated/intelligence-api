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

// encryptionLookupMinPlan is the single source of truth for which encryption
// lookup names are valid and which plan each one requires. Adding a lookup
// means adding a row here — name validation and plan gating both read from
// this table.
//
// All three are on the free plan: they spend no upstream quota, only a handful
// of handshakes of our own, and the per-plan host cap and rate limit already
// bound that. Gating one later is a one-word change.
var encryptionLookupMinPlan = map[string]string{
	domain.LookupProtocolsName:   planFree,
	domain.LookupKeyExchangeName: planFree,
	domain.LookupCertificateName: planFree,
}

// hostValidationMessage explains why a submitted host was rejected. Hosts are
// normalized by the same rules as domains (normalizeDomain), so the port a
// caller writes is dropped: every encryption lookup goes to 443.
func hostValidationMessage(normalized string) string {
	if net.ParseIP(normalized) != nil {
		return "raw IP addresses are not accepted; provide a hostname"
	}
	return "invalid hostname"
}

// EncryptionLookup handles POST /v1/encryption/lookup. It normalizes and
// validates the request, resolves the requested lookups against the caller's
// plan, fans out across the unique hosts, and returns a results envelope.
func (h *Handler) EncryptionLookup(c *gin.Context) {
	if h.encryptionService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "encryption posture not configured"})
		return
	}

	var req domain.EncryptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: hosts field is required and must be a non-empty array"})
		return
	}

	// Normalization runs before every validation step.
	lookups := normalizeLookups(req.Lookups)
	groups := groupDomains(req.Hosts)

	// Published before validation so usage tracking and request logs capture
	// attempted demand, including on requests that go on to be rejected.
	c.Set("host_count", len(req.Hosts))
	c.Set("lookups_requested", lookups)

	if len(lookups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": `lookups is required, e.g. ["key_exchange", "certificate"]`})
		return
	}

	plan, _ := c.Get("api_key_plan")
	planStr, _ := plan.(string)

	for _, name := range lookups {
		minPlan, ok := encryptionLookupMinPlan[name]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid lookup %q; valid lookups: %s", name, strings.Join(domain.AllEncryptionLookupNames, ", ")),
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

	opts := domain.EncryptionLookupOptions{Lookups: lookups}

	// Plan host limits count submitted entries, not unique normalized hosts.
	if limit := h.maxHosts(planStr); limit > 0 && len(req.Hosts) > limit {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many hosts: maximum %d allowed for %s plan", limit, planStr)})
		return
	}

	results := make([]*domain.EncryptionResponse, len(groups))
	var valid []int
	for i, g := range groups {
		if !g.valid {
			results[i] = &domain.EncryptionResponse{
				Host:   g.normalized,
				Inputs: g.inputs,
				Errors: []domain.LookupError{{Lookup: "validation", Message: hostValidationMessage(g.normalized)}},
			}
			continue
		}
		valid = append(valid, i)
	}

	if len(valid) == 0 && len(req.Hosts) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": results[0].Errors[0].Message})
		return
	}

	type indexedResult struct {
		index int
		resp  *domain.EncryptionResponse
		stats domain.CacheStats
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, idx := range valid {
		g := groups[idx]
		wg.Go(func() {
			result, stats := h.encryptionService.Lookup(c.Request.Context(), g.normalized, opts)
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

	c.JSON(http.StatusOK, domain.EncryptionResponseEnvelope{Results: results})
}
