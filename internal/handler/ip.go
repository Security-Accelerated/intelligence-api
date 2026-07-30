package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// validateIP parses and canonicalizes an IP address. Returns the canonical
// string form and validity. Rejects private, loopback, multicast, link-local,
// unspecified, and CGNAT addresses.
func validateIP(raw string) (string, bool) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return raw, false
	}

	// Canonical form handles IPv6 normalization
	canonical := addr.String()

	// Reject non-globally-routable IPs
	if safenet.IsPrivateAddr(addr) {
		return canonical, false
	}

	return canonical, true
}

// IPLookup handles POST /v1/ip/lookup. Non-globally-routable addresses are
// rejected at validation; threat intel is gated to pro and admin plans.
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

	plan, _ := c.Get("api_key_plan")
	planStr, _ := plan.(string)
	if max := h.maxIPs(planStr); max > 0 && len(req.IPs) > max {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many IPs: maximum %d allowed for %s plan", max, planStr)})
		return
	}

	opts := domain.IPLookupOptions{ThreatIntel: req.ThreatIntel}
	c.Set("ip_count", len(req.IPs))
	if req.ThreatIntel {
		c.Set("lookups_requested", []string{domain.LookupThreatIntelName})
	}

	if req.ThreatIntel && planStr != planPro && planStr != planAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "threat_intel requires a pro plan"})
		return
	}

	type indexedResult struct {
		index int
		resp  *domain.IPResponse
	}

	var valid []struct {
		index int
		ip    string
	}
	results := make([]*domain.IPResponse, len(req.IPs))

	for i, raw := range req.IPs {
		ip, ok := validateIP(raw)
		if !ok {
			msg := "invalid or non-routable IP address"
			results[i] = &domain.IPResponse{
				IP:     raw,
				Errors: []domain.LookupError{{Lookup: "validation", Message: msg}},
			}
			continue
		}
		valid = append(valid, struct {
			index int
			ip    string
		}{i, ip})
	}

	if len(valid) == 0 && len(req.IPs) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": results[0].Errors[0].Message})
		return
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, v := range valid {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			result, cached := h.ipService.Lookup(c.Request.Context(), ip, opts)
			result.CacheHit = cached
			ch <- indexedResult{index: idx, resp: result}
		}(v.index, v.ip)
	}

	wg.Wait()
	close(ch)

	// IP responses are cached whole, so each IP counts as a single hit or miss.
	cacheHits, cacheMisses := 0, 0
	for ir := range ch {
		results[ir.index] = ir.resp
		if ir.resp.CacheHit {
			cacheHits++
		} else {
			cacheMisses++
		}
	}
	errorCount := 0
	for _, r := range results {
		if r != nil {
			errorCount += len(r.Errors)
		}
	}
	c.Set("cache_hits", cacheHits)
	c.Set("cache_misses", cacheMisses)
	c.Set("error_count", errorCount)

	c.JSON(http.StatusOK, results)
}
