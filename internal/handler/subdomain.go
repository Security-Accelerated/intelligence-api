package handler

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func (h *Handler) SubdomainLookup(c *gin.Context) {
	c.Set("subdomain_requested", true)
	c.Set("check_live_requested", false)

	tier, _ := c.Get("api_key_tier")
	tierStr, _ := tier.(string)
	if tierStr != "premium" {
		c.JSON(http.StatusForbidden, gin.H{"error": "subdomain enumeration requires a premium tier subscription"})
		return
	}

	var req domain.SubdomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: domains field is required and must be a non-empty array"})
		return
	}

	if max := h.maxDomains("subdomain", tierStr); max > 0 && len(req.Domains) > max {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many domains: maximum %d allowed for %s tier", max, tierStr)})
		return
	}

	c.Set("check_live_requested", req.CheckLive)

	type indexedResult struct {
		index int
		resp  *domain.SubdomainResponse
	}

	var valid []struct {
		index int
		name  string
	}
	results := make([]*domain.SubdomainResponse, len(req.Domains))

	for i, raw := range req.Domains {
		d, ok := normalizeDomain(raw)
		if !ok {
			msg := "invalid domain name"
			if net.ParseIP(d) != nil {
				msg = "raw IP addresses are not accepted; provide a domain name"
			}
			results[i] = &domain.SubdomainResponse{
				Domain: raw,
				Errors: []domain.LookupError{{Lookup: "validation", Message: msg}},
			}
			continue
		}
		valid = append(valid, struct {
			index int
			name  string
		}{i, d})
	}

	if len(valid) == 0 && len(req.Domains) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": results[0].Errors[0].Message})
		return
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, v := range valid {
		wg.Add(1)
		go func(idx int, name string) {
			defer wg.Done()
			result, cached := h.subdomainService.Lookup(c.Request.Context(), name, req.CheckLive)
			result.CacheHit = cached
			ch <- indexedResult{index: idx, resp: result}
		}(v.index, v.name)
	}

	wg.Wait()
	close(ch)

	anyCached := false
	for ir := range ch {
		results[ir.index] = ir.resp
		if ir.resp.CacheHit {
			anyCached = true
		}
	}
	c.Set("cache_hit", anyCached)

	c.JSON(http.StatusOK, results)
}
