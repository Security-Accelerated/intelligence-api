package handler

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func normalizeDomain(raw string) (string, bool) {
	d := strings.TrimSpace(raw)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimRight(d, "/")
	if d == "" || !strings.Contains(d, ".") {
		return d, false
	}
	if net.ParseIP(d) != nil {
		return d, false
	}
	return d, true
}

func (h *Handler) DomainLookup(c *gin.Context) {
	var req domain.DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: domains field is required and must be a non-empty array"})
		return
	}

	opts := domain.LookupOptions{Screenshot: req.Screenshot, Reputation: req.Reputation}
	c.Set("screenshot_requested", req.Screenshot)
	c.Set("reputation_requested", req.Reputation)

	if req.Screenshot {
		tier, _ := c.Get("api_key_tier")
		if tier != "premium" {
			c.JSON(http.StatusForbidden, gin.H{"error": "screenshot requires a premium tier subscription"})
			return
		}
	}

	if req.Reputation {
		tier, _ := c.Get("api_key_tier")
		if tier != "premium" {
			c.JSON(http.StatusForbidden, gin.H{"error": "reputation requires a premium tier subscription"})
			return
		}
	}

	type indexedResult struct {
		index int
		resp  *domain.DomainResponse
	}

	var valid []struct {
		index int
		name  string
	}
	results := make([]*domain.DomainResponse, len(req.Domains))

	for i, raw := range req.Domains {
		d, ok := normalizeDomain(raw)
		if !ok {
			msg := "invalid domain name"
			if net.ParseIP(d) != nil {
				msg = "raw IP addresses are not accepted; provide a domain name"
			}
			results[i] = &domain.DomainResponse{
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
			result, cached := h.domainService.Lookup(c.Request.Context(), name, opts)
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
