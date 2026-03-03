package handler

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func (h *Handler) TyposquattingLookup(c *gin.Context) {
	c.Set("typosquatting_requested", true)

	tier, _ := c.Get("api_key_tier")
	if tier != "premium" {
		c.JSON(http.StatusForbidden, gin.H{"error": "typosquatting requires a premium tier subscription"})
		return
	}

	var req domain.TyposquattingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: domains field is required and must be a non-empty array"})
		return
	}

	depth := req.Depth
	if depth == "" {
		depth = "shallow"
	}
	if depth != "shallow" && depth != "deep" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "depth must be \"shallow\" or \"deep\""})
		return
	}

	type indexedResult struct {
		index int
		resp  *domain.TyposquattingResponse
	}

	var valid []struct {
		index int
		name  string
	}
	results := make([]*domain.TyposquattingResponse, len(req.Domains))

	for i, raw := range req.Domains {
		d, ok := normalizeDomain(raw)
		if !ok {
			results[i] = &domain.TyposquattingResponse{
				Domain: raw,
				Depth:  depth,
				Errors: []domain.LookupError{{Lookup: "validation", Message: "invalid domain name"}},
			}
			continue
		}
		valid = append(valid, struct {
			index int
			name  string
		}{i, d})
	}

	if len(valid) == 0 && len(req.Domains) == 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain name"})
		return
	}

	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(valid))

	for _, v := range valid {
		wg.Add(1)
		go func(idx int, name string) {
			defer wg.Done()
			result, cached := h.typosquattingService.Lookup(c.Request.Context(), name, req.Active, depth)
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
