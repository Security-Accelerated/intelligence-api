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

func normalizeDomain(raw string) (string, bool) {
	d := strings.TrimSpace(raw)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimRight(d, "/")

	// Reject anything that still looks like a URL (paths, query strings, fragments, ports).
	if strings.ContainsAny(d, "/:?#@") {
		return d, false
	}

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
	// Reject trailing dots and consecutive dots (e.g. "example..com").
	if strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return d, false
	}
	return d, true
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

	plan, _ := c.Get("api_key_plan")
	planStr, _ := plan.(string)
	if max := h.maxDomains("domain", planStr); max > 0 && len(req.Domains) > max {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many domains: maximum %d allowed for %s plan", max, planStr)})
		return
	}

	opts := domain.LookupOptions{Screenshot: req.Screenshot, Reputation: req.Reputation, EmailSecurity: req.EmailSecurity, Subdomains: req.Subdomains, CTLogs: req.CTLogs, BGP: req.BGP, Fingerprint: req.Fingerprint, ThreatIntel: req.ThreatIntel}
	c.Set("domain_count", len(req.Domains))
	c.Set("screenshot_requested", req.Screenshot)
	c.Set("reputation_requested", req.Reputation)
	c.Set("email_security_requested", req.EmailSecurity)
	c.Set("subdomain_requested", req.Subdomains)
	c.Set("ct_logs_requested", req.CTLogs)
	c.Set("bgp_requested", req.BGP)
	c.Set("fingerprint_requested", req.Fingerprint)
	c.Set("threat_intel_requested", req.ThreatIntel)

	if req.Screenshot && planStr != "pro" && planStr != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "screenshot requires a pro plan"})
		return
	}

	if req.Reputation && planStr != "pro" && planStr != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "reputation requires a pro plan"})
		return
	}

	if req.ThreatIntel && planStr != "pro" && planStr != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "threat_intel requires a pro plan"})
		return
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
	errorCount := 0
	for ir := range ch {
		results[ir.index] = ir.resp
		if ir.resp.CacheHit {
			anyCached = true
		}
		errorCount += len(ir.resp.Errors)
	}
	c.Set("cache_hit", anyCached)
	c.Set("error_count", errorCount)

	c.JSON(http.StatusOK, results)
}
