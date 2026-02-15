package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func (h *Handler) DomainLookup(c *gin.Context) {
	var req domain.DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: domain field is required"})
		return
	}

	d := strings.TrimSpace(req.Domain)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimRight(d, "/")

	if d == "" || !strings.Contains(d, ".") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain name"})
		return
	}

	result, cached := h.domainService.Lookup(c.Request.Context(), d)
	c.Set("cache_hit", cached)
	c.JSON(http.StatusOK, result)
}
