package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"go.uber.org/zap"
)

// GetFingerprints returns the current technology fingerprint rules.
func (h *Handler) GetFingerprints(c *gin.Context) {
	if h.fingerprintService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "fingerprint service not configured"})
		return
	}

	rules := h.fingerprintService.GetRules()
	c.JSON(http.StatusOK, gin.H{
		"count": len(rules),
		"rules": rules,
	})
}

// UpdateFingerprints replaces the technology fingerprint rules.
func (h *Handler) UpdateFingerprints(c *gin.Context) {
	if h.fingerprintService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "fingerprint service not configured"})
		return
	}

	var rules []domain.TechRule
	if err := c.ShouldBindJSON(&rules); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: expected a JSON array of rules"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rules array must not be empty"})
		return
	}

	apiKeyID := 0
	if v, ok := c.Get("api_key_id"); ok {
		if id, ok := v.(int); ok {
			apiKeyID = id
		}
	}

	if err := h.fingerprintService.UpdateRules(c.Request.Context(), rules, apiKeyID); err != nil {
		var validationErr *service.ValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Message})
			return
		}
		logging.Logger().Error("fingerprint update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update fingerprint rules"})
		return
	}

	logging.Logger().Info("fingerprint rules updated",
		zap.Int("api_key_id", apiKeyID),
		zap.Int("rule_count", len(rules)),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "fingerprint rules updated",
		"count":   len(rules),
	})
}
