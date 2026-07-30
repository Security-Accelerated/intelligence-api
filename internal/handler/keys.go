package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// KeyRotationService issues a fresh API key for a customer, grace-expiring
// previous keys.
type KeyRotationService interface {
	Rotate(ctx context.Context, customerID int) (rawKey string, oldKeysExpireAt time.Time, err error)
}

// RotateKey lets the authenticated customer rotate their own API key. The new
// key is returned exactly once; previous keys keep working until the grace
// window ends so deployed clients can be switched over without downtime.
func (h *Handler) RotateKey(c *gin.Context) {
	if h.keyRotationService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "key rotation not configured"})
		return
	}

	customerID, ok := c.Get("customer_id")
	id, isInt := customerID.(int)
	if !ok || !isInt || id < 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	rawKey, oldExpiry, err := h.keyRotationService.Rotate(c.Request.Context(), id)
	if err != nil {
		logging.Logger().Error("key rotation failed", zap.Int("customer_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key rotation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_key":            rawKey,
		"old_keys_expire_at": oldExpiry,
		"message":            "store this key now — it cannot be retrieved again; previous keys stop working at old_keys_expire_at",
	})
}
