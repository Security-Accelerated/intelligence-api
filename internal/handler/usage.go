package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// GetUsage returns aggregated usage statistics for the admin endpoint.
func (h *Handler) GetUsage(c *gin.Context) {
	if h.usageService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "usage tracking not configured"})
		return
	}

	days := 30
	if d := c.Query("days"); d != "" {
		v, err := strconv.Atoi(d)
		if err != nil || v < 1 || v > 365 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "days must be between 1 and 365"})
			return
		}
		days = v
	}

	var customerID, apiKeyID int
	if v := c.Query("customer_id"); v != "" {
		id, err := strconv.Atoi(v)
		if err != nil || id < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid customer_id"})
			return
		}
		customerID = id
	}
	if v := c.Query("api_key_id"); v != "" {
		id, err := strconv.Atoi(v)
		if err != nil || id < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid api_key_id"})
			return
		}
		apiKeyID = id
	}

	now := time.Now().UTC()
	since := now.AddDate(0, 0, -days)

	summary, err := h.usageService.QueryUsage(customerID, apiKeyID, since, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query usage"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// MyUsage returns aggregated usage statistics for the authenticated customer.
// Unlike the admin endpoint, the customer filter always comes from the auth
// context — callers can only ever see their own usage.
func (h *Handler) MyUsage(c *gin.Context) {
	if h.usageService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "usage tracking not configured"})
		return
	}

	customerID, ok := c.Get("customer_id")
	id, isInt := customerID.(int)
	if !ok || !isInt || id < 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	days := 30
	if d := c.Query("days"); d != "" {
		v, err := strconv.Atoi(d)
		if err != nil || v < 1 || v > 365 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "days must be between 1 and 365"})
			return
		}
		days = v
	}

	now := time.Now().UTC()
	since := now.AddDate(0, 0, -days)

	summary, err := h.usageService.QueryUsage(id, 0, since, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query usage"})
		return
	}

	c.JSON(http.StatusOK, summary)
}
