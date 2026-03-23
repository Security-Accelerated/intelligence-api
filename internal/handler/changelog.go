package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Changelog returns the full unfiltered changelog (admin only).
func (h *Handler) Changelog(c *gin.Context) {
	c.JSON(http.StatusOK, h.changelog)
}
