package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Version(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": h.version})
}
