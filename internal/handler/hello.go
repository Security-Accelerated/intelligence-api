package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Hello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "hello world"})
}
