package handler

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed docs.html
var docsHTML []byte

func (h *Handler) Docs(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", docsHTML)
}
