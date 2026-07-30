package handler

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed openapi.yaml
var openapiYAML []byte

// OpenAPISpec serves the hand-written OpenAPI 3.1 specification for the
// customer-facing API surface.
func (h *Handler) OpenAPISpec(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openapiYAML)
}
