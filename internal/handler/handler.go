package handler

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string) (*domain.DomainResponse, bool)
}

type Handler struct {
	domainService DomainLookupService
	version       string
}

func New(domainService DomainLookupService, version string) *Handler {
	return &Handler{
		domainService: domainService,
		version:       version,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	{
		v1.GET("/hello", h.Hello)
		v1.GET("/info", h.Info)
		v1.POST("/domain", h.DomainLookup)
	}
}
