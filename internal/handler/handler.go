package handler

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/domain"
)

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string) (*domain.DomainResponse, bool)
}

type Handler struct {
	domainService DomainLookupService
}

func New(domainService DomainLookupService) *Handler {
	return &Handler{
		domainService: domainService,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	{
		v1.GET("/hello", h.Hello)
		v1.POST("/domain", h.DomainLookup)
	}
}
