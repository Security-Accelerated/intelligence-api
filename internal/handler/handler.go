package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/service"
)

type Handler struct {
	domainService *service.DomainService
}

func New(domainService *service.DomainService) *Handler {
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
