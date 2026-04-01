package handler

import (
	"bytes"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

func renderHTML(c *gin.Context, status int, tmpl *template.Template, data any, headers map[string]string) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		logging.Logger().Error("template render failed",
			zap.String("template", tmpl.Name()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	for key, value := range headers {
		c.Header(key, value)
	}
	c.Status(status)
	if _, err := c.Writer.Write(buf.Bytes()); err != nil {
		logging.Logger().Warn("template response write failed",
			zap.String("template", tmpl.Name()),
			zap.Error(err),
		)
	}
}
