package handler

import (
	_ "embed"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed docs.html
var docsHTML string

var docsTmpl = template.Must(template.New("docs").Parse(docsHTML))

type docsData struct {
	BasicPaymentLink string
	ProPaymentLink   string
}

func (h *Handler) Docs(c *gin.Context) {
	data := docsData{}
	if h.cfg != nil {
		data.BasicPaymentLink = h.cfg.GetString("stripe.payment_link.basic")
		data.ProPaymentLink = h.cfg.GetString("stripe.payment_link.pro")
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	docsTmpl.Execute(c.Writer, data)
}
