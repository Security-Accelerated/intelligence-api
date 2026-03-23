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
	PortalLink       string
	Version          string
	Changelog        []docsChangelogVersion
}

type docsChangelogVersion struct {
	Version string
	Date    string
	Changes []string
}

func (h *Handler) Docs(c *gin.Context) {
	version := ""
	if h.status != nil {
		version = h.status.System.Version
	}
	data := docsData{Version: version}
	if h.cfg != nil {
		data.BasicPaymentLink = h.cfg.GetString("stripe.payment_link.basic")
		data.ProPaymentLink = h.cfg.GetString("stripe.payment_link.pro")
		data.PortalLink = h.cfg.GetString("stripe.portal_link")
	}

	// Filter changelog to public entries only.
	for _, v := range h.changelog {
		var publicChanges []string
		for _, ch := range v.Changes {
			if ch.Audience == "public" {
				publicChanges = append(publicChanges, ch.Text)
			}
		}
		if len(publicChanges) > 0 {
			data.Changelog = append(data.Changelog, docsChangelogVersion{
				Version: v.Version,
				Date:    v.Date,
				Changes: publicChanges,
			})
		}
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	docsTmpl.Execute(c.Writer, data)
}
