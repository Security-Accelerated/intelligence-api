package handler

import (
	_ "embed"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed docs_styles.css
var docsCSS string

//go:embed docs.html
var docsHTML string

//go:embed docs_domain.html
var docsDomainHTML string

//go:embed docs_ip.html
var docsIPHTML string

var docsTmpl = template.Must(template.New("docs").Parse(docsHTML))
var docsDomainTmpl = template.Must(template.New("docs_domain").Parse(docsDomainHTML))
var docsIPTmpl = template.Must(template.New("docs_ip").Parse(docsIPHTML))

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

func (h *Handler) buildDocsData() docsData {
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
	return data
}

func (h *Handler) renderDocs(c *gin.Context, tmpl *template.Template) {
	data := h.buildDocsData()
	renderHTML(c, http.StatusOK, tmpl, data, map[string]string{
		"Content-Type": "text/html; charset=utf-8",
	})
}

func (h *Handler) DocsCSS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "text/css; charset=utf-8", []byte(docsCSS))
}

func (h *Handler) Docs(c *gin.Context) {
	h.renderDocs(c, docsTmpl)
}

func (h *Handler) DocsDomain(c *gin.Context) {
	h.renderDocs(c, docsDomainTmpl)
}

func (h *Handler) DocsIP(c *gin.Context) {
	h.renderDocs(c, docsIPTmpl)
}
