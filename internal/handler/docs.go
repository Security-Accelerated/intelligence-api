package handler

import (
	_ "embed"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

// htmlPageCSP is the Content-Security-Policy for HTML pages (docs, checkout
// success). It overrides the strict API-wide default set by the
// SecurityHeaders middleware: pages load same-origin scripts/styles/images,
// inline <style> blocks, and Google Fonts. No inline JavaScript is allowed.
const htmlPageCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// htmlPageHeaders returns the response headers for an HTML page, including
// the page-level Content-Security-Policy override.
func htmlPageHeaders(extra map[string]string) map[string]string {
	headers := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Content-Security-Policy": htmlPageCSP,
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

//go:embed docs_styles.css
var docsCSS string

//go:embed docs_theme.js
var docsThemeJS string

//go:embed docs.js
var docsJS string

//go:embed checkout_success.js
var checkoutSuccessJS string

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
	renderHTML(c, http.StatusOK, tmpl, data, htmlPageHeaders(nil))
}

func (h *Handler) DocsCSS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "text/css; charset=utf-8", []byte(docsCSS))
}

func (h *Handler) DocsThemeJS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(docsThemeJS))
}

func (h *Handler) DocsJS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(docsJS))
}

func (h *Handler) CheckoutSuccessJS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(checkoutSuccessJS))
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
