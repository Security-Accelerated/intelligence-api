package handler

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"

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

//go:embed docs_account.html
var docsAccountHTML string

//go:embed docs_changelog.html
var docsChangelogHTML string

//go:embed docs_404.html
var docsNotFoundHTML string

var docsTmpl = template.Must(template.New("docs").Parse(docsHTML))
var docsDomainTmpl = template.Must(template.New("docs_domain").Parse(docsDomainHTML))
var docsIPTmpl = template.Must(template.New("docs_ip").Parse(docsIPHTML))
var docsAccountTmpl = template.Must(template.New("docs_account").Parse(docsAccountHTML))
var docsChangelogTmpl = template.Must(template.New("docs_changelog").Parse(docsChangelogHTML))
var docsNotFoundTmpl = template.Must(template.New("docs_404").Parse(docsNotFoundHTML))

// docsPage is one public documentation page.
type docsPage struct {
	Path string
	HTML string
	Tmpl *template.Template
}

// docsPages is the canonical set of documentation pages, in nav order. Routes
// are registered from it and the tests enumerate it, so a page cannot be added
// to one and forgotten in the other.
//
// It exists because the alternative failed: the page set was previously spelled
// out in the router, twice in docs_test.go, twice more in docs_layout_test.go,
// and in every template's topbar nav. Adding /docs/account meant finding all
// six by hand, and the nav test only catches the last of them.
var docsPages = []docsPage{
	{"/docs", docsHTML, docsTmpl},
	{"/docs/domain", docsDomainHTML, docsDomainTmpl},
	{"/docs/ip", docsIPHTML, docsIPTmpl},
	{"/docs/account", docsAccountHTML, docsAccountTmpl},
	{"/docs/changelog", docsChangelogHTML, docsChangelogTmpl},
}

type docsData struct {
	ProPaymentLink string
	ProPrice       string // display text such as "$29/month"; empty hides the price
	PortalLink     string
	Version        string
	Changelog      []docsChangelogVersion
}

type docsChangelogVersion struct {
	Version string
	Date    string
	Changes []template.HTML
}

// renderChangelogText turns the one-backtick-per-identifier style the changelog
// entries are written in into inline <code>, which is what the rest of the docs
// uses and what docs_styles.css already handles. Rendering the text verbatim put
// the backticks on the page, so the spans are converted here rather than taken
// out of the entries — GET /v1/admin/changelog still returns the source text.
//
// The result is template.HTML, which switches off the escaping the template was
// doing, so every segment is escaped by hand here instead. Both HTMLEscapeString
// calls are load-bearing: dropping either one turns a changelog entry into an
// injection point. The entries are repo-controlled and reviewed, so this is
// defense in depth rather than a live hole, but it is not redundant.
func renderChangelogText(s string) template.HTML {
	parts := strings.Split(s, "`")
	var b strings.Builder
	if len(parts)%2 == 0 {
		// An even number of segments means an unpaired backtick. Escaping the
		// whole string leaves it visible, which beats swallowing the rest of the
		// sentence into a code span.
		b.WriteString(template.HTMLEscapeString(s))
	} else {
		for i, p := range parts {
			if i%2 == 1 {
				b.WriteString("<code>")
				b.WriteString(template.HTMLEscapeString(p))
				b.WriteString("</code>")
				continue
			}
			b.WriteString(template.HTMLEscapeString(p))
		}
	}
	// The only markup in the builder is the <code> tags written above; every
	// segment of the entry itself went through HTMLEscapeString first.
	//nolint:gosec // G203: escaping is done by hand here, see the comment above.
	return template.HTML(b.String())
}

func (h *Handler) buildDocsData() docsData {
	version := ""
	if h.status != nil {
		version = h.status.System.Version
	}
	data := docsData{Version: version}
	if h.cfg != nil {
		data.ProPaymentLink = h.cfg.GetString("stripe.payment_link.pro")
		data.ProPrice = h.cfg.GetString("stripe.price_display.pro")
		data.PortalLink = h.cfg.GetString("stripe.portal_link")
	}

	for _, v := range h.changelog {
		var publicChanges []template.HTML
		for _, ch := range v.Changes {
			if ch.Audience == "public" {
				publicChanges = append(publicChanges, renderChangelogText(ch.Text))
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

// docsPageHandler serves one page from the docsPages table.
func (h *Handler) docsPageHandler(tmpl *template.Template) gin.HandlerFunc {
	return func(c *gin.Context) { h.renderDocs(c, tmpl) }
}

// NotFound answers any request that matched no route. It is the engine's
// NoRoute handler, so it runs under the global middleware only — no auth, no
// rate limit.
//
// API namespaces get the same JSON error envelope as every other failure, so a
// mistyped endpoint is handled by a caller's existing error path rather than
// arriving as a page of HTML. Everything else gets the docs-styled page, which
// is what a browser following a stale link is asking for.
//
// The requested path is deliberately not echoed back. Reflecting attacker-chosen
// text onto our own domain is a phishing primitive, and a 404 page has no need
// to repeat an address the reader just typed.
func (h *Handler) NotFound(c *gin.Context) {
	if isAPIPath(c.Request.URL.Path) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	renderHTML(c, http.StatusNotFound, docsNotFoundTmpl, h.buildDocsData(), htmlPageHeaders(nil))
}

// isAPIPath reports whether a path belongs to a machine-facing namespace, where
// a JSON body is the useful answer.
func isAPIPath(path string) bool {
	for _, prefix := range []string{"/v1/", "/billing/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return path == "/v1" || path == "/billing"
}

// The release notes have their own page rather than sitting at the bottom of
// the overview and the domain reference, which pushed the changelog's length
// onto pages people open to look something up and meant two copies of the same
// list to keep in sync. Likewise the account endpoints have their own page
// rather than a table row on the overview: /v1/usage and /v1/keys/rotate are
// two of the four public endpoints and were the only two with no reference.
