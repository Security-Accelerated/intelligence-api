package handler

import (
	_ "embed"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed home.html
var homeHTML string

var homeTmpl = template.Must(template.New("home").Parse(homeHTML))

// Home answers the site root: the Security Accelerated company page — what the
// company makes, the plans, and how to reach it — or a redirect to the docs.
//
// Which one depends on the hostname. One app serves two names: the company's
// own domain, where the root is the company page, and the API's, where the
// root is the way into the docs. site.home_host names the first; with it set,
// the root of any other host redirects to /docs. With it unset the page is
// served on every host, which is what local development and the tests want.
//
// The redirect is a 302, not a 301. Which host gets the page is configuration,
// and a browser keeps a 301 after the configuration has changed: v1.1.0 served
// this page at the API's root, and anyone holding the 301 from before it never
// saw it there.
//
// The page is deliberately not a row in docsPages. That table is the
// documentation set, whose pages share one shell (topbar nav, sidebar,
// reference tables); this is the front door. It uses the docs' design language
// — the shared stylesheet's tokens, typefaces, code blocks and theme toggle —
// with a layout of its own, so it reads as the same company without being a
// copy of the docs overview. It also shares the CSP and the template data, so
// the price and payment link shown here come from the same config keys as the
// Plans table on /docs.
func (h *Handler) Home(c *gin.Context) {
	if !h.servesHomeOn(c.Request.Host) {
		c.Redirect(http.StatusFound, "/docs")
		return
	}
	h.renderDocs(c, homeTmpl)
}

// servesHomeOn reports whether the company page is the root of the host a
// request named. www. on the home host counts, so both spellings of the
// company's domain show the same page.
//
// The Host header is the caller's to set, which is safe here: it only chooses
// between the page and a redirect to a fixed path on the same host.
func (h *Handler) servesHomeOn(requestHost string) bool {
	home := h.siteHost("site.home_host")
	if home == "" {
		return true
	}
	if hostname, _, err := net.SplitHostPort(requestHost); err == nil {
		requestHost = hostname
	}
	host := strings.ToLower(strings.TrimSuffix(requestHost, "."))
	return host == home || host == "www."+home
}

// siteHost returns one of the site.*_host config values as a bare lowercase
// hostname, or "" when it is not set.
func (h *Handler) siteHost(key string) string {
	if h.cfg == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(h.cfg.GetString(key)))
}
