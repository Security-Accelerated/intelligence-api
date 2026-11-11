package handler

import (
	_ "embed"
	"html/template"

	"github.com/gin-gonic/gin"
)

//go:embed home.html
var homeHTML string

var homeTmpl = template.Must(template.New("home").Parse(homeHTML))

// Home serves the Security Accelerated company page at the site root: what the
// company makes, the plans, and how to reach it, with the docs one link away.
// The root used to redirect to /docs.
//
// It is deliberately not a row in docsPages. That table is the documentation
// set, whose pages share one shell (topbar nav, sidebar, reference tables);
// this is the front door. It uses the docs' design language — the shared
// stylesheet's tokens, typefaces, code blocks and theme toggle — with a layout
// of its own, so it reads as the same company without being a copy of the
// docs overview. It also shares the CSP and the template data, so the price
// and payment link shown here come from the same config keys as the Plans
// table on /docs.
func (h *Handler) Home(c *gin.Context) {
	h.renderDocs(c, homeTmpl)
}
