package handler

import (
	"regexp"
	"strings"
	"testing"
)

// TestDocs_TablesAreScrollWrapped guards the fix for the docs being unreadable
// on a phone.
//
// `width: 100%` on a table is only a floor: when the columns' own min-content
// widths add up to more than the container, the table grows past it and takes
// the document's scroll width with it, so the whole page scrolls sideways and
// body text runs off the screen. Wrapping every table in an overflow-x
// container confines that to the table.
//
// This is asserted here rather than left to review because the failure is
// invisible on a desktop viewport, where every one of these tables fits.
// allDocsHTML is every page a reader can land on: the routed pages from the
// docsPages table, plus the 404, which has no route of its own because it is
// what NoRoute renders.
func allDocsHTML() []docsPage {
	pages := append([]docsPage{}, docsPages...)
	return append(pages, docsPage{Path: "/docs/404", HTML: docsNotFoundHTML, Tmpl: docsNotFoundTmpl})
}

func TestDocs_TablesAreScrollWrapped(t *testing.T) {
	openTag := regexp.MustCompile(`<table\b[^>]*>`)

	for _, tc := range allDocsHTML() {
		t.Run(tc.Path, func(t *testing.T) {
			for _, loc := range openTag.FindAllStringIndex(tc.HTML, -1) {
				before := tc.HTML[:loc[0]]
				opener := strings.LastIndex(before, `<div class="table-scroll">`)
				if opener == -1 || strings.Contains(before[opener:], "</div>") {
					t.Errorf("table at offset %d is not wrapped in <div class=\"table-scroll\">; "+
						"an unwrapped table makes the whole page scroll sideways on a phone", loc[0])
				}
			}
		})
	}
}

// TestDocs_StylesheetKeepsMobileGuards pins the handful of CSS declarations
// that stop long unbreakable tokens — header names, IPv6 addresses, config
// keys — from painting past a narrow viewport. Losing any of them reintroduces
// the same horizontal overflow the table wrapper fixes.
func TestDocs_StylesheetKeepsMobileGuards(t *testing.T) {
	for _, want := range []string{
		".table-scroll",
		"overflow-wrap: break-word",
		"overflow-wrap: anywhere",
		"-webkit-text-size-adjust: 100%",
	} {
		if !strings.Contains(docsCSS, want) {
			t.Errorf("docs stylesheet no longer contains %q", want)
		}
	}

	// The mobile bar carries the nav on a second row, so the offsets that
	// position content below it are derived from the variable rather than
	// from the desktop height.
	if !strings.Contains(docsCSS, "height: var(--topbar-height)") {
		t.Error("mobile topbar height is not pinned to --topbar-height; " +
			"the variable and the rendered bar can drift apart, hiding the first heading behind it")
	}
}

// TestDocs_MobileNavReachesEveryPage covers the overview specifically: it is
// the one page with no sidebar, so hiding the topbar nav on narrow viewports
// left a phone with no route to the other pages at all.
func TestDocs_MobileNavReachesEveryPage(t *testing.T) {
	if strings.Contains(docsCSS, ".topbar-nav { display: none; }") {
		t.Error("topbar nav is hidden on mobile; the overview then has no navigation")
	}

	for _, tc := range allDocsHTML() {
		t.Run(tc.Path, func(t *testing.T) {
			nav := regexp.MustCompile(`(?s)<nav class="topbar-nav">.*?</nav>`).FindString(tc.HTML)
			if nav == "" {
				t.Fatal("page has no topbar nav")
			}
			for _, href := range docsPagePaths {
				if !strings.Contains(nav, `href="`+href+`"`) {
					t.Errorf("topbar nav does not link to %s", href)
				}
			}
		})
	}
}
