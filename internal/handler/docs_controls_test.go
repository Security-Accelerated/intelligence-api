package handler

import (
	"regexp"
	"strings"
	"testing"
)

// The copy button and the page search are both built by docs.js at load rather
// than written into the templates. These tests pin the invariants that choice
// depends on, since none of them are visible in a rendered page: the pages must
// carry no markup for either control, the script must copy the code rather than
// the syntax highlighting, and the class names the script assigns must be the
// ones the stylesheet defines.

// TestDocs_InteractiveControlsAreInjected keeps both controls out of the
// templates. A copy button or a search box written into the HTML is still there
// when the script does not run — a dead control on a page that is otherwise
// perfectly readable static HTML. Injecting them means "no JavaScript" and "no
// control" are the same state.
func TestDocs_InteractiveControlsAreInjected(t *testing.T) {
	markers := []string{"code-copy", "code-block", "docs-search"}

	for _, page := range allDocsHTML() {
		t.Run(page.Path, func(t *testing.T) {
			for _, marker := range markers {
				if strings.Contains(page.HTML, marker) {
					t.Errorf("page markup contains %q; the control is injected by docs.js, "+
						"and markup for it is left behind when the script does not run", marker)
				}
			}
		})
	}
}

// TestDocs_CopyUsesTextContent guards the one way the copy button can be subtly
// wrong: the blocks are marked up with <span class="str"> and friends for
// syntax colour, so innerHTML would put a page of markup on the clipboard and
// look fine to anyone who does not paste it.
func TestDocs_CopyUsesTextContent(t *testing.T) {
	if strings.Contains(docsJS, "innerHTML") {
		t.Error("docs.js uses innerHTML; the code blocks carry syntax-highlighting markup, " +
			"so a copy must read textContent")
	}
	if !strings.Contains(docsJS, "writeText(code.textContent)") {
		t.Error("the copy handler no longer copies code.textContent")
	}
}

// TestDocs_ScriptAndStylesheetShareClassNames catches a rename in one file only.
// The script creates elements the stylesheet has never seen otherwise, and an
// unstyled overlay is invisible rather than broken — it renders as unstyled
// text over the page with no error anywhere.
func TestDocs_ScriptAndStylesheetShareClassNames(t *testing.T) {
	shared := []string{
		"code-block",
		"code-copy",
		"code-copy-label",
		"is-copied",
		"visually-hidden",
		"docs-search-trigger",
		"docs-search-panel",
		"docs-search-field",
		"docs-search-input",
		"docs-search-results",
		"docs-search-result",
		"docs-search-result-label",
		"docs-search-result-scope",
		"docs-search-status",
		"docs-search-hint",
		"docs-search-backdrop",
		"is-active",
		"is-search-hit",
		"search-open",
	}

	for _, class := range shared {
		if !strings.Contains(docsJS, class) {
			t.Errorf("docs.js no longer references the %q class", class)
		}
		if !strings.Contains(docsCSS, "."+class) && !strings.Contains(docsCSS, "body."+class) {
			t.Errorf("docs stylesheet has no rule for the %q class docs.js assigns", class)
		}
	}
}

// TestDocs_SearchOverlayTakesItsOwnScrollLock pins the distinction between the
// two body classes. `shell-open` is what slides the mobile drawer out, so an
// overlay reusing it as a scroll lock opens the drawer behind itself.
func TestDocs_SearchOverlayTakesItsOwnScrollLock(t *testing.T) {
	if !strings.Contains(docsCSS, "body.search-open") {
		t.Fatal("stylesheet has no body.search-open rule")
	}
	if regexp.MustCompile(`add\('shell-open'\)`).MatchString(searchSection(t)) {
		t.Error("the search overlay adds shell-open, which opens the mobile drawer behind it")
	}
}

// searchSection returns the part of docs.js from the search feature onwards, so
// the assertion above reads the overlay's own code rather than the sidebar
// toggle that legitimately uses shell-open.
func searchSection(t *testing.T) string {
	t.Helper()
	idx := strings.Index(docsJS, "docs-search-trigger")
	if idx == -1 {
		t.Fatal("docs.js no longer contains the search feature")
	}
	return docsJS[idx:]
}

// TestDocs_StylesheetHonoursReducedMotion covers the smooth scroll shared by
// the sidebar links and the search results: both move the whole document, and
// the preference has to be answered in the stylesheet because that is where the
// scroll behaviour is set.
func TestDocs_StylesheetHonoursReducedMotion(t *testing.T) {
	if !strings.Contains(docsCSS, "@media (prefers-reduced-motion: reduce)") {
		t.Error("stylesheet has no prefers-reduced-motion block")
	}
	if !strings.Contains(docsJS, "prefers-reduced-motion") {
		t.Error("docs.js scrolls to a search result without consulting prefers-reduced-motion")
	}
}

// TestDocs_ControlsAreHiddenInPrint keeps the injected controls out of a printed
// page, where a "Copy" button is ink spent on something the reader cannot press.
func TestDocs_ControlsAreHiddenInPrint(t *testing.T) {
	block := printBlock(t)

	for _, selector := range []string{".code-copy", ".docs-search", ".docs-search-trigger"} {
		if !hiddenInPrint(block, selector) {
			t.Errorf("@media print has no rule hiding %s", selector)
		}
	}
}

// printBlock returns the contents of the stylesheet's @media print rule, matched
// brace by brace.
//
// Reading to the end of the file instead — which this test used to do — let a
// rule that has nothing to do with printing satisfy the assertion: the
// responsive blocks sit after @media print and style .docs-search-trigger
// themselves, so removing the trigger from the print rule still passed.
func printBlock(t *testing.T) string {
	t.Helper()

	start := strings.Index(docsCSS, "@media print")
	if start == -1 {
		t.Fatal("stylesheet has no @media print block")
	}
	open := strings.Index(docsCSS[start:], "{")
	if open == -1 {
		t.Fatal("@media print is not followed by a block")
	}

	depth := 0
	for i := start + open; i < len(docsCSS); i++ {
		switch docsCSS[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return docsCSS[start+open+1 : i]
			}
		}
	}

	t.Fatal("@media print block is never closed")
	return ""
}

// hiddenInPrint reports whether the print block carries a rule that names the
// selector and actually hides it. Both halves matter: a class name appearing
// somewhere in the block proves nothing, since it could be picking up a padding
// adjustment.
//
// The selector is matched whole rather than as a substring, because
// ".docs-search" is a prefix of ".docs-search-trigger" — a substring check would
// let the trigger's rule stand in for the overlay's.
func hiddenInPrint(block, selector string) bool {
	for rule := range strings.SplitSeq(block, "}") {
		parts := strings.SplitN(rule, "{", 2)
		if len(parts) != 2 || !strings.Contains(parts[1], "display: none") {
			continue
		}
		for sel := range strings.SplitSeq(parts[0], ",") {
			if strings.TrimSpace(sel) == selector {
				return true
			}
		}
	}
	return false
}
