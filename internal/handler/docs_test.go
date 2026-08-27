package handler

import (
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/spf13/viper"
)

func docsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{})
	h.RegisterRoutes(r)
	return r
}

func TestDocs_RootRedirectsToDocs(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	loc := w.Header().Get("Location")
	if loc != "/docs" {
		t.Errorf("Location = %q, want /docs", loc)
	}
}

func TestDocs_LandingPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Domain Intelligence") {
		t.Error("expected landing page to mention Domain Intelligence")
	}
	if !strings.Contains(body, "IP Intelligence") {
		t.Error("expected landing page to mention IP Intelligence")
	}
}

func TestDocs_DomainPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/domain", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Domain Intelligence") {
		t.Error("expected domain page content")
	}
}

func TestDocs_IPPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/ip", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "IP Intelligence") {
		t.Error("expected IP page content")
	}
}

func TestDocs_CSSEndpoint(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/styles.css", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/css") {
		t.Errorf("Content-Type = %q, want text/css", ct)
	}
	cc := w.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}
	body := w.Body.String()
	if !strings.Contains(body, "--accent") {
		t.Error("expected CSS to contain custom properties")
	}
}

func TestDocs_JSEndpoints(t *testing.T) {
	r := docsRouter()

	tests := []struct {
		path string
		want string
	}{
		{"/docs/theme.js", "sa-docs-theme"},
		{"/docs/docs.js", "lang-tab"},
		{"/docs/checkout_success.js", "copy-key"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			ct := w.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/javascript") {
				t.Errorf("Content-Type = %q, want application/javascript", ct)
			}
			cc := w.Header().Get("Cache-Control")
			if cc != "public, max-age=3600" {
				t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
			}
			if !strings.Contains(w.Body.String(), tt.want) {
				t.Errorf("expected JS body to contain %q", tt.want)
			}
		})
	}
}

// docsPagePaths is every public HTML docs page, derived from the docsPages
// table the routes are registered from. Tests that assert a page-wide invariant
// iterate this rather than listing paths inline, so adding a page cannot
// quietly opt out of them.
var docsPagePaths = func() []string {
	paths := make([]string, 0, len(docsPages))
	for _, page := range docsPages {
		paths = append(paths, page.Path)
	}
	return paths
}()

// docsReferencePagePaths is the subset with the sidebar reference layout. The
// overview uses a different shell, so it is the one exclusion rather than the
// list being spelled out again.
var docsReferencePagePaths = func() []string {
	paths := make([]string, 0, len(docsPages))
	for _, page := range docsPages {
		if page.Path != "/docs" {
			paths = append(paths, page.Path)
		}
	}
	return paths
}()

func TestDocs_PagesSetCSPAndNoInlineScripts(t *testing.T) {
	r := docsRouter()

	for _, path := range docsPagePaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			if got := w.Header().Get("Content-Security-Policy"); got != htmlPageCSP {
				t.Errorf("Content-Security-Policy = %q, want %q", got, htmlPageCSP)
			}

			body := w.Body.String()
			if strings.Contains(body, "<script>") {
				t.Error("docs pages must not contain inline <script> blocks")
			}
			if strings.Contains(body, "onclick=") {
				t.Error("docs pages must not contain inline event handlers")
			}
			if !strings.Contains(body, `<script src="/docs/theme.js"></script>`) {
				t.Error("expected page to reference external theme.js")
			}
			if !strings.Contains(body, `<script src="/docs/docs.js" defer></script>`) {
				t.Error("expected page to reference external docs.js")
			}
		})
	}
}

// --- Changelog filtering and data injection tests ---

func docsRouterWithData(changelog []ChangelogVersion, cfg *viper.Viper, status *config.StatusSnapshot) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{
		changelog: changelog,
		cfg:       cfg,
		status:    status,
	}
	h.RegisterRoutes(r)
	return r
}

func TestDocs_ChangelogFiltersInternalEntries(t *testing.T) {
	changelog := []ChangelogVersion{
		{
			Version: "v1.0.0",
			Date:    "2026-01-01",
			Changes: []ChangelogChange{
				{Text: "Public feature added", Audience: "public"},
				{Text: "Internal refactor", Audience: "internal"},
			},
		},
	}

	r := docsRouterWithData(changelog, nil, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/changelog", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Public feature added") {
		t.Error("expected public changelog entry to appear on the changelog page")
	}
	if strings.Contains(body, "Internal refactor") {
		t.Error("internal changelog entry must not appear in public docs")
	}

	// The audience filter is the only thing keeping internal notes off a public
	// page, so assert it on every page rather than just the one that renders the
	// list. A page that starts rendering the changelog unfiltered would
	// otherwise leak silently.
	for _, path := range docsPagePaths {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		r.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), "Internal refactor") {
			t.Errorf("%s leaks an internal changelog entry", path)
		}
	}
}

func TestDocs_ChangelogExcludesAllInternalVersions(t *testing.T) {
	changelog := []ChangelogVersion{
		{
			Version: "v2.0.0",
			Date:    "2026-02-01",
			Changes: []ChangelogChange{
				{Text: "Public change", Audience: "public"},
			},
		},
		{
			Version: "v1.5.0",
			Date:    "2026-01-15",
			Changes: []ChangelogChange{
				{Text: "Internal only fix", Audience: "internal"},
				{Text: "Another internal thing", Audience: "internal"},
			},
		},
	}

	r := docsRouterWithData(changelog, nil, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/changelog", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "v2.0.0") {
		t.Error("expected v2.0.0 version with public changes to appear")
	}
	if strings.Contains(body, "v1.5.0") {
		t.Error("v1.5.0 with only internal changes must not appear in public docs")
	}
}

func TestDocs_ChangelogRendersBackticksAsCode(t *testing.T) {
	changelog := []ChangelogVersion{
		{
			Version: "v1.0.0",
			Date:    "2026-01-01",
			Changes: []ChangelogChange{
				{Text: "`errors` is omitted from a successful response — it is never `[]`.", Audience: "public"},
			},
		},
	}

	r := docsRouterWithData(changelog, nil, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/changelog", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if strings.Contains(body, "`") {
		t.Error("changelog page renders a literal backtick; identifiers should become inline <code>")
	}
	if !strings.Contains(body, "<code>errors</code>") {
		t.Error("expected the backtick span to render as inline <code>")
	}
}

// renderChangelogText hands the template pre-escaped HTML, so the escaping it
// does by hand is the only escaping left. This is the case that catches it
// being dropped.
func TestRenderChangelogText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "code span",
			in:   "`errors` is omitted",
			want: "<code>errors</code> is omitted",
		},
		{
			name: "markup in prose is escaped",
			in:   "a < b & c",
			want: "a &lt; b &amp; c",
		},
		{
			name: "markup inside a code span is escaped",
			in:   "use `<script>alert(1)</script>` here",
			want: "use <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> here",
		},
		{
			name: "unpaired backtick stays literal",
			in:   "an unclosed `span and <b>markup</b>",
			want: "an unclosed `span and &lt;b&gt;markup&lt;/b&gt;",
		},
		{
			name: "no backticks",
			in:   "plain prose",
			want: "plain prose",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(renderChangelogText(tt.in)); got != tt.want {
				t.Errorf("renderChangelogText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDocs_RendersVersion(t *testing.T) {
	status := &config.StatusSnapshot{
		System: config.SystemStatus{Version: "v99.0.0-test"},
	}

	r := docsRouterWithData(nil, nil, status)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "v99.0.0-test") {
		t.Error("expected version string to appear in docs page")
	}
}

func TestDocs_RendersPaymentLinks(t *testing.T) {
	cfg := viper.New()
	cfg.Set("stripe.payment_link.pro", "https://buy.stripe.com/test_pro")
	cfg.Set("stripe.portal_link", "https://billing.stripe.com/test_portal")

	r := docsRouterWithData(nil, cfg, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://buy.stripe.com/test_pro") {
		t.Error("expected pro payment link in docs")
	}
	if !strings.Contains(body, "https://billing.stripe.com/test_portal") {
		t.Error("expected portal link in docs")
	}
}

func TestDocs_OverviewRendersFooter(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	for _, want := range []string{
		"<footer class=\"docs-footer docs-footer-overview\">",
		"&copy; 2026 Security Accelerated",
		"https://x.com/SecAccelerated",
		"support@securityaccelerated.com",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q to appear in overview footer", want)
		}
	}
}

// TestDocs_DetailPagesFooter guards the detail-page footer. These pages carry
// the plain .page-footer, never the overview's paneled .docs-footer — the two
// look nothing alike and the heavy one does not belong at the end of a
// reference page.
func TestDocs_DetailPagesFooter(t *testing.T) {
	r := docsRouter()

	for _, path := range docsReferencePagePaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			if !strings.Contains(body, `class="page-footer"`) {
				t.Error("detail page is missing its footer")
			}
			if strings.Contains(body, "docs-footer") {
				t.Error("detail pages must not use the overview's paneled footer")
			}
			if strings.Contains(body, "sidebar-footer") {
				t.Error("detail pages should not have a sidebar footer")
			}
		})
	}
}

// TestDocs_PagesLinkToOpenAPISpec keeps the spec discoverable. It is the
// machine-readable contract customers generate clients from, and it was
// reachable only from the overview page's footer — invisible to anyone landing
// on /docs/domain from a search, which is where the reference actually lives.
func TestDocs_PagesLinkToOpenAPISpec(t *testing.T) {
	r := docsRouter()

	for _, path := range docsPagePaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			if !strings.Contains(w.Body.String(), `href="/docs/openapi.yaml"`) {
				t.Error("page does not link to the OpenAPI spec")
			}
		})
	}
}

// TestDocs_ResponseHeadersDocumented keeps the response-header documentation
// honest. The headers a caller sees are as much the contract as the JSON body,
// and they were previously described only in prose — the full response example
// showed the body alone, so nothing told a reader that X-Request-ID exists.
//
// The length check is the real point. The IP page claimed the correlation ID
// accepted "any string up to 128 chars" while the middleware capped it at 64
// and rejected most punctuation, so a customer following the docs could send a
// 100-character ID, get a 200 back, and silently lose their tracing with no
// error to explain it. Deriving the expected number from the middleware
// constant means the two cannot drift apart again.
func TestDocs_ResponseHeadersDocumented(t *testing.T) {
	r := docsRouter()

	// Set by RequestLogger, ClientRequestID, and RateLimit respectively. A
	// header a caller can observe but cannot find in the docs is a gap.
	wantHeaders := []string{
		"X-Request-ID",
		"X-Client-Request-ID",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"Retry-After",
	}

	for _, path := range []string{"/docs/domain", "/docs/ip"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			body := w.Body.String()

			for _, h := range wantHeaders {
				if !strings.Contains(body, h) {
					t.Errorf("page never mentions the %s response header", h)
				}
			}

			// The full response example must show headers, not just the body.
			if !strings.Contains(body, `id="response-headers"`) {
				t.Error("full response example does not show the returned headers")
			}

			wantLen := strconv.Itoa(middleware.ClientRequestIDMaxLen)
			if !strings.Contains(body, "Up to "+wantLen+" characters") {
				t.Errorf("page does not state the %s-character correlation ID limit enforced by middleware.ClientRequestIDMaxLen", wantLen)
			}
		})
	}
}

// docsPagesWithLanguageTabs returns every page carrying a language-tab block,
// so a page that gains examples is covered by the tab and compile checks
// without anyone remembering to add it to a list. A page with no tabs is not a
// failure; it simply has nothing to check.
func docsPagesWithLanguageTabs() []docsPage {
	var pages []docsPage
	for _, page := range docsPages {
		if strings.Contains(page.HTML, `class="lang-tabs"`) {
			pages = append(pages, page)
		}
	}
	return pages
}

func TestDocs_LanguageTabsHavePanels(t *testing.T) {
	for _, tc := range docsPagesWithLanguageTabs() {
		t.Run(tc.Path, func(t *testing.T) {
			tabs := map[string]bool{}
			for _, m := range regexp.MustCompile(`data-lang="([^"]+)"`).FindAllStringSubmatch(tc.HTML, -1) {
				tabs[m[1]] = true
			}
			panels := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="tab-([^"]+)"`).FindAllStringSubmatch(tc.HTML, -1) {
				panels[m[1]] = true
			}

			if len(tabs) == 0 {
				t.Fatal("no language tabs found")
			}
			for lang := range tabs {
				if !panels[lang] {
					t.Errorf("tab %q has no #tab-%s panel — clicking it does nothing", lang, lang)
				}
			}
			for lang := range panels {
				if !tabs[lang] {
					t.Errorf("panel #tab-%s has no tab — it is unreachable", lang)
				}
			}
			for _, want := range []string{"curl", "javascript", "python", "go"} {
				if !tabs[want] {
					t.Errorf("missing %q example tab", want)
				}
			}
		})
	}
}

// TestDocs_ExamplesUseCurrentRequestContract catches example code left on the
// pre-v0.54.0 contract. Both endpoints now require a `lookups` array and return
// a `results` envelope; an example that omits either is wrong in a way no other
// test would notice.
func TestDocs_ExamplesUseCurrentRequestContract(t *testing.T) {
	// Scoped to the lookup pages on purpose: these assertions are about the
	// lookup request contract, which the account examples do not share.
	for _, tc := range []docsPage{
		{Path: "/docs/domain", HTML: docsDomainHTML},
		{Path: "/docs/ip", HTML: docsIPHTML},
	} {
		t.Run(tc.Path, func(t *testing.T) {
			// Every example sends a request, so all must name lookups.
			for _, lang := range []string{"curl", "javascript", "python", "go"} {
				if panel := extractPanel(t, tc.HTML, lang); !strings.Contains(panel, "lookups") {
					t.Errorf("%s example does not send a lookups array", lang)
				}
			}
			// Only the ones that parse a response can read the envelope; the
			// curl example stops at the request.
			for _, lang := range []string{"javascript", "python", "go"} {
				if panel := extractPanel(t, tc.HTML, lang); !strings.Contains(panel, "results") {
					t.Errorf("%s example does not read the results envelope", lang)
				}
			}
		})
	}
}

// TestDocs_GoExamplesCompile builds the Go example from each docs page. The
// examples are self-contained stdlib-only programs that customers copy verbatim,
// so a redeclared variable or missing import is a real defect — and one that no
// amount of string matching against the markup would catch. This exists because
// exactly that shipped: both pages declared `body` for the request payload and
// then again for the decoded response.
func TestDocs_GoExamplesCompile(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	for _, tc := range docsPagesWithLanguageTabs() {
		t.Run(tc.Path, func(t *testing.T) {
			src := exampleSource(t, tc.HTML, "go")
			if !strings.HasPrefix(src, "package main") {
				t.Fatalf("example is not a standalone program, got prefix %.20q", src)
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"),
				[]byte("module docsexample\n\ngo 1.25\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			// -o os.DevNull: we care about compilation, not the artifact.
			cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
			cmd.Dir = dir
			// Inherit the module cache but keep the build off the network;
			// the examples import nothing outside the standard library.
			cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("go example does not compile: %v\n%s\n--- source ---\n%s", err, out, src)
			}
		})
	}
}

// exampleSource returns one language panel's example as plain text, with markup
// stripped and HTML entities decoded — i.e. what a customer gets by copying it.
func exampleSource(t *testing.T, page, lang string) string {
	t.Helper()
	panel := extractPanel(t, page, lang)
	code := panel[strings.Index(panel, ">")+1:]
	if i := strings.Index(code, "<code"); i != -1 {
		code = code[strings.Index(code[i:], ">")+i+1:]
	}
	return html.UnescapeString(tagPattern.ReplaceAllString(code, ""))
}

var tagPattern = regexp.MustCompile(`<[^>]*>`)

// extractPanel returns the markup of one language panel. The parameter is not
// named `html`: this file imports the stdlib html package and calls it just
// above, in stripTags.
func extractPanel(t *testing.T, markup, lang string) string {
	t.Helper()
	start := strings.Index(markup, `id="tab-`+lang+`"`)
	if start == -1 {
		t.Fatalf("no panel for %q", lang)
	}
	end := strings.Index(markup[start:], "</code></pre>")
	if end == -1 {
		t.Fatalf("unterminated panel for %q", lang)
	}
	return markup[start : start+end]
}

// TestDocs_SidebarMatchesDocumentOrder keeps each sidebar honest about the page
// it navigates.
//
// Two failure modes, both of which have happened. A link can point at an anchor
// that does not exist, which silently does nothing when clicked — easy to
// introduce by renaming a heading. And the sidebar can list sections in an order
// the page does not follow, so working down the nav jumps backwards through the
// document; the IP page listed Example before Validation while the page had them
// the other way round. Moving a section is exactly when both happen, and neither
// is visible from the rendered page unless you happen to click the wrong link.
func TestDocs_SidebarMatchesDocumentOrder(t *testing.T) {
	sidebarRe := regexp.MustCompile(`(?s)<nav class="sidebar">.*?</nav>`)
	anchorRe := regexp.MustCompile(`href="#([^"]+)"`)
	headingRe := regexp.MustCompile(`<h[234] id="([^"]+)"`)

	r := docsRouter()

	for _, path := range docsReferencePagePaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			body := w.Body.String()

			sidebar := sidebarRe.FindString(body)
			if sidebar == "" {
				t.Fatal("no sidebar found")
			}

			position := map[string]int{}
			for i, m := range headingRe.FindAllStringSubmatch(body, -1) {
				position[m[1]] = i
			}

			var prev string
			prevPos := -1
			for _, m := range anchorRe.FindAllStringSubmatch(sidebar, -1) {
				id := m[1]
				pos, ok := position[id]
				if !ok {
					t.Errorf("sidebar links to #%s, which no heading on the page defines", id)
					continue
				}
				if pos < prevPos {
					t.Errorf("sidebar lists %q before %q, but the page has them the other way round", prev, id)
				}
				prev, prevPos = id, pos
			}
		})
	}
}
