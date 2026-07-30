package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/docs/domain", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/docs/ip", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/docs/styles.css", nil)
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
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

func TestDocs_PagesSetCSPAndNoInlineScripts(t *testing.T) {
	r := docsRouter()

	for _, path := range []string{"/docs", "/docs/domain", "/docs/ip"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
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
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Public feature added") {
		t.Error("expected public changelog entry to appear in docs")
	}
	if strings.Contains(body, "Internal refactor") {
		t.Error("internal changelog entry must not appear in public docs")
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
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
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

func TestDocs_RendersVersion(t *testing.T) {
	status := &config.StatusSnapshot{
		System: config.SystemStatus{Version: "v99.0.0-test"},
	}

	r := docsRouterWithData(nil, nil, status)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
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
	cfg.Set("stripe.payment_link.basic", "https://buy.stripe.com/test_basic")
	cfg.Set("stripe.payment_link.pro", "https://buy.stripe.com/test_pro")
	cfg.Set("stripe.portal_link", "https://billing.stripe.com/test_portal")

	r := docsRouterWithData(nil, cfg, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://buy.stripe.com/test_basic") {
		t.Error("expected basic payment link in docs")
	}
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
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
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

func TestDocs_DetailPagesNoFooter(t *testing.T) {
	r := docsRouter()

	for _, path := range []string{"/docs/domain", "/docs/ip"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			if strings.Contains(body, "sidebar-footer") {
				t.Error("detail pages should not have a sidebar footer")
			}
			if strings.Contains(body, "docs-footer") {
				t.Error("detail pages should not have a standalone footer")
			}
		})
	}
}

// TestDocs_LanguageTabsHavePanels guards the docs example tabs: the switcher in
// docs.js resolves a tab's data-lang to a #tab-<lang> panel, so a tab without a
// panel silently does nothing when clicked, and a panel without a tab is
// unreachable. Neither shows up as a build or template failure.
func TestDocs_LanguageTabsHavePanels(t *testing.T) {
	for _, tc := range []struct {
		name string
		html string
	}{
		{"/docs/domain", docsDomainHTML},
		{"/docs/ip", docsIPHTML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tabs := map[string]bool{}
			for _, m := range regexp.MustCompile(`data-lang="([^"]+)"`).FindAllStringSubmatch(tc.html, -1) {
				tabs[m[1]] = true
			}
			panels := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="tab-([^"]+)"`).FindAllStringSubmatch(tc.html, -1) {
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
	for _, tc := range []struct {
		name string
		html string
	}{
		{"/docs/domain", docsDomainHTML},
		{"/docs/ip", docsIPHTML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every example sends a request, so all must name lookups.
			for _, lang := range []string{"curl", "javascript", "python", "go"} {
				if panel := extractPanel(t, tc.html, lang); !strings.Contains(panel, "lookups") {
					t.Errorf("%s example does not send a lookups array", lang)
				}
			}
			// Only the ones that parse a response can read the envelope; the
			// curl example stops at the request.
			for _, lang := range []string{"javascript", "python", "go"} {
				if panel := extractPanel(t, tc.html, lang); !strings.Contains(panel, "results") {
					t.Errorf("%s example does not read the results envelope", lang)
				}
			}
		})
	}
}

// extractPanel returns the markup of one language panel.
func extractPanel(t *testing.T, html, lang string) string {
	t.Helper()
	start := strings.Index(html, `id="tab-`+lang+`"`)
	if start == -1 {
		t.Fatalf("no panel for %q", lang)
	}
	end := strings.Index(html[start:], "</code></pre>")
	if end == -1 {
		t.Fatalf("unterminated panel for %q", lang)
	}
	return html[start : start+end]
}
