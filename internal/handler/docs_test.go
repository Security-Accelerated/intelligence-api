package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/spf13/viper"
)

func docsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
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
